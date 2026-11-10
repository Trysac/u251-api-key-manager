"""API key manager.

Issue, verify, rotate and revoke API keys in a scanner-friendly format with
a checksum, peppered HMAC-SHA256 digests at rest, grace-period rotation and a
pluggable key store.

Threat model (defended):
- A leaked key table does not reveal keys (only peppered digests).
- Timing attacks on comparison are mitigated with hmac.compare_digest.
- A leaked old key after rotation stops working at the grace deadline.
- Revoked keys never verify.
- ``verify`` does not reveal key status without the secret: an unknown key, a
  wrong secret and a revoked key all raise ``invalid_key``.

``rotate()`` and ``revoke()`` take a bare ``key_id`` and are privileged
administration entry points: key ids are not secret material (they appear in
``on_event`` payloads), so they must only be reachable from an authenticated
admin path. Applications that want rotation and revocation gated on proof of
possession should use ``rotate_token()`` and ``revoke_token()``, which verify
the caller's token before acting.

Not defended: theft of the pepper or of keys from clients, brute-force rate
limiting, key transport.
"""

from __future__ import annotations

import hmac
import logging
import re
import secrets
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

__all__ = [
    "ApiKeyError",
    "InMemoryKeyStore",
    "KeyManager",
    "KeyRecord",
    "KeyStore",
    "__version__",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())

ErrorCode = Literal[
    "malformed",
    "wrong_prefix",
    "bad_checksum",
    "invalid_key",
    "expired",
    "revoked",
    "already_revoked",
    "already_rotated",
    "invalid_grace",
    "input_too_large",
    "store_full",
    "id_collision",
    "invalid_pepper",
    "invalid_owner",
    "invalid_prefix",
]


class ApiKeyError(Exception):
    """Base error for the api_key_manager package with a machine-readable code."""

    def __init__(self, code: ErrorCode, message: str | None = None) -> None:
        self.code: ErrorCode = code
        super().__init__(message or code)


@dataclass(frozen=True, slots=True)
class KeyRecord:
    """Immutable record stored for an API key. The digest is redacted in repr."""

    key_id: str
    owner: str
    digest: str
    created_at: float
    expires_at: float | None = None
    revoked_at: float | None = None
    rotated_from: str | None = None
    rotated_to: str | None = None

    def __repr__(self) -> str:
        return (
            f"KeyRecord(key_id={self.key_id!r}, owner={self.owner!r}, "
            f"digest='<redacted>', created_at={self.created_at!r}, "
            f"expires_at={self.expires_at!r}, revoked_at={self.revoked_at!r}, "
            f"rotated_from={self.rotated_from!r}, rotated_to={self.rotated_to!r})"
        )


class KeyStore(Protocol):
    """Protocol for pluggable key stores."""

    def get(self, key_id: str) -> KeyRecord | None: ...

    def put(self, record: KeyRecord) -> None: ...


class InMemoryKeyStore:
    """Simple in-memory key store with a max entry count and no eviction."""

    def __init__(self, max_entries: int = 100_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._records: dict[str, KeyRecord] = {}

    def get(self, key_id: str) -> KeyRecord | None:
        return self._records.get(key_id)

    def put(self, record: KeyRecord) -> None:
        if record.key_id in self._records:
            self._records[record.key_id] = record
            return
        if len(self._records) >= self._max_entries:
            raise ApiKeyError("store_full", "key store is full")
        self._records[record.key_id] = record


class KeyManager:
    """Issues, verifies, rotates and revokes API keys."""

    def __init__(
        self,
        store: KeyStore,
        *,
        prefix: str,
        pepper: bytes,
        clock: Callable[[], float] = time.time,
        rng: Callable[[int], bytes] = secrets.token_bytes,
        on_event: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-z]{2,10}", prefix):
            raise ApiKeyError("invalid_prefix", "prefix must match [a-z]{2,10}")
        if not isinstance(pepper, bytes) or len(pepper) < 16:
            raise ApiKeyError("invalid_pepper", "pepper must be at least 16 bytes")
        self._store = store
        self._prefix = prefix
        self._pepper = pepper
        self._clock = clock
        self._rng = rng
        self._on_event = on_event
        self._token_re = re.compile(r"^([a-z]{2,10})_([0-9a-f]{12})_([0-9a-f]{64})_([0-9a-f]{8})$")

    def _emit(self, event: str, payload: dict[str, object] | None = None) -> None:
        if self._on_event is not None:
            data: dict[str, object] = {"event": event}
            if payload:
                data.update(payload)
            self._on_event(data)

    def _checksum(self, key_id: str, secret: str) -> str:
        source = f"{self._prefix}_{key_id}_{secret}".encode()
        return format(zlib.crc32(source), "08x")

    def _issue(self, owner: str, rotated_from: str | None = None) -> tuple[str, KeyRecord]:
        # Generate a key_id, redrawing up to 3 times on collision.
        for _attempt in range(3):
            key_id = self._rng(6).hex()
            if self._store.get(key_id) is None:
                break
        else:
            self._emit("issue_failed", {"code": "id_collision"})
            raise ApiKeyError("id_collision", "key id collision after 3 attempts")

        secret_bytes = self._rng(32)
        secret = secret_bytes.hex()
        token = f"{self._prefix}_{key_id}_{secret}_{self._checksum(key_id, secret)}"
        digest = hmac.new(self._pepper, secret.encode("ascii"), "sha256").hexdigest()
        now = self._clock()
        record = KeyRecord(
            key_id=key_id,
            owner=owner,
            digest=digest,
            created_at=now,
            rotated_from=rotated_from,
        )
        try:
            self._store.put(record)
        except ApiKeyError as exc:
            if exc.code == "store_full":
                self._emit("issue_failed", {"code": "store_full", "key_id": key_id})
            raise
        self._emit("issue", {"key_id": key_id})
        return token, record

    def issue(self, owner: str) -> tuple[str, KeyRecord]:
        """Issue a new API key for *owner*. Returns ``(token, record)``."""
        if not isinstance(owner, str) or not 1 <= len(owner) <= 128 or not owner.isprintable():
            self._emit("issue_failed", {"code": "invalid_owner"})
            raise ApiKeyError("invalid_owner", "owner must be 1-128 printable characters")
        return self._issue(owner)

    def verify(self, token: str) -> KeyRecord:
        """Verify *token* and return the matching :class:`KeyRecord`."""
        if not isinstance(token, str):
            self._emit("verify_failed", {"code": "malformed"})
            raise ApiKeyError("malformed", "token must be a string")
        if len(token) > 256:
            self._emit("verify_failed", {"code": "input_too_large"})
            raise ApiKeyError("input_too_large", "token exceeds 256 characters")
        match = self._token_re.fullmatch(token)
        if match is None:
            self._emit("verify_failed", {"code": "malformed"})
            raise ApiKeyError("malformed", "token does not match expected format")
        prefix, key_id, secret, checksum = match.groups()
        if prefix != self._prefix:
            self._emit("verify_failed", {"code": "wrong_prefix", "key_id": key_id})
            raise ApiKeyError("wrong_prefix", "token prefix does not match")
        expected_checksum = self._checksum(key_id, secret)
        # The checksum is not a secret control (it guards typos and scanners),
        # so a plain comparison is enough; hmac.compare_digest is reserved for
        # the secret digest.
        if checksum != expected_checksum:
            self._emit("verify_failed", {"code": "bad_checksum", "key_id": key_id})
            raise ApiKeyError("bad_checksum", "token checksum mismatch")
        record = self._store.get(key_id)
        if record is None or record.key_id != key_id:
            self._emit("verify_failed", {"code": "invalid_key", "key_id": key_id})
            raise ApiKeyError("invalid_key", "unknown key")
        expected_digest = hmac.new(self._pepper, secret.encode("ascii"), "sha256").hexdigest()
        if not hmac.compare_digest(expected_digest, record.digest):
            self._emit("verify_failed", {"code": "invalid_key", "key_id": key_id})
            raise ApiKeyError("invalid_key", "key secret mismatch")
        if record.revoked_at is not None:
            self._emit("verify_failed", {"code": "revoked", "key_id": key_id})
            raise ApiKeyError("revoked", "key has been revoked")
        now = self._clock()
        if record.expires_at is not None and now >= record.expires_at:
            self._emit("verify_failed", {"code": "expired", "key_id": key_id})
            raise ApiKeyError("expired", "key has expired")
        self._emit("verify_success", {"key_id": key_id})
        return record

    def rotate(self, key_id: str, *, grace_s: float) -> tuple[str, KeyRecord]:
        """Rotate the key *key_id*, granting a grace period of *grace_s* seconds.

        Privileged administration entry point: *key_id* alone authorises the
        rotation. Only expose it behind an authenticated admin path; use
        :meth:`rotate_token` to require proof of possession instead.
        """
        if (
            not isinstance(grace_s, (int, float))
            or isinstance(grace_s, bool)
            or not 0 <= grace_s <= 2_592_000
        ):
            self._emit("rotate_failed", {"code": "invalid_grace", "key_id": key_id})
            raise ApiKeyError("invalid_grace", "grace_s must be between 0 and 2592000")
        record = self._store.get(key_id)
        if record is None or record.key_id != key_id:
            self._emit("rotate_failed", {"code": "invalid_key", "key_id": key_id})
            raise ApiKeyError("invalid_key", "unknown key")
        if record.revoked_at is not None:
            self._emit("rotate_failed", {"code": "already_revoked", "key_id": key_id})
            raise ApiKeyError("already_revoked", "key is revoked")
        if record.rotated_to is not None:
            self._emit("rotate_failed", {"code": "already_rotated", "key_id": key_id})
            raise ApiKeyError("already_rotated", "key has already been rotated")
        new_token, new_record = self._issue(record.owner, rotated_from=key_id)
        now = self._clock()
        expires_at = now + grace_s
        if record.expires_at is not None:
            expires_at = min(record.expires_at, expires_at)
        updated_old = KeyRecord(
            key_id=record.key_id,
            owner=record.owner,
            digest=record.digest,
            created_at=record.created_at,
            expires_at=expires_at,
            revoked_at=record.revoked_at,
            rotated_from=record.rotated_from,
            rotated_to=new_record.key_id,
        )
        self._store.put(updated_old)
        self._emit("rotate", {"old_key_id": key_id, "new_key_id": new_record.key_id})
        return new_token, new_record

    def rotate_token(self, token: str, *, grace_s: float) -> tuple[str, KeyRecord]:
        """Rotate the key identified by *token* after verifying possession.

        Unlike :meth:`rotate`, the caller must present the current token, so a
        bare ``key_id`` is not enough to mint a replacement key.
        """
        record = self.verify(token)
        return self.rotate(record.key_id, grace_s=grace_s)

    def revoke(self, key_id: str) -> KeyRecord:
        """Revoke the key *key_id*. Returns the updated record.

        Privileged administration entry point: *key_id* alone authorises the
        revocation. Only expose it behind an authenticated admin path; use
        :meth:`revoke_token` to require proof of possession instead.
        """
        record = self._store.get(key_id)
        if record is None or record.key_id != key_id:
            self._emit("revoke_failed", {"code": "invalid_key", "key_id": key_id})
            raise ApiKeyError("invalid_key", "unknown key")
        if record.revoked_at is not None:
            self._emit("revoke_failed", {"code": "already_revoked", "key_id": key_id})
            raise ApiKeyError("already_revoked", "key is already revoked")
        now = self._clock()
        updated = KeyRecord(
            key_id=record.key_id,
            owner=record.owner,
            digest=record.digest,
            created_at=record.created_at,
            expires_at=record.expires_at,
            revoked_at=now,
            rotated_from=record.rotated_from,
            rotated_to=record.rotated_to,
        )
        self._store.put(updated)
        self._emit("revoke", {"key_id": key_id})
        return updated

    def revoke_token(self, token: str) -> KeyRecord:
        """Revoke the key identified by *token* after verifying possession.

        Unlike :meth:`revoke`, the caller must present the current token, so a
        bare ``key_id`` is not enough to kill the legitimate key.
        """
        record = self.verify(token)
        return self.revoke(record.key_id)
