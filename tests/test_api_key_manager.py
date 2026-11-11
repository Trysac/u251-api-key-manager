from __future__ import annotations

import hmac
import zlib
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

import pytest

from api_key_manager import (
    ApiKeyError,
    InMemoryKeyStore,
    KeyManager,
    KeyRecord,
    KeyStore,
)

PEPPER = b"0123456789abcdef"
PREFIX = "ak"


def _fixed_rng(n: int) -> bytes:
    return bytes(range(n))


def _constant_rng(n: int) -> bytes:
    return b"\x00" * n


def _make_default_rng() -> Callable[[int], bytes]:
    """Deterministic rng: fixed for the first key, distinct for later keys.

    ``issue`` must draw the same key material as the acceptance example, while
    a following ``rotate`` must draw a *different* key_id or it would collide
    with the key being rotated.
    """
    calls = 0

    def rng(n: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls <= 2:
            return _fixed_rng(n)
        return bytes([calls]) * n

    return rng


def make_manager(
    store: KeyStore | None = None,
    *,
    prefix: str = PREFIX,
    pepper: bytes = PEPPER,
    clock: Callable[[], float] | None = None,
    rng: Callable[[int], bytes] | None = None,
    on_event=None,
) -> KeyManager:
    if store is None:
        store = InMemoryKeyStore()
    return KeyManager(
        store,
        prefix=prefix,
        pepper=pepper,
        clock=clock or (lambda: 1000.0),
        rng=rng if rng is not None else _make_default_rng(),
        on_event=on_event,
    )


def recompute_checksum(token: str, manager: KeyManager) -> str:
    prefix, key_id, secret, _ = token.split("_", 3)
    return f"{prefix}_{key_id}_{secret}_{format(zlib.crc32(f'{prefix}_{key_id}_{secret}'.encode()), '08x')}"


# ---------------------------------------------------------------------------
# KeyRecord
# ---------------------------------------------------------------------------


def test_key_record_repr_redacts_digest() -> None:
    rec = KeyRecord(
        key_id="abc",
        owner="team-a",
        digest="deadbeef",
        created_at=1.0,
    )
    assert "<redacted>" in repr(rec)
    assert "deadbeef" not in repr(rec)


def test_key_record_frozen() -> None:
    rec = KeyRecord("abc", "owner", "digest", 1.0)
    with pytest.raises(FrozenInstanceError):
        rec.owner = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# InMemoryKeyStore
# ---------------------------------------------------------------------------


def test_in_memory_store_put_get_replace() -> None:
    store = InMemoryKeyStore(max_entries=2)
    r1 = KeyRecord("k1", "o", "d1", 1.0)
    r2 = KeyRecord("k2", "o", "d2", 2.0)
    r1_updated = replace(r1, digest="d3")
    store.put(r1)
    store.put(r2)
    assert store.get("k1") == r1
    store.put(r1_updated)
    assert store.get("k1") == r1_updated
    assert len(store._records) == 2


def test_in_memory_store_full() -> None:
    store = InMemoryKeyStore(max_entries=2)
    store.put(KeyRecord("a", "o", "d", 1.0))
    store.put(KeyRecord("b", "o", "d", 2.0))
    with pytest.raises(ApiKeyError) as exc:
        store.put(KeyRecord("c", "o", "d", 3.0))
    assert exc.value.code == "store_full"


def test_in_memory_store_invalid_max_entries() -> None:
    with pytest.raises(ValueError):
        InMemoryKeyStore(max_entries=0)


# ---------------------------------------------------------------------------
# KeyManager construction
# ---------------------------------------------------------------------------


def test_constructor_invalid_prefix() -> None:
    with pytest.raises(ApiKeyError) as exc:
        KeyManager(InMemoryKeyStore(), prefix="ABC", pepper=PEPPER)
    assert exc.value.code == "invalid_prefix"

    with pytest.raises(ApiKeyError) as exc:
        KeyManager(InMemoryKeyStore(), prefix="a", pepper=PEPPER)
    assert exc.value.code == "invalid_prefix"


def test_constructor_invalid_pepper() -> None:
    with pytest.raises(ApiKeyError) as exc:
        KeyManager(InMemoryKeyStore(), prefix=PREFIX, pepper=b"short")
    assert exc.value.code == "invalid_pepper"

    with pytest.raises(ApiKeyError) as exc:
        KeyManager(InMemoryKeyStore(), prefix=PREFIX, pepper="0123456789abcdef")  # type: ignore[arg-type]
    assert exc.value.code == "invalid_pepper"


# ---------------------------------------------------------------------------
# issue
# ---------------------------------------------------------------------------


def test_issue_returns_expected_token_and_record() -> None:
    manager = make_manager()
    token, record = manager.issue("team-a")
    assert token == (
        "ak_000102030405_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f_bdaae882"
    )
    assert record.key_id == "000102030405"
    assert record.owner == "team-a"
    assert record.created_at == 1000.0
    assert record.digest == "016578e2afc817495a46bd2fa048a51e858a38ed597a476a42e1cc7f271e86cf"


def test_issue_token_not_stored() -> None:
    class SpyStore:
        def __init__(self) -> None:
            self.put_calls: list[KeyRecord] = []

        def get(self, key_id: str) -> KeyRecord | None:
            return None

        def put(self, record: KeyRecord) -> None:
            self.put_calls.append(record)

    store = SpyStore()
    manager = make_manager(store)
    token, _ = manager.issue("team-a")
    assert len(store.put_calls) == 1
    stored = store.put_calls[0]
    assert token not in repr(stored)
    assert token.split("_")[2] not in repr(stored)  # secret not present
    assert stored.digest != token.split("_")[2]


def test_issue_invalid_owner() -> None:
    manager = make_manager()
    for owner in ["", " " * 129, "bad\x00owner"]:
        with pytest.raises(ApiKeyError) as exc:
            manager.issue(owner)
        assert exc.value.code == "invalid_owner"


def test_issue_id_collision() -> None:
    store = InMemoryKeyStore()
    manager = make_manager(store, rng=_constant_rng)
    first_token, _ = manager.issue("a")
    assert first_token.startswith("ak_")
    with pytest.raises(ApiKeyError) as exc:
        manager.issue("b")
    assert exc.value.code == "id_collision"


def test_issue_store_full_propagates() -> None:
    store = InMemoryKeyStore(max_entries=1)
    manager = make_manager(store)
    manager.issue("a")
    with pytest.raises(ApiKeyError) as exc:
        manager.issue("b")
    assert exc.value.code == "store_full"


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_success_returns_record() -> None:
    store = InMemoryKeyStore()
    manager = make_manager(store)
    token, issued_record = manager.issue("team-a")
    verified = manager.verify(token)
    assert verified == issued_record


def test_verify_bad_checksum() -> None:
    manager = make_manager()
    token, _ = manager.issue("team-a")
    # Change last secret character from f to e (secret ends with '1f',
    # the underscore and trailing 8 characters are the checksum)
    bad = token[:-10] + "e" + token[-9:]
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(bad)
    assert exc.value.code == "bad_checksum"


def test_verify_wrong_secret_with_valid_checksum() -> None:
    manager = make_manager()
    token, _ = manager.issue("team-a")
    prefix, key_id, _secret, _checksum = token.split("_")
    wrong_secret = "0" * 64
    wrong_checksum = format(zlib.crc32(f"{prefix}_{key_id}_{wrong_secret}".encode()), "08x")
    forged = f"{prefix}_{key_id}_{wrong_secret}_{wrong_checksum}"
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(forged)
    assert exc.value.code == "invalid_key"


def test_verify_unknown_key() -> None:
    manager = make_manager()
    token, _ = manager.issue("team-a")
    prefix, _key_id, secret, _checksum = token.split("_")
    unknown_key_id = "ffffffffffff"
    new_checksum = format(zlib.crc32(f"{prefix}_{unknown_key_id}_{secret}".encode()), "08x")
    forged = f"{prefix}_{unknown_key_id}_{secret}_{new_checksum}"
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(forged)
    assert exc.value.code == "invalid_key"


def test_verify_malformed() -> None:
    manager = make_manager()
    with pytest.raises(ApiKeyError) as exc:
        manager.verify("zz_1")
    assert exc.value.code == "malformed"


def test_verify_wrong_prefix() -> None:
    manager = make_manager()
    token, _ = manager.issue("team-a")
    _prefix, key_id, secret, _checksum = token.split("_")
    wrong_prefix = "bk"
    new_checksum = format(zlib.crc32(f"{wrong_prefix}_{key_id}_{secret}".encode()), "08x")
    forged = f"{wrong_prefix}_{key_id}_{secret}_{new_checksum}"
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(forged)
    assert exc.value.code == "wrong_prefix"


def test_verify_uppercase_hex_malformed() -> None:
    manager = make_manager()
    token, _ = manager.issue("team-a")
    upper = token.upper()
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(upper)
    assert exc.value.code == "malformed"


def test_verify_input_too_large() -> None:
    manager = make_manager()
    too_long = "a" * 257
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(too_long)
    assert exc.value.code == "input_too_large"


def test_verify_exactly_256_malformed() -> None:
    manager = make_manager()
    token = "a" * 256
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(token)
    assert exc.value.code == "malformed"


def test_verify_store_returns_wrong_key_id() -> None:
    class WeirdStore(InMemoryKeyStore):
        def get(self, key_id: str) -> KeyRecord | None:
            rec = super().get(key_id)
            if rec is not None:
                return replace(rec, key_id="different")
            return None

    store = WeirdStore()
    manager = make_manager(store)
    token, _ = manager.issue("team-a")
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(token)
    assert exc.value.code == "invalid_key"


def test_verify_compare_digest_called_once() -> None:
    manager = make_manager()
    token, record = manager.issue("team-a")
    assert record.key_id == "000102030405"
    real_compare_digest = hmac.compare_digest
    with patch("api_key_manager.hmac.compare_digest", wraps=real_compare_digest) as mock:
        manager.verify(token)
    mock.assert_called_once()
    expected_digest = hmac.new(PEPPER, token.split("_")[2].encode("ascii"), "sha256").hexdigest()
    assert mock.call_args.args == (expected_digest, record.digest)


# ---------------------------------------------------------------------------
# rotate
# ---------------------------------------------------------------------------


def test_rotate_success_and_grace_period() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    old_token, old_record = manager.issue("team-a")
    clock_value = 1000.0
    new_token, new_record = manager.rotate("000102030405", grace_s=3600)
    assert new_record.rotated_from == "000102030405"
    assert old_record.key_id not in new_token
    # old token verifies before deadline
    clock_value = 4599.0
    assert manager.verify(old_token) == replace(
        old_record, expires_at=4600.0, rotated_to=new_record.key_id
    )
    # old token expires at deadline
    clock_value = 4600.0
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(old_token)
    assert exc.value.code == "expired"
    # new token verifies
    clock_value = 4600.0
    assert manager.verify(new_token) == new_record


def test_rotate_grace_zero() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    old_token, _old_record = manager.issue("team-a")
    _new_token, new_record = manager.rotate("000102030405", grace_s=0)
    assert new_record.rotated_from == "000102030405"
    clock_value = 1000.0
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(old_token)
    assert exc.value.code == "expired"


def test_rotate_already_rotated() -> None:
    manager = make_manager()
    _token, _ = manager.issue("team-a")
    manager.rotate("000102030405", grace_s=3600)
    with pytest.raises(ApiKeyError) as exc:
        manager.rotate("000102030405", grace_s=3600)
    assert exc.value.code == "already_rotated"


def test_rotate_invalid_grace() -> None:
    manager = make_manager()
    manager.issue("team-a")
    for bad in [-1, 2_592_001]:
        with pytest.raises(ApiKeyError) as exc:
            manager.rotate("000102030405", grace_s=bad)
        assert exc.value.code == "invalid_grace"


def test_rotate_revoked_key() -> None:
    manager = make_manager()
    _token, _ = manager.issue("team-a")
    manager.revoke("000102030405")
    with pytest.raises(ApiKeyError) as exc:
        manager.rotate("000102030405", grace_s=3600)
    assert exc.value.code == "already_revoked"


def test_rotate_token_requires_possession() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    token, _record = manager.issue("team-a")
    prefix, key_id, _secret, _checksum = token.split("_")
    wrong_secret = "0" * 64
    wrong_checksum = format(zlib.crc32(f"{prefix}_{key_id}_{wrong_secret}".encode()), "08x")
    forged = f"{prefix}_{key_id}_{wrong_secret}_{wrong_checksum}"
    with pytest.raises(ApiKeyError) as exc:
        manager.rotate_token(forged, grace_s=3600)
    assert exc.value.code == "invalid_key"
    # The legitimate key is untouched and the old token still verifies.
    assert manager.verify(token).key_id == key_id
    stored = manager._store.get(key_id)
    assert stored is not None
    assert stored.rotated_to is None


def test_rotate_token_success() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    token, _record = manager.issue("team-a")
    new_token, new_record = manager.rotate_token(token, grace_s=3600)
    assert new_record.rotated_from == "000102030405"
    clock_value = 4599.0
    assert manager.verify(token).key_id == "000102030405"
    clock_value = 4600.0
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(token)
    assert exc.value.code == "expired"
    assert manager.verify(new_token) == new_record


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


def test_revoke_success() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    token, _record = manager.issue("team-a")
    clock_value = 2000.0
    revoked = manager.revoke("000102030405")
    assert revoked.revoked_at == 2000.0
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(token)
    assert exc.value.code == "revoked"


def test_revoke_twice_unchanged() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    manager.issue("team-a")
    clock_value = 2000.0
    manager.revoke("000102030405")
    clock_value = 3000.0
    with pytest.raises(ApiKeyError) as exc:
        manager.revoke("000102030405")
    assert exc.value.code == "already_revoked"
    record = manager._store.get("000102030405")
    assert record is not None
    assert record.revoked_at == 2000.0  # unchanged from first revoke


def test_revoke_unknown_key() -> None:
    manager = make_manager()
    with pytest.raises(ApiKeyError) as exc:
        manager.revoke("ffffffffffff")
    assert exc.value.code == "invalid_key"


def test_revoke_token_requires_possession() -> None:
    manager = make_manager()
    token, _record = manager.issue("team-a")
    prefix, key_id, _secret, _checksum = token.split("_")
    wrong_secret = "0" * 64
    wrong_checksum = format(zlib.crc32(f"{prefix}_{key_id}_{wrong_secret}".encode()), "08x")
    forged = f"{prefix}_{key_id}_{wrong_secret}_{wrong_checksum}"
    with pytest.raises(ApiKeyError) as exc:
        manager.revoke_token(forged)
    assert exc.value.code == "invalid_key"
    # The legitimate key is untouched.
    assert manager.verify(token).revoked_at is None


def test_revoke_token_success() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    token, _record = manager.issue("team-a")
    clock_value = 2000.0
    revoked = manager.revoke_token(token)
    assert revoked.revoked_at == 2000.0
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(token)
    assert exc.value.code == "revoked"


def test_revoked_key_wrong_secret_still_invalid_key() -> None:
    manager = make_manager()
    token, _ = manager.issue("team-a")
    manager.revoke("000102030405")
    # craft token with wrong secret but valid checksum
    prefix, key_id, _secret, _checksum = token.split("_")
    wrong_secret = "1" * 64
    wrong_checksum = format(zlib.crc32(f"{prefix}_{key_id}_{wrong_secret}".encode()), "08x")
    forged = f"{prefix}_{key_id}_{wrong_secret}_{wrong_checksum}"
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(forged)
    assert exc.value.code == "invalid_key"


def test_revoked_wins_over_expired() -> None:
    clock_value = 1000.0
    manager = make_manager(clock=lambda: clock_value)
    token, record = manager.issue("team-a")
    # Set expired by calling rotate with grace 0? Actually rotate would mark rotated_to.
    # Manually update store record to have expires_at < now and revoked_at set.
    updated = replace(record, expires_at=1000.0, revoked_at=1000.0)
    manager._store.put(updated)
    clock_value = 2000.0
    with pytest.raises(ApiKeyError) as exc:
        manager.verify(token)
    assert exc.value.code == "revoked"


# ---------------------------------------------------------------------------
# on_event
# ---------------------------------------------------------------------------


def test_on_event_payloads_do_not_contain_token_secret_digest() -> None:
    events: list[dict[str, object]] = []
    store = InMemoryKeyStore()
    manager = make_manager(store, on_event=events.append)
    token, _ = manager.issue("team-a")
    manager.verify(token)
    with pytest.raises(ApiKeyError):
        manager.verify(token[:-10] + "e" + token[-9:])
    # wrong secret with a valid checksum -> invalid_key event
    prefix, key_id, _secret, _checksum = token.split("_")
    wrong_secret = "0" * 64
    wrong_checksum = format(zlib.crc32(f"{prefix}_{key_id}_{wrong_secret}".encode()), "08x")
    forged = f"{prefix}_{key_id}_{wrong_secret}_{wrong_checksum}"
    with pytest.raises(ApiKeyError):
        manager.verify(forged)
    # rotate
    new_token, _ = manager.rotate("000102030405", grace_s=3600)
    with pytest.raises(ApiKeyError):
        manager.rotate("000102030405", grace_s=3600)
    # revoke
    manager.revoke(new_token.split("_")[1])

    forbidden = [token, new_token, token.split("_")[2], new_token.split("_")[2]]
    for event in events:
        serialized = str(event)
        for secret in forbidden:
            assert secret not in serialized
        assert "digest" not in event

    # Check a failure payload has expected structure
    verify_failed = [e for e in events if e.get("event") == "verify_failed"]
    assert verify_failed
    # find one with code invalid_key (from bad secret verification)
    invalid_key_event = next((e for e in verify_failed if e.get("code") == "invalid_key"), None)
    assert invalid_key_event is not None
    assert invalid_key_event["key_id"] == "000102030405"


def test_on_event_receives_expected_verify_failed_payload() -> None:
    events: list[dict[str, object]] = []
    manager = make_manager(on_event=events.append)
    token, _ = manager.issue("team-a")
    prefix, key_id, _secret, _checksum = token.split("_")
    wrong_secret = "0" * 64
    wrong_checksum = format(zlib.crc32(f"{prefix}_{key_id}_{wrong_secret}".encode()), "08x")
    forged = f"{prefix}_{key_id}_{wrong_secret}_{wrong_checksum}"
    with pytest.raises(ApiKeyError):
        manager.verify(forged)
    matching = [
        e for e in events if e.get("event") == "verify_failed" and e.get("code") == "invalid_key"
    ]
    assert matching
    assert matching[0]["key_id"] == "000102030405"
    assert "token" not in str(matching[0])
    assert "secret" not in str(matching[0])
    assert "digest" not in str(matching[0])
