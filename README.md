# trysac-api-key-manager

Issue, verify, rotate and revoke API keys with a scanner-friendly format, peppered HMAC-SHA256 digests at rest and grace-period rotation.

## Installation

```bash
pip install trysac-api-key-manager
```

## Usage

```python
from api_key_manager import KeyManager, InMemoryKeyStore

store = InMemoryKeyStore()
manager = KeyManager(store, prefix="ak", pepper=b"0123456789abcdef")
token, record = manager.issue("team-a")
verified = manager.verify(token)
```

Tokens look like `ak_000102030405_000102..._bdaae882`. Only the peppered digest is stored.

## Features

- Prefixed tokens with a CRC32 checksum for secret scanners and offline typo rejection
- Peppered HMAC-SHA256 digests; a leaked key table does not reveal keys
- Constant-time digest comparison with `hmac.compare_digest`
- Rotation with a grace period so old keys stop working at a deadline
- Revocation is terminal; revoked keys never verify
- Pluggable key store; in-memory store with configurable max entries (no eviction)
- Typed error codes via `ApiKeyError`

## Public API

`api_key_manager` exports `ApiKeyError`, `InMemoryKeyStore`, `KeyManager`, `KeyRecord`, `KeyStore` and `__version__`.

- `KeyRecord` is a frozen dataclass with `key_id`, `owner`, `digest`, `created_at`, `expires_at`, `revoked_at`, `rotated_from` and `rotated_to`; its `repr` shows the digest as `<redacted>`.
- `KeyStore` is a protocol with `get(key_id) -> KeyRecord | None` and `put(record) -> None`; `put` replaces by `key_id`.
- `InMemoryKeyStore(max_entries=100_000)` refuses a new key with `ApiKeyError('store_full')` when full and never evicts.
- `KeyManager(store, *, prefix, pepper, clock=time.time, rng=secrets.token_bytes, on_event=None)` provides `issue(owner)`, `verify(token)`, `rotate(key_id, *, grace_s)`, `rotate_token(token, *, grace_s)`, `revoke(key_id)` and `revoke_token(token)`.
- `rotate` and `revoke` take a bare `key_id` and are privileged administration entry points; use `rotate_token` and `revoke_token` when proof of possession is required.

`ApiKeyError.code` is one of `malformed`, `wrong_prefix`, `bad_checksum`, `invalid_key`, `expired`, `revoked`, `already_revoked`, `already_rotated`, `invalid_grace`, `input_too_large`, `store_full`, `id_collision`, `invalid_pepper`, `invalid_owner`, `invalid_prefix`.

Limits and options enforced by the code: `prefix` must match `[a-z]{2,10}`; `pepper` must be at least 16 bytes; `owner` must be 1-128 printable characters; tokens longer than 256 characters raise `input_too_large`; `grace_s` must be between 0 and 2_592_000; `key_id` collisions are redrawn up to 3 times. `verify` raises `invalid_key` for an unknown key, a wrong secret or a revoked key when the presented secret is wrong, so key status is not disclosed without the secret.

## Why not ad hoc uuid4 keys

Ad hoc `uuid4` keys have no prefix or checksum for scanners and typo rejection, no digest-at-rest format, no rotation grace period and no stable error codes. This library defines the token format, stores only peppered HMAC-SHA256 digests, verifies with `hmac.compare_digest`, rotates with a deadline and reports typed `ApiKeyError.code` values.

## Documentation

See `docs/SECURITY.md` for the threat model.
