# Architecture

## Purpose

`trysac-api-key-manager` is a dependency-free Python library: issue, verify, rotate and revoke API keys with prefixed tokens, a CRC32 checksum, peppered HMAC-SHA256 digests at rest, grace-period rotation and a pluggable key store.

## Shape

```text
caller code --> api_key_manager (public API in src/api_key_manager/__init__.py)
                    |
                    +-- KeyManager
                    +-- KeyStore protocol / InMemoryKeyStore
                    +-- KeyRecord / ApiKeyError
```

- **Public API**: the names listed in `__all__` of `src/api_key_manager/__init__.py`: `ApiKeyError`, `InMemoryKeyStore`, `KeyManager`, `KeyRecord`, `KeyStore` and `__version__`. Anything else is internal.
- **Token format**: `<prefix>_<key_id>_<secret>_<checksum>`, where `prefix` matches `[a-z]{2,10}`, `key_id` is `rng(6).hex()`, `secret` is `rng(32).hex()` and `checksum` is `format(zlib.crc32('<prefix>_<key_id>_<secret>'), '08x')`.
- **Verification order**: length `<= 256`, token regex, prefix, checksum, store lookup, `hmac.compare_digest` on the digest, revoked check, expired check.
- **Errors**: `ApiKeyError` carries a `code` literal; invalid constructor and method inputs raise `ApiKeyError` or `ValueError` (`InMemoryKeyStore` max entries).
- **Side effects**: optional `on_event` callback receives event dictionaries; the module uses `logging.getLogger(__name__)` with a `NullHandler` and logs nothing secret.

## Quality contract

The package ships `src/api_key_manager/py.typed` and uses type annotations. Tests live in `tests/test_api_key_manager.py`. No `scripts/check.py` or factory gate file is present in the provided source tree.

## Decisions

No ADR files are included in the provided source tree.
