# Security

## Threat model

### Defended

- **Leaked key table**: Only peppered HMAC-SHA256 digests are stored. The secret is 32 random bytes (256 bits), so a table dump does not reveal the token secret.
- **Timing attacks on comparison**: Digest comparison uses `hmac.compare_digest`. The CRC32 checksum uses a plain comparison and is not a security control; it rejects typos and scanner noise offline.
- **Leaked old key after rotation**: Rotation sets the old record's `expires_at` to `min(existing expires_at, now + grace_s)`. The old token verifies before that deadline and raises `expired` at or after it.
- **Revoked keys**: Once `revoked_at` is set, `verify` raises `revoked`; `revoke` on an already revoked key raises `already_revoked`, and `rotate` on a revoked key raises `already_revoked`. Revocation is terminal.
- **Status disclosure**: `verify` checks length, syntax, prefix, checksum, key lookup and `hmac.compare_digest` before checking `revoked_at` and `expires_at`. An unknown key, a wrong secret and a revoked key with a wrong secret all raise `invalid_key`; only a holder of the correct secret sees `revoked` or `expired`.

### Limits enforced by the code

- `prefix` must match `[a-z]{2,10}`; a mismatch raises `invalid_prefix` at construction.
- `pepper` must be `bytes` of at least 16 bytes; otherwise `invalid_pepper`.
- `owner` must be 1-128 printable characters; otherwise `invalid_owner`.
- Tokens longer than 256 characters raise `input_too_large`; the token regex then raises `malformed` for syntax that does not match `^([a-z]{2,10})_([0-9a-f]{12})_([0-9a-f]{64})_([0-9a-f]{8})$`.
- `grace_s` must be between 0 and 2_592_000 (30 days); otherwise `invalid_grace`.
- `InMemoryKeyStore(max_entries=100_000)` raises `store_full` for a new key when full and never evicts.

### Privileged administration

`rotate(key_id, *, grace_s)` and `revoke(key_id)` authorise an action from a bare `key_id`. Key ids are not secret material: they appear in `on_event` payloads that operators log and monitor. Expose these methods only from an authenticated admin path. Applications that need rotation or revocation gated on proof of possession should use `rotate_token(token, *, grace_s)` and `revoke_token(token)`, which call `verify(token)` first so a key id alone is not enough.

### Not defended

- **Pepper theft**: If the pepper is stolen, an attacker can brute-force digests offline, although the secret space is 256 bits.
- **Client-side key theft**: Keys stolen from clients are valid until revoked or expired.
- **Brute-force rate limiting**: The library does not rate-limit verification attempts.
- **Key transport**: The library does not encrypt or secure the transmission of keys.

## Best practices

- Store the pepper in a separate secret manager (for example an environment variable or vault).
- Provide a persistent `KeyStore` implementation for production; `InMemoryKeyStore` is not durable and has no eviction.
- Monitor `on_event` callbacks for failed verifications and rotations to detect abuse; payloads contain event names, key ids and error codes, not tokens, secrets or digests.
- Rotate keys periodically and revoke compromised keys immediately.
- Set a grace period appropriate for your clients; zero means immediate expiry of old keys.
