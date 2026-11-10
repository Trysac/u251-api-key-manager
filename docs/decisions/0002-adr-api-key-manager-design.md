# ADR: API key manager design

Status: accepted (generated, pending human review)

## Context

Services that hand out API keys often store them in plain text, compare them with == and have no way to rotate a leaked key without breaking every client at once. Getting the token format, the digest at rest, constant-time verification and a rotation grace period right is repeated work in every project.

## Decision

Implement a library that issues keys in a scanner-friendly prefixed format with a CRC32 checksum, stores only peppered HMAC-SHA256 digests, verifies with hmac.compare_digest, rotates with a grace period and revokes keys terminally. Use a pluggable KeyStore protocol with an in-memory implementation that refuses new keys when full and never evicts.

## Consequences

The library provides stable, typed error codes via ApiKeyError. It does not protect against pepper theft, client-side key theft, brute-force rate limiting or transport security. The design is simple, testable and portable, with no runtime dependencies beyond the Python standard library.
