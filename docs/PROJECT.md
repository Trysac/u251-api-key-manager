# Project record

## Objective

Issue, verify, rotate and revoke API keys: prefixed tokens with a CRC32 checksum, peppered HMAC-SHA256 digests at rest, grace-period rotation and a pluggable key store.

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested.
- In scope: `KeyRecord`, the `KeyStore` protocol, `InMemoryKeyStore`, `KeyManager` (`issue`, `verify`, `rotate`, `rotate_token`, `revoke`, `revoke_token`), `ApiKeyError` codes and `on_event` callbacks.
- In scope: token format `<prefix>_<key_id>_<secret>_<checksum>` with a CRC32 checksum and peppered HMAC-SHA256 digests.
- Out of scope: persistence backends other than the in-memory store, scopes and permissions, HTTP middleware and a CLI.
- Out of scope: runtime dependencies; the package uses the Python standard library.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 1729460 / 104182 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.1272 |

## Factory run u251 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-10 | generation | deepseek-v4-pro | yes | 2042 | 20257 | 0 | 3200 | 0.0415 |
| 2026-11-10 | fix-1 | deepseek-flash | no | 23291 | 20508 | 0 | 427776 | 0.0171 |
| 2026-11-10 | audit | deepseek-flash | no | 28121 | 30375 | 0 | 680448 | 0.0245 |
| 2026-11-10 | fix-2 | deepseek-flash | no | 10965 | 3092 | 0 | 113024 | 0.0038 |
| 2026-11-10 | threat-model | deepseek-flash | no | 22742 | 13655 | 0 | 115584 | 0.0119 |
| 2026-11-10 | fix-3 | deepseek-flash | no | 13650 | 4679 | 0 | 182144 | 0.0054 |
| 2026-11-10 | docs | deepseek-flash | no | 106217 | 11616 | 0 | 256 | 0.0229 |

Total: $0.1272. Prices: deepseek line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
