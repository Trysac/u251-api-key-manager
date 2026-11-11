# Stack

## Used

| Tool | Why |
|---|---|
| Python >= 3.10 | The code uses `str | None`, `dataclass(slots=True)` and `from __future__ import annotations`. |
| Python standard library (`hmac`, `zlib`, `secrets`, `re`, `logging`, `time`, `dataclasses`, `typing`, `collections.abc`) | Runtime has no third-party dependencies. |
| pytest | `tests/test_api_key_manager.py` is a pytest module. |
| `py.typed` | The package ships `src/api_key_manager/py.typed` for type checkers. |

## Discarded

None recorded in the provided source tree.
