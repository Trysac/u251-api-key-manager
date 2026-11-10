# api-key-manager

[![PyPI version](https://img.shields.io/pypi/v/trysac-api-key-manager)](https://pypi.org/project/trysac-api-key-manager/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-api-key-manager)](LICENSE)
[![CI](https://github.com/Trysac/u251-api-key-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u251-api-key-manager/actions/workflows/ci.yml)

Issue, verify, rotate and revoke API keys: prefixed tokens with a CRC32 checksum, peppered HMAC-SHA256 digests at rest, grace-period rotation and a pluggable key store

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-api-key-manager
# or
uv add trysac-api-key-manager
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import api_key_manager

# normalize() trims surrounding whitespace and lower-cases the text.
print(api_key_manager.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    api_key_manager.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
