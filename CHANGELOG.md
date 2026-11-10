# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added api_key_manager with issue, verify, rotate, revoke for API keys; prefixed tokens with CRC32 checksum, peppered HMAC-SHA256 digests, grace-period rotation, pluggable key store, and typed error codes.
- Initial project structure from the factory utility template.
