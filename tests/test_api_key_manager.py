"""Behavior tests for the public API of api_key_manager."""

from __future__ import annotations

import pytest

import api_key_manager


def test_normalize_trims_and_lowercases() -> None:
    assert api_key_manager.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        api_key_manager.normalize(value)


def test_version_is_semver() -> None:
    parts = api_key_manager.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
