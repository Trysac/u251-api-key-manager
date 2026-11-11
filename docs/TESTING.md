# Testing

## Running

The repository contains `tests/test_api_key_manager.py` and uses pytest.

```sh
pytest tests/test_api_key_manager.py
```

## Policy

- Tests import the public API from `api_key_manager` and assert return values, `ApiKeyError.code` values, event payloads and the redacted `KeyRecord` representation.
- The test module uses deterministic helpers `_fixed_rng`, `_constant_rng`, `_make_default_rng`, `make_manager` and `recompute_checksum`; it does not need network access.
- No coverage threshold or separate gate script is present in the provided source tree.

## Tiers

No separate conformance tier is present. All tests are in `tests/test_api_key_manager.py`.

## Layout

`tests/test_api_key_manager.py` is the only test module in the provided source tree. It includes tests named `test_key_record_repr_redacts_digest`, `test_key_record_frozen`, `test_in_memory_store_put_get_replace`, `test_in_memory_store_full`, `test_in_memory_store_invalid_max_entries`, `test_constructor_invalid_prefix`, `test_constructor_invalid_pepper`, `test_issue_returns_expected_token_and_record`, `test_issue_token_not_stored`, `test_issue_invalid_owner`, `test_issue_id_collision`, `test_issue_store_full_propagates`, `test_verify_success_returns_record` and `test_verify_bad_checksum`. These cover the record repr and frozen dataclass, in-memory store replace/full/invalid max, constructor validation, the acceptance token vector, that the token is not stored, invalid owner, id collision, store-full propagation, successful verification and bad-checksum rejection.
