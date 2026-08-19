from datetime import UTC, datetime
from decimal import Decimal

import pytest

from proofflow.canonical import canonical_json, sha256_digest


def test_canonical_hash_is_stable_across_mapping_order() -> None:
    left = {"b": Decimal("2.00"), "a": [1, datetime(2026, 8, 20, tzinfo=UTC)]}
    right = {"a": [1, datetime(2026, 8, 20, tzinfo=UTC)], "b": Decimal("2")}

    assert canonical_json(left) == canonical_json(right)
    assert sha256_digest(left) == sha256_digest(right)


def test_floats_are_forbidden_in_business_hashes() -> None:
    with pytest.raises(TypeError, match="use Decimal"):
        canonical_json({"amount": 0.1})


def test_naive_datetimes_are_forbidden() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json({"when": datetime(2026, 8, 20)})


def test_explicit_exclusion_is_recursive() -> None:
    left = {"content_hash": "old", "nested": {"content_hash": "nested-old", "x": 1}}
    right = {"content_hash": "new", "nested": {"content_hash": "nested-new", "x": 1}}
    excluded = frozenset({"content_hash"})

    assert sha256_digest(left, exclude_keys=excluded) == sha256_digest(right, exclude_keys=excluded)
