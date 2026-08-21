from __future__ import annotations

import tempfile
from pathlib import Path

from validate_manifest import strict_load


def test_duplicate_key_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "duplicate.json"
        path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
        try:
            strict_load(path)
        except ValueError as error:
            assert "duplicate JSON key" in str(error)
        else:
            raise AssertionError("duplicate key was accepted")


def test_non_finite_number_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "nonfinite.json"
        path.write_text('{"a": NaN}', encoding="utf-8")
        try:
            strict_load(path)
        except ValueError as error:
            assert "non-finite JSON number" in str(error)
        else:
            raise AssertionError("NaN was accepted")
