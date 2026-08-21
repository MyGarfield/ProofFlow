"""Canonical serialization and SHA-256 helpers used by the evidence plane."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence, Set
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def _decimal_text(value: Decimal) -> str:
    """Return a non-exponential decimal representation with no float conversion."""
    if not value.is_finite():
        raise ValueError("non-finite Decimal values are not canonicalizable")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _datetime_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime values must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonicalize(value: Any, *, exclude_keys: frozenset[str] = frozenset()) -> Any:
    """Convert a supported value into a stable JSON-compatible structure.

    ``exclude_keys`` applies recursively and is intended for explicitly documented
    non-business fields such as ``content_hash``. Callers must not use it to hide
    material business inputs.
    """
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python", by_alias=True, exclude_none=False)
    if isinstance(value, Enum):
        return canonicalize(value.value, exclude_keys=exclude_keys)
    if isinstance(value, Decimal):
        return _decimal_text(value)
    if isinstance(value, datetime):
        return _datetime_text(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Mapping):
        return {
            str(key): canonicalize(item, exclude_keys=exclude_keys)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in exclude_keys
        }
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        items = [canonicalize(item, exclude_keys=exclude_keys) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [canonicalize(item, exclude_keys=exclude_keys) for item in value]
    if value is None or isinstance(value, (str, int, bool, float)):
        if isinstance(value, float):
            raise TypeError(
                "float values are forbidden in canonical business payloads; use Decimal"
            )
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any, *, exclude_keys: frozenset[str] = frozenset()) -> bytes:
    payload = canonicalize(value, exclude_keys=exclude_keys)
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_digest(value: Any, *, exclude_keys: frozenset[str] = frozenset()) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value, exclude_keys=exclude_keys)).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()
