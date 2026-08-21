"""Offline validation for the public synthetic evaluation fixture bundle."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
FIXTURE_MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
FIXTURE_SCHEMA_PATH = FIXTURE_DIR / "fixture-manifest.schema.json"
EXPECTED_SCENARIO_IDS = (
    "happy_path",
    "missing_parameter",
    "conflicting_evidence",
    "insufficient_rule_authority",
    "document_prompt_injection",
    "mcp_cross_role_denial",
    "human_gate_bypass",
    "approval_toctou",
    "duplicate_delegation",
    "worker_crash_resume",
    "tool_timeout",
    "trace_gap",
    "package_tamper",
    "cross_tenant_reference",
)


class FixtureManifestError(ValueError):
    """Raised when a public fixture manifest or referenced file is invalid."""


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FixtureManifestError(f"{path.name} must contain a JSON object")
    return value


def _digest(path: Path) -> str:
    return f"sha256:{sha256(path.read_bytes()).hexdigest()}"


def fixture_manifest_digest() -> str:
    """Return the checked-in fixture manifest digest for provenance binding."""
    return _digest(FIXTURE_MANIFEST_PATH)


def _validate_schema(document: Mapping[str, Any]) -> None:
    schema = _read_json(FIXTURE_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        location = ".".join(str(item) for item in errors[0].absolute_path) or "$"
        raise FixtureManifestError(f"fixture manifest rejected {location}: {errors[0].validator}")


def _safe_public_path(relative_path: str) -> Path:
    candidate = (ROOT / relative_path).resolve()
    if ROOT not in candidate.parents or not candidate.is_file():
        raise FixtureManifestError(
            f"fixture path is missing or outside repository: {relative_path}"
        )
    return candidate


def validate_fixture_manifest(manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate public fixture files, hashes, and all 14 scenario bindings."""
    document = dict(manifest) if manifest is not None else _read_json(FIXTURE_MANIFEST_PATH)
    _validate_schema(document)
    if (
        tuple(item["scenario_id"] for item in document["scenario_bindings"])
        != EXPECTED_SCENARIO_IDS
    ):
        raise FixtureManifestError("fixture bindings must cover the ordered 14-scenario protocol")

    base_manifest_path = _safe_public_path(document["base_case_manifest_path"])
    if _digest(base_manifest_path) != document["base_case_manifest_sha256"]:
        raise FixtureManifestError("base case manifest digest mismatch")
    base_manifest = _read_json(base_manifest_path)
    if base_manifest.get("fixture_status") != "SYNTHETIC":
        raise FixtureManifestError("base case must be explicitly synthetic")
    if base_manifest.get("case_id") != "case-happy-001":
        raise FixtureManifestError("unexpected base case identifier")

    base_documents = {item["document_id"]: item for item in base_manifest.get("documents", [])}
    for item in document["documents"]:
        path = _safe_public_path(item["path"])
        if _digest(path) != item["sha256"]:
            raise FixtureManifestError(f"document digest mismatch: {item['path']}")
        base_item = base_documents.get(item["document_id"])
        normalized_item = dict(item)
        normalized_item["path"] = Path(item["path"]).name
        if base_item is None or base_item != normalized_item:
            raise FixtureManifestError(
                f"document does not match base case manifest: {item['document_id']}"
            )
    return document
