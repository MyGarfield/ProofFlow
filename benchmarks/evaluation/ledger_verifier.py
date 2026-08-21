"""Independent verifier and aggregator for append-only evaluation ledgers.

This module intentionally does not import ``suite.classify_scenario_observation``
or any producer-side runner. It validates the ledger from its serialized public
contract and computes report status/arm counts independently.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from math import isfinite
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .fixture import FIXTURE_MANIFEST_PATH, fixture_manifest_digest, validate_fixture_manifest

EVALUATION_DIR = Path(__file__).resolve().parent
SCENARIO_MANIFEST_PATH = EVALUATION_DIR / "scenarios.json"
SCENARIO_SCHEMA_PATH = EVALUATION_DIR / "scenarios.schema.json"
LEDGER_SCHEMA_PATH = EVALUATION_DIR / "run-ledger.schema.json"
REPORT_SCHEMA_PATH = EVALUATION_DIR / "evaluation-report.schema.json"
ARMS = ("deterministic_reference", "single_agent", "six_agent")
VERIFIER_ID = "proofflow.ledger-independent-verifier/v2"


def _duplicate_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _finite(value: object) -> None:
    if isinstance(value, float) and not isfinite(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, Mapping):
        for item in value.values():
            _finite(item)
    elif isinstance(value, list):
        for item in value:
            _finite(item)


def _strict_json(raw: str | bytes) -> object:
    value = json.loads(raw, object_pairs_hook=_duplicate_guard, parse_constant=_reject_constant)
    _finite(value)
    return value


def _read_json(path: Path) -> dict[str, Any]:
    value = _strict_json(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be an object")
    return value


def _digest(path: Path) -> str:
    return f"sha256:{sha256(path.read_bytes()).hexdigest()}"


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return f"sha256:{sha256(payload).hexdigest()}"


def _result(status: str, *reason_codes: str, **extra: Any) -> dict[str, Any]:
    return {
        "verifier": VERIFIER_ID,
        "status": status,
        "reason_codes": sorted(set(reason_codes)),
        **extra,
    }


def _schemas_and_manifest() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _read_json(SCENARIO_MANIFEST_PATH)
    scenario_schema = _read_json(SCENARIO_SCHEMA_PATH)
    ledger_schema = _read_json(LEDGER_SCHEMA_PATH)
    Draft202012Validator.check_schema(scenario_schema)
    Draft202012Validator.check_schema(ledger_schema)
    Draft202012Validator(scenario_schema, format_checker=FormatChecker()).validate(manifest)
    return manifest, ledger_schema


def _contract_status(result: Mapping[str, Any], expected: Mapping[str, Any]) -> str:
    signals = result["unsafe_signals"]
    if any(signals.values()):
        return "UNSAFE_SUCCESS"
    fields = (
        "outcome_class",
        "terminal_stage",
        "approval_required",
        "external_side_effects_enabled",
        "value_emitted",
        "artifact_verification_valid",
    )
    if any(result[field] != expected[field] for field in fields):
        return "FAIL"
    if set(result["issue_codes"]) != set(expected["required_issue_codes"]):
        return "FAIL"
    if not set(expected["required_trace_events"]).issubset(set(result["trace_events"])):
        return "FAIL"
    return "PASS"


def _measurement_reasons(measurement: Mapping[str, Any], *, kind: str) -> list[str]:
    complete = measurement["complete"]
    if kind == "latency":
        fields = ("end_to_end_ms", "active_compute_ms", "human_wait_ms")
    else:
        fields = (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "total_cost",
            "currency",
            "rate_card_id",
        )
    values = [measurement[field] for field in fields]
    if complete and (
        any(value is None for value in values) or measurement["unknown_reason"] is not None
    ):
        return [f"{kind.upper()}_COMPLETENESS_INVALID"]
    if not complete and (
        any(value is not None for value in values) or measurement["unknown_reason"] is None
    ):
        return [f"{kind.upper()}_UNKNOWN_SEMANTICS_INVALID"]
    return []


def verify_run_ledger(
    ledger: Mapping[str, Any] | str | bytes | None,
    *,
    expected_repository_commit: str | None = None,
) -> dict[str, Any]:
    """Verify one ledger without importing producer execution/classification code."""
    if ledger is None:
        return _result("UNKNOWN", "LEDGER_MISSING")
    try:
        if isinstance(ledger, (str, bytes)):
            parsed = _strict_json(ledger)
        else:
            _finite(ledger)
            parsed = ledger
        if not isinstance(parsed, Mapping):
            return _result("UNKNOWN", "LEDGER_SCHEMA_INVALID")
        _, schema = _schemas_and_manifest()
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(parsed),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            return _result("UNKNOWN", "LEDGER_SCHEMA_INVALID")
        manifest, _ = _schemas_and_manifest()
        try:
            validate_fixture_manifest()
        except ValueError:
            return _result("UNKNOWN", "FIXTURE_MANIFEST_INVALID")
    except (TypeError, ValueError, json.JSONDecodeError):
        return _result("UNKNOWN", "LEDGER_JSON_INVALID")

    expected_fixture = fixture_manifest_digest()
    expected_scenario = _digest(SCENARIO_MANIFEST_PATH)
    root_provenance = parsed["provenance"]
    reasons: list[str] = []
    if root_provenance["fixture_manifest_sha256"] != expected_fixture:
        reasons.append("FIXTURE_MANIFEST_DIGEST_MISMATCH")
    if root_provenance["scenario_manifest_sha256"] != expected_scenario:
        reasons.append("SCENARIO_MANIFEST_DIGEST_MISMATCH")
    if expected_repository_commit is None:
        reasons.append("SOURCE_COMMIT_EXPECTATION_MISSING")
    elif root_provenance["repository_commit"] != expected_repository_commit:
        reasons.append("SOURCE_COMMIT_MISMATCH")

    scenarios = {item["id"]: item for item in manifest["scenarios"]}
    seen_keys: set[tuple[str, str, int, int]] = set()
    seen_entries: set[str] = set()
    seen_runs: set[str] = set()
    pair_groups: defaultdict[tuple[str, int, int], list[Mapping[str, Any]]] = defaultdict(list)
    for entry in parsed["entries"]:
        key = (entry["arm_id"], entry["scenario_id"], entry["replicate_id"], entry["attempt"])
        if key in seen_keys:
            reasons.append("LEDGER_ENTRY_KEY_NOT_UNIQUE")
        seen_keys.add(key)
        if entry["entry_id"] in seen_entries:
            reasons.append("LEDGER_ENTRY_ID_NOT_UNIQUE")
        seen_entries.add(entry["entry_id"])
        if entry["run_id"] in seen_runs:
            reasons.append("LEDGER_RUN_ID_NOT_UNIQUE")
        seen_runs.add(entry["run_id"])
        scenario = scenarios.get(entry["scenario_id"])
        if scenario is None:
            reasons.append("UNKNOWN_SCENARIO")
            continue
        if entry["arm_id"] not in scenario["arm_ids"]:
            reasons.append("ARM_NOT_ALLOWED_FOR_SCENARIO")
        if entry["fixture_manifest_sha256"] != expected_fixture:
            reasons.append("ENTRY_FIXTURE_MANIFEST_DIGEST_MISMATCH")
        if entry["scenario_manifest_sha256"] != expected_scenario:
            reasons.append("ENTRY_SCENARIO_MANIFEST_DIGEST_MISMATCH")
        if entry["repository_commit"] != root_provenance["repository_commit"]:
            reasons.append("ENTRY_SOURCE_COMMIT_MISMATCH")
        try:
            started = datetime.fromisoformat(entry["started_at"].replace("Z", "+00:00"))
            finished = datetime.fromisoformat(entry["finished_at"].replace("Z", "+00:00"))
            if finished < started:
                reasons.append("ENTRY_TIMESTAMP_ORDER_INVALID")
        except ValueError:
            reasons.append("ENTRY_TIMESTAMP_INVALID")
        result = entry["result"]
        if entry["execution_status"] == "NOT_EXECUTED":
            if entry["status"] != "UNKNOWN" or result is not None:
                reasons.append("UNEXECUTED_RESULT_NOT_UNKNOWN")
        else:
            if result is None:
                if entry["status"] != "UNKNOWN":
                    reasons.append("EXECUTED_RESULT_MISSING")
            else:
                if result["issue_codes"] != entry["issue_codes"]:
                    reasons.append("RESULT_ISSUE_BINDING_MISMATCH")
                expected_status = _contract_status(result, scenario["expected"])
                if entry["status"] != expected_status:
                    reasons.append("RESULT_STATUS_MISMATCH")
        reasons.extend(_measurement_reasons(entry["latency"], kind="latency"))
        reasons.extend(_measurement_reasons(entry["cost"], kind="cost"))
        pair_groups[(entry["scenario_id"], entry["replicate_id"], entry["attempt"])].append(entry)

    applicable = {item["id"]: set(item["arm_ids"]) for item in manifest["scenarios"]}
    for (scenario_id, _replicate_id, _attempt), entries in pair_groups.items():
        arms = {item["arm_id"] for item in entries}
        if arms != applicable[scenario_id]:
            reasons.append("PAIR_ARM_SET_MISMATCH")
    if reasons:
        return _result("UNKNOWN", *reasons)
    return _result("VERIFIED", entries_verified=len(parsed["entries"]))


def aggregate_run_ledger(
    ledger: Mapping[str, Any] | None,
    *,
    expected_repository_commit: str | None = None,
) -> dict[str, Any]:
    """Build an executed/mixed report while retaining UNKNOWN/null semantics."""
    manifest, _ = _schemas_and_manifest()
    if ledger is None:
        entries: list[Mapping[str, Any]] = []
        ledger_status = "PROTOCOL_VALIDATED_NOT_EXECUTED"
        ledger_digest = None
    else:
        verification = verify_run_ledger(
            ledger, expected_repository_commit=expected_repository_commit
        )
        if verification["status"] != "VERIFIED":
            raise ValueError("cannot aggregate an unverified ledger")
        entries = list(ledger["entries"])
        ledger_digest = _canonical_digest(ledger)
        executed = any(item["execution_status"] == "EXECUTED" for item in entries)
        unexecuted = any(item["execution_status"] == "NOT_EXECUTED" for item in entries)
        ledger_status = "MIXED_EXECUTION" if executed and unexecuted else "EXECUTED"
    arms: list[dict[str, Any]] = []
    for arm_id in ARMS:
        arm_entries = [item for item in entries if item["arm_id"] == arm_id]
        counts = Counter(item["status"] for item in arm_entries)
        if not arm_entries or all(
            item["execution_status"] == "NOT_EXECUTED" for item in arm_entries
        ):
            execution_status = "NOT_EXECUTED"
        elif all(item["execution_status"] == "EXECUTED" for item in arm_entries):
            execution_status = "EXECUTED"
        else:
            execution_status = "MIXED"
        arms.append(
            {
                "arm_id": arm_id,
                "execution_status": execution_status,
                "score_status": "UNKNOWN",
                "gate_status": "NOT_REQUIRED" if arm_id == "deterministic_reference" else "BLOCKED",
                "reason_codes": [
                    "ARM_NOT_EXECUTED"
                    if execution_status == "NOT_EXECUTED"
                    else "OFFICIAL_SCORE_REQUIRES_PAIRED_ARMS"
                ],
                "entry_count": len(arm_entries),
                "status_counts": (
                    None
                    if not arm_entries
                    else {
                        status: counts.get(status, 0)
                        for status in ("PASS", "FAIL", "UNKNOWN", "UNSAFE_SUCCESS")
                    }
                ),
            }
        )
    complete_pairs = 0
    incomplete_pairs = 0
    for scenario in manifest["scenarios"]:
        applicable_arms = set(scenario["arm_ids"])
        for replicate_id in sorted({item["replicate_id"] for item in entries} or {1}):
            pair = [
                item
                for item in entries
                if item["scenario_id"] == scenario["id"] and item["replicate_id"] == replicate_id
            ]
            if not pair:
                continue
            if {item["arm_id"] for item in pair} == applicable_arms and all(
                item["status"] != "UNKNOWN" for item in pair
            ):
                complete_pairs += 1
            else:
                incomplete_pairs += 1
    report = {
        "schema_version": "proofflow.evaluation-report/v2",
        "report_status": ledger_status,
        "execution_claim": (
            "NONE"
            if not entries
            else "DETERMINISTIC_REFERENCE_ONLY"
            if {item["arm_id"] for item in entries if item["execution_status"] == "EXECUTED"}
            == {"deterministic_reference"}
            else "MIXED_PARTIAL"
        ),
        "protocol_manifest_sha256": _digest(SCENARIO_MANIFEST_PATH),
        "ledger_sha256": ledger_digest,
        "arms": arms,
        "scorecard": [
            {
                "score_id": item["score_id"],
                "official_weight_points": item["official_weight_points"],
                "status": "UNKNOWN",
                "points": None,
                "reason_code": "OFFICIAL_SCORE_REQUIRES_PAIRED_ARMS",
            }
            for item in manifest["official_score_mapping"]
        ],
        "pairing_summary": {
            "unit": "scenario_id+replicate_id+attempt",
            "complete_pairs": complete_pairs,
            "incomplete_pairs": incomplete_pairs,
            "unknown_is_not_counted_as_pass_or_fail": True,
        },
        "metric_contract": {
            "latency_unit": "milliseconds",
            "cost_units": ["USD_OR_DECLARED_CURRENCY", "tokens", "milliseconds"],
            "unknown_cost_representation": "UNKNOWN_NOT_ZERO",
            "reliability_denominator": "attempted_runs",
        },
        "provenance": {
            "fixture_manifest_sha256": fixture_manifest_digest(),
            "fixture_schema_sha256": _digest(
                FIXTURE_MANIFEST_PATH.parent / "fixture-manifest.schema.json"
            ),
            "scenario_schema_sha256": _digest(SCENARIO_SCHEMA_PATH),
            "worker_evidence_schema_sha256": _digest(
                EVALUATION_DIR / "worker-run-evidence.schema.json"
            ),
            "suite_source_sha256": _digest(EVALUATION_DIR / "suite.py"),
        },
    }
    payload = json.dumps(
        report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    report["report_hash"] = f"sha256:{sha256(payload).hexdigest()}"
    return report
