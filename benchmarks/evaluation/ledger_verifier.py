"""Independent verifier and aggregator for hash-chained evaluation ledgers.

This module intentionally does not import ``suite.classify_scenario_observation``
or any producer-side runner. It validates the ledger from its serialized public
contract and invokes only the shared Worker evidence semantic gate for executed
Worker records. Hashes are unsigned consistency evidence, not an authenticity
attestation.
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
from .suite import (
    EXPECTED_AGENTTEAMS_COMMIT,
    EXPECTED_AGENTTEAMS_VERSION,
    gate_worker_execution_evidence,
)

EVALUATION_DIR = Path(__file__).resolve().parent
SCENARIO_MANIFEST_PATH = EVALUATION_DIR / "scenarios.json"
SCENARIO_SCHEMA_PATH = EVALUATION_DIR / "scenarios.schema.json"
LEDGER_SCHEMA_PATH = EVALUATION_DIR / "run-ledger.schema.json"
REPORT_SCHEMA_PATH = EVALUATION_DIR / "evaluation-report.schema.json"
WORKER_EVIDENCE_SCHEMA_PATH = EVALUATION_DIR / "worker-run-evidence.schema.json"
ARMS = ("deterministic_reference", "single_agent", "six_agent")
VERIFIER_ID = "proofflow.ledger-independent-verifier/v2"
GENESIS_ENTRY_SHA256 = "sha256:" + "0" * 64


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
    previous_entry_sha256 = GENESIS_ENTRY_SHA256
    for expected_index, entry in enumerate(parsed["entries"], start=1):
        if entry["entry_index"] != expected_index:
            reasons.append("LEDGER_ENTRY_SEQUENCE_INVALID")
        if entry["previous_entry_sha256"] != previous_entry_sha256:
            reasons.append("LEDGER_PREVIOUS_HASH_MISMATCH")
        computed_entry_sha256 = _canonical_digest(
            {key: value for key, value in entry.items() if key != "entry_sha256"}
        )
        if entry["entry_sha256"] != computed_entry_sha256:
            reasons.append("LEDGER_ENTRY_HASH_MISMATCH")
        previous_entry_sha256 = entry["entry_sha256"]
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
        is_worker_arm = entry["arm_id"] in ("single_agent", "six_agent")
        if (entry["execution_status"] == "NOT_EXECUTED" or not is_worker_arm) and any(
            entry[field] is not None
            for field in (
                "model_provider_id",
                "model_id",
                "model_configuration_digest",
                "agentteams_version",
                "agentteams_commit",
            )
        ):
            reasons.append("UNEXECUTED_MODEL_PROVENANCE_NOT_NULL")
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
        worker_evidence = entry["worker_evidence"]
        worker_evidence_sha256 = entry["worker_evidence_sha256"]
        requires_worker_evidence = is_worker_arm
        if entry["execution_status"] == "NOT_EXECUTED" or not requires_worker_evidence:
            if worker_evidence is not None or worker_evidence_sha256 is not None:
                reasons.append("UNEXECUTED_WORKER_EVIDENCE_NOT_NULL")
        elif not isinstance(worker_evidence, Mapping) or worker_evidence_sha256 is None:
            reasons.append("EXECUTED_WORKER_EVIDENCE_MISSING")
        else:
            try:
                worker_digest = _canonical_digest(worker_evidence)
            except (TypeError, ValueError, OverflowError):
                reasons.append("WORKER_EVIDENCE_HASH_INVALID")
                worker_digest = None
            if worker_digest != worker_evidence_sha256:
                reasons.append("WORKER_EVIDENCE_HASH_MISMATCH")
            try:
                worker_schema = _read_json(WORKER_EVIDENCE_SCHEMA_PATH)
                Draft202012Validator.check_schema(worker_schema)
                worker_errors = Draft202012Validator(
                    worker_schema, format_checker=FormatChecker()
                ).iter_errors(worker_evidence)
                if next(worker_errors, None) is not None:
                    reasons.append("WORKER_EVIDENCE_SCHEMA_INVALID")
            except (TypeError, ValueError, json.JSONDecodeError):
                reasons.append("WORKER_EVIDENCE_SCHEMA_INVALID")
            worker_provenance = worker_evidence.get("provenance")
            worker_model = worker_evidence.get("model")
            worker_repository_commit = (
                worker_provenance.get("repository_commit")
                if isinstance(worker_provenance, Mapping)
                else None
            )
            if (
                worker_evidence.get("arm_id") != entry["arm_id"]
                or worker_evidence.get("scenario_id") != entry["scenario_id"]
                or worker_evidence.get("run_id") != entry["run_id"]
                or worker_evidence.get("fixture_manifest_sha256")
                != entry["fixture_manifest_sha256"]
                or worker_evidence.get("scenario_manifest_sha256")
                != entry["scenario_manifest_sha256"]
                or worker_repository_commit != entry["repository_commit"]
                or not isinstance(worker_model, Mapping)
                or worker_model.get("provider_id") != entry["model_provider_id"]
                or worker_model.get("model_id") != entry["model_id"]
                or worker_model.get("configuration_digest") != entry["model_configuration_digest"]
                or not isinstance(worker_provenance, Mapping)
                or worker_provenance.get("agentteams_version") != entry["agentteams_version"]
                or worker_provenance.get("agentteams_commit") != entry["agentteams_commit"]
            ):
                reasons.append("WORKER_EVIDENCE_BINDING_MISMATCH")
            if entry["model_configuration_digest"] is None:
                reasons.append("WORKER_MODEL_PROVENANCE_MISSING")
            if entry["agentteams_version"] != EXPECTED_AGENTTEAMS_VERSION:
                reasons.append("AGENTTEAMS_VERSION_MISMATCH")
            if entry["agentteams_commit"] != EXPECTED_AGENTTEAMS_COMMIT:
                reasons.append("AGENTTEAMS_COMMIT_MISMATCH")
            semantic_gate = gate_worker_execution_evidence(
                worker_evidence,
                arm_id=entry["arm_id"],
                scenario_id=entry["scenario_id"],
                expected_repository_commit=entry["repository_commit"],
            )
            if semantic_gate["status"] != "READY":
                reasons.append("WORKER_EVIDENCE_SEMANTIC_INVALID")
        pair_groups[(entry["scenario_id"], entry["replicate_id"], entry["attempt"])].append(entry)

    applicable = {item["id"]: set(item["arm_ids"]) for item in manifest["scenarios"]}
    planned_replicates = parsed["coverage_plan"]["replicate_ids"]
    planned_attempts = parsed["coverage_plan"]["attempts"]
    expected_keys = {
        (arm_id, scenario["id"], replicate_id, attempt)
        for scenario in manifest["scenarios"]
        for arm_id in scenario["arm_ids"]
        for replicate_id in planned_replicates
        for attempt in planned_attempts
    }
    missing_keys = expected_keys - seen_keys
    unexpected_keys = seen_keys - expected_keys
    if missing_keys:
        reasons.append("LEDGER_RUN_PLAN_COVERAGE_MISSING")
    if unexpected_keys:
        reasons.append("LEDGER_RUN_PLAN_ENTRY_UNEXPECTED")
    for scenario in manifest["scenarios"]:
        for replicate_id in planned_replicates:
            for attempt in planned_attempts:
                entries = pair_groups[(scenario["id"], replicate_id, attempt)]
                arms = {item["arm_id"] for item in entries}
                if arms != applicable[scenario["id"]]:
                    reasons.append("PAIR_ARM_SET_MISMATCH")
    expected_root = _canonical_digest(
        {key: value for key, value in parsed.items() if key != "ledger_root_sha256"}
    )
    if parsed["ledger_root_sha256"] != expected_root:
        reasons.append("LEDGER_ROOT_HASH_MISMATCH")
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
    pairing_keys = {
        (item["scenario_id"], item["replicate_id"], item["attempt"]) for item in entries
    }
    for scenario_id, replicate_id, attempt in sorted(pairing_keys):
        scenario = next(item for item in manifest["scenarios"] if item["id"] == scenario_id)
        pair = [
            item
            for item in entries
            if (
                item["scenario_id"],
                item["replicate_id"],
                item["attempt"],
            )
            == (scenario_id, replicate_id, attempt)
        ]
        if {item["arm_id"] for item in pair} == set(scenario["arm_ids"]) and all(
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
