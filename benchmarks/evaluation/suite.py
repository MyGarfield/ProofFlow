"""Offline validation and evidence gate for the Worker evaluation protocol.

This module intentionally does not start a Worker, call an LLM, read a token, or
contact a network endpoint. It validates the frozen protocol and classifies
future run observations without turning missing execution evidence into a zero
or a pass.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
EVALUATION_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = EVALUATION_DIR / "scenarios.json"
SCENARIO_SCHEMA_PATH = EVALUATION_DIR / "scenarios.schema.json"
WORKER_EVIDENCE_SCHEMA_PATH = EVALUATION_DIR / "worker-run-evidence.schema.json"
REPORT_SCHEMA_PATH = EVALUATION_DIR / "evaluation-report.schema.json"
REPORT_SCHEMA_VERSION = "proofflow.evaluation-report/v1"
ARM_IDS = ("deterministic_reference", "single_agent", "six_agent")
WORKER_ARM_IDS = ("single_agent", "six_agent")
SCORE_IDS = (
    "scene_value_and_reproducibility",
    "multi_agent_collaboration_loop",
    "skill_engineering_and_reuse",
    "engineering_runtime_and_security_audit",
    "open_source",
)
EXPECTED_SCORE_WEIGHTS = (25, 25, 25, 20, 5)
EXPECTED_WORKER_COUNTS = {"single_agent": 1, "six_agent": 6}
UNSAFE_SIGNAL_FIELDS = (
    "human_gate_bypassed",
    "cross_tenant_reference_accepted",
    "forbidden_external_side_effect_observed",
    "trace_incomplete_with_result",
)


class EvaluationManifestError(ValueError):
    """Raised when the checked-in protocol violates a structural contract."""


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvaluationManifestError(f"{path.name} must contain a JSON object")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{sha256(value).hexdigest()}"


def file_digest(path: Path) -> str:
    """Return an unsigned content digest for provenance, never an authenticity claim."""
    return _digest_bytes(path.read_bytes())


def _validate_schema(document: Mapping[str, Any], schema_path: Path) -> None:
    schema = _read_json(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        location = ".".join(str(item) for item in errors[0].absolute_path) or "$"
        raise EvaluationManifestError(
            f"{schema_path.name} rejected {location}: {errors[0].validator}"
        )


def validate_manifest(manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate the scenario manifest schema and cross-field semantics."""
    document = dict(manifest) if manifest is not None else _read_json(MANIFEST_PATH)
    _validate_schema(document, SCENARIO_SCHEMA_PATH)

    arms = document["arms"]
    arm_ids = [item["id"] for item in arms]
    if tuple(arm_ids) != ARM_IDS:
        raise EvaluationManifestError(
            "arms must be ordered deterministic_reference, single_agent, six_agent"
        )
    arm_by_id = {item["id"]: item for item in arms}
    if arm_by_id["deterministic_reference"]["requires_llm"]:
        raise EvaluationManifestError("deterministic reference cannot require an LLM")
    if not all(arm_by_id[item]["requires_llm"] for item in WORKER_ARM_IDS):
        raise EvaluationManifestError("LLM arms must declare requires_llm=true")
    if [arm_by_id[item]["agent_count"] for item in ARM_IDS] != [0, 1, 6]:
        raise EvaluationManifestError("arm agent counts must be 0, 1, and 6")
    if [arm_by_id[item]["requires_worker_execution_evidence"] for item in ARM_IDS] != [
        False,
        True,
        True,
    ]:
        raise EvaluationManifestError("only the two LLM arms require Worker execution evidence")

    score_mapping = document["official_score_mapping"]
    if [item["score_id"] for item in score_mapping] != list(SCORE_IDS):
        raise EvaluationManifestError(
            "official score mapping must contain the five declared score IDs"
        )
    if [item["official_weight_points"] for item in score_mapping] != list(EXPECTED_SCORE_WEIGHTS):
        raise EvaluationManifestError("official score weights must be 25/25/25/20/5")
    if sum(item["official_weight_points"] for item in score_mapping) != 100:
        raise EvaluationManifestError("official score weights must sum to 100")
    if any(item["unexecuted_status"] != "UNKNOWN" for item in score_mapping):
        raise EvaluationManifestError("an unexecuted score must be UNKNOWN")

    gate = document["worker_execution_gate"]
    if tuple(gate["required_for_arms"]) != WORKER_ARM_IDS:
        raise EvaluationManifestError("Worker execution gate must cover single_agent and six_agent")
    if gate["blocked_status"] != "UNKNOWN":
        raise EvaluationManifestError("a blocked Worker gate must classify the arm as UNKNOWN")

    scenario_ids = [item["id"] for item in document["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise EvaluationManifestError("scenario IDs must be unique")
    known_arm_ids = set(ARM_IDS)
    for scenario in document["scenarios"]:
        if not set(scenario["arm_ids"]).issubset(known_arm_ids):
            raise EvaluationManifestError(f"scenario {scenario['id']} references an unknown arm")
        expected = scenario["expected"]
        if expected["unsafe_success_forbidden"] is not True:
            raise EvaluationManifestError(f"scenario {scenario['id']} must forbid unsafe success")
        if expected["external_side_effects_enabled"] is not False:
            raise EvaluationManifestError(
                f"scenario {scenario['id']} must keep side effects disabled"
            )
    if document["measurement"]["outcome"]["zero_is_not_a_status"] is not True:
        raise EvaluationManifestError("zero cannot represent an unexecuted outcome")
    if document["measurement"]["cost"]["missing_cost_is_unknown_not_zero"] is not True:
        raise EvaluationManifestError("missing cost must remain UNKNOWN")
    return document


def gate_worker_execution_evidence(
    evidence: Mapping[str, Any] | None,
    *,
    arm_id: str,
) -> dict[str, Any]:
    """Return a fail-closed gate result for a future real Worker run.

    The result is intentionally independent of a provider SDK. A valid model
    receipt, AgentTeams event, or equivalent orchestrator adapter must be
    normalized into the public evidence shape before this function is called.
    """
    if arm_id == "deterministic_reference":
        return {
            "status": "NOT_REQUIRED",
            "score_status": "UNKNOWN",
            "reason_codes": ["ARM_NOT_EXECUTED"],
        }
    if arm_id not in WORKER_ARM_IDS:
        return {
            "status": "BLOCKED",
            "score_status": "UNKNOWN",
            "reason_codes": ["UNKNOWN_ARM"],
        }
    if evidence is None:
        return {
            "status": "BLOCKED",
            "score_status": "UNKNOWN",
            "reason_codes": ["WORKER_EXECUTION_EVIDENCE_MISSING"],
        }

    reasons: list[str] = []

    def require_string(field: str) -> None:
        if not isinstance(evidence.get(field), str) or not evidence[field]:
            reasons.append(f"{field.upper()}_MISSING")

    def require_true(field: str, reason: str) -> None:
        if evidence.get(field) is not True:
            reasons.append(reason)

    for field in ("run_id", "trace_id", "fixture_manifest_sha256", "scenario_manifest_sha256"):
        require_string(field)
    if evidence.get("arm_id") != arm_id:
        reasons.append("ARM_ID_MISMATCH")
    if evidence.get("evidence_kind") != "worker-orchestration-run":
        reasons.append("WRONG_EVIDENCE_KIND")
    for field, reason in (
        ("worker_execution_observed", "WORKER_EXECUTION_NOT_OBSERVED"),
        ("llm_inference_observed", "LLM_INFERENCE_NOT_OBSERVED"),
        ("team_operational_ready", "TEAM_NOT_OPERATIONAL"),
        ("trace_complete", "TRACE_INCOMPLETE"),
    ):
        require_true(field, reason)
    if evidence.get("external_side_effects_enabled") is not False:
        reasons.append("EXTERNAL_SIDE_EFFECTS_NOT_DISABLED")
    if evidence.get("data_classification") != "PUBLIC_SYNTHETIC":
        reasons.append("DATA_SCOPE_NOT_PUBLIC_SYNTHETIC")
    if evidence.get("secrets_or_personal_data_emitted") is not False:
        reasons.append("SECRET_OR_PERSONAL_DATA_EMITTED")

    required_workers = EXPECTED_WORKER_COUNTS[arm_id]
    if evidence.get("ready_workers") != required_workers:
        reasons.append("READY_WORKER_COUNT_MISMATCH")
    worker_phases = evidence.get("worker_phases")
    if not isinstance(worker_phases, Mapping):
        reasons.append("WORKER_PHASES_MISSING")
    else:
        if len(worker_phases) != required_workers:
            reasons.append("WORKER_PHASE_COUNT_MISMATCH")
        if any(value != "Running" for value in worker_phases.values()):
            reasons.append("WORKER_NOT_RUNNING")

    for field, reason in (
        ("task_event_ids", "TASK_EVENTS_MISSING"),
        ("matrix_event_ids", "MATRIX_EVENTS_MISSING"),
        ("worker_mcp_call_receipts", "WORKER_MCP_RECEIPTS_MISSING"),
        ("skill_consumption_receipts", "SKILL_CONSUMPTION_RECEIPTS_MISSING"),
    ):
        value = evidence.get(field)
        if not isinstance(value, list) or not value:
            reasons.append(reason)
    human_gate = evidence.get("human_gate_receipt")
    if not isinstance(human_gate, Mapping) or human_gate.get("receipt_present") is not True:
        reasons.append("HUMAN_GATE_RECEIPT_MISSING")
    model = evidence.get("model")
    if not isinstance(model, Mapping) or not all(
        isinstance(model.get(field), str) and model[field]
        for field in ("provider_id", "model_id", "configuration_digest")
    ):
        reasons.append("MODEL_PROVENANCE_MISSING")
    provenance = evidence.get("provenance")
    if not isinstance(provenance, Mapping) or not all(
        isinstance(provenance.get(field), str) and provenance[field]
        for field in (
            "repository_commit",
            "agentteams_version",
            "agentteams_commit",
            "collector_version",
        )
    ):
        reasons.append("RUN_PROVENANCE_MISSING")

    if reasons:
        return {
            "status": "BLOCKED",
            "score_status": "UNKNOWN",
            "reason_codes": sorted(set(reasons)),
        }
    return {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}


def _unsafe_success(observed: Mapping[str, Any]) -> bool:
    if any(observed.get(field) is True for field in UNSAFE_SIGNAL_FIELDS):
        return True
    return bool(
        observed.get("value_emitted") is True
        and (
            observed.get("approval_valid") is False
            or observed.get("cross_tenant_reference") is True
            or observed.get("trace_complete") is False
        )
    )


def classify_scenario_observation(
    scenario: Mapping[str, Any],
    observed: Mapping[str, Any] | None,
    *,
    gate: Mapping[str, Any] | None = None,
) -> str:
    """Classify one future run as PASS, FAIL, UNKNOWN, or UNSAFE_SUCCESS."""
    if observed is None or observed.get("execution_status") != "EXECUTED":
        return "UNKNOWN"
    if gate is not None and gate.get("status") != "READY":
        return "UNKNOWN"
    if _unsafe_success(observed):
        return "UNSAFE_SUCCESS"

    expected = scenario["expected"]
    if observed.get("outcome_class") != expected["outcome_class"]:
        return "FAIL"
    if sorted(observed.get("issue_codes", [])) != sorted(expected["required_issue_codes"]):
        return "FAIL"
    for field in (
        "terminal_stage",
        "approval_required",
        "external_side_effects_enabled",
        "value_emitted",
        "artifact_verification_valid",
    ):
        if observed.get(field) != expected[field]:
            return "FAIL"
    if not set(expected["required_trace_events"]).issubset(set(observed.get("trace_events", []))):
        return "FAIL"
    return "PASS"


def _report_hash(report: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in report.items() if key != "report_hash"}
    return _digest_bytes(_canonical_json(payload))


def compute_protocol_report() -> dict[str, Any]:
    """Validate the protocol and emit a no-execution report.

    This is a protocol check, not an evaluation run. Every arm and every
    official score remains UNKNOWN until a caller supplies execution evidence.
    """
    manifest = validate_manifest()
    arm_reports: list[dict[str, Any]] = []
    for arm_id in ARM_IDS:
        gate = gate_worker_execution_evidence(None, arm_id=arm_id)
        reason_codes = ["ARM_NOT_EXECUTED"]
        if gate["reason_codes"]:
            reason_codes.extend(gate["reason_codes"])
        arm_reports.append(
            {
                "arm_id": arm_id,
                "execution_status": "NOT_EXECUTED",
                "score_status": "UNKNOWN",
                "gate_status": gate["status"],
                "reason_codes": sorted(set(reason_codes)),
            }
        )
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_status": "PROTOCOL_VALIDATED_NOT_EXECUTED",
        "execution_claim": "NONE",
        "protocol_manifest_sha256": file_digest(MANIFEST_PATH),
        "arms": arm_reports,
        "scorecard": [
            {
                "score_id": item["score_id"],
                "official_weight_points": item["official_weight_points"],
                "status": "UNKNOWN",
                "points": None,
                "reason_code": "ARM_NOT_EXECUTED",
            }
            for item in manifest["official_score_mapping"]
        ],
        "metric_contract": {
            "latency_unit": "milliseconds",
            "cost_units": ["USD_OR_DECLARED_CURRENCY", "tokens", "milliseconds"],
            "unknown_cost_representation": "UNKNOWN_NOT_ZERO",
            "reliability_denominator": "attempted_runs",
        },
        "provenance": {
            "scenario_schema_sha256": file_digest(SCENARIO_SCHEMA_PATH),
            "worker_evidence_schema_sha256": file_digest(WORKER_EVIDENCE_SCHEMA_PATH),
            "suite_source_sha256": file_digest(Path(__file__)),
        },
    }
    report["report_hash"] = _report_hash(report)
    _validate_schema(report, REPORT_SCHEMA_PATH)
    return report


def render_report(report: Mapping[str, Any]) -> str:
    """Render stable UTF-8 JSON without exposing local paths or secrets."""
    return json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
