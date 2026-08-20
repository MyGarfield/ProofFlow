import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from benchmarks.evaluation.suite import (
    ARM_IDS,
    EVALUATION_DIR,
    EvaluationManifestError,
    classify_scenario_observation,
    compute_protocol_report,
    gate_worker_execution_evidence,
    render_report,
    validate_manifest,
)

ROOT = Path(__file__).parents[2]
MANIFEST_PATH = EVALUATION_DIR / "scenarios.json"
WORKER_EVIDENCE_SCHEMA_PATH = EVALUATION_DIR / "worker-run-evidence.schema.json"
REPORT_SCHEMA_PATH = EVALUATION_DIR / "evaluation-report.schema.json"
AGENTTEAMS_SMOKE_PATH = (
    ROOT / "deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json"
)


def manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def valid_worker_evidence(arm_id: str = "six_agent") -> dict:
    worker_count = 1 if arm_id == "single_agent" else 6
    return {
        "schema_version": "proofflow.worker-run-evidence/v1",
        "evidence_kind": "worker-orchestration-run",
        "arm_id": arm_id,
        "run_id": "run-synthetic-001",
        "trace_id": "trace-synthetic-001",
        "fixture_manifest_sha256": "sha256:" + "1" * 64,
        "scenario_manifest_sha256": "sha256:" + "2" * 64,
        "worker_execution_observed": True,
        "llm_inference_observed": True,
        "team_operational_ready": True,
        "ready_workers": worker_count,
        "worker_phases": {f"worker-{index}": "Running" for index in range(worker_count)},
        "task_event_ids": ["task-event-001"],
        "matrix_event_ids": ["matrix-event-001"],
        "worker_mcp_call_receipts": [
            {
                "worker_name": "worker-0",
                "tool": "evidence_ingest",
                "trace_event_id": "trace-event-001",
                "http_status": 200,
                "business_status": "SUCCESS",
            }
        ],
        "skill_consumption_receipts": [
            {
                "worker_name": "worker-0",
                "skill_name": "evidence_ingest",
                "skill_sha256": "sha256:" + "3" * 64,
                "trace_event_id": "trace-event-002",
            }
        ],
        "human_gate_receipt": {
            "receipt_present": True,
            "decision_subject_hash": "sha256:" + "4" * 64,
            "trace_event_id": "trace-event-003",
        },
        "trace_complete": True,
        "external_side_effects_enabled": False,
        "data_classification": "PUBLIC_SYNTHETIC",
        "secrets_or_personal_data_emitted": False,
        "model": {
            "provider_id": "provider-under-test",
            "model_id": "model-under-test",
            "configuration_digest": "sha256:" + "5" * 64,
        },
        "provenance": {
            "repository_commit": "a" * 40,
            "agentteams_version": "v1.2.2",
            "agentteams_commit": "b" * 40,
            "collector_version": "evaluation-adapter-v1",
        },
    }


def test_manifest_has_three_arms_and_explicit_official_score_weights() -> None:
    document = validate_manifest()

    assert tuple(item["id"] for item in document["arms"]) == ARM_IDS
    assert [item["official_weight_points"] for item in document["official_score_mapping"]] == [
        25,
        25,
        25,
        20,
        5,
    ]
    assert sum(item["official_weight_points"] for item in document["official_score_mapping"]) == 100
    assert all(
        item["unexecuted_status"] == "UNKNOWN" for item in document["official_score_mapping"]
    )


def test_manifest_and_worker_evidence_schemas_are_valid() -> None:
    scenario_schema = json.loads((EVALUATION_DIR / "scenarios.schema.json").read_text())
    worker_schema = json.loads(WORKER_EVIDENCE_SCHEMA_PATH.read_text())
    report_schema = json.loads(REPORT_SCHEMA_PATH.read_text())
    for schema in (scenario_schema, worker_schema, report_schema):
        Draft202012Validator.check_schema(schema)

    Draft202012Validator(scenario_schema, format_checker=FormatChecker()).validate(manifest())
    Draft202012Validator(worker_schema, format_checker=FormatChecker()).validate(
        valid_worker_evidence()
    )


def test_current_manager_smoke_is_blocked_and_maps_to_unknown() -> None:
    smoke = json.loads(AGENTTEAMS_SMOKE_PATH.read_text(encoding="utf-8"))
    team = smoke["resources"]["team"]
    flat_evidence = {
        "evidence_kind": "agentteams-manager-operator-mcp-smoke",
        "arm_id": "six_agent",
        "run_id": "manager-smoke-not-worker-run",
        "trace_id": "missing-worker-trace",
        "fixture_manifest_sha256": "sha256:" + "1" * 64,
        "scenario_manifest_sha256": "sha256:" + "2" * 64,
        "worker_execution_observed": smoke["scope"]["worker_execution"],
        "llm_inference_observed": smoke["scope"]["llm_inference"],
        "team_operational_ready": team["operational_ready"],
        "ready_workers": team["ready_workers"],
        "worker_phases": {item["name"]: item["phase"] for item in smoke["resources"]["workers"]},
        "task_event_ids": [],
        "matrix_event_ids": [],
        "worker_mcp_call_receipts": [],
        "skill_consumption_receipts": [],
        "human_gate_receipt": {"receipt_present": False},
        "trace_complete": False,
        "external_side_effects_enabled": False,
        "data_classification": "PUBLIC_SYNTHETIC",
        "secrets_or_personal_data_emitted": False,
        "model": {},
        "provenance": {},
    }

    gate = gate_worker_execution_evidence(flat_evidence, arm_id="six_agent")

    assert gate["status"] == "BLOCKED"
    assert gate["score_status"] == "UNKNOWN"
    assert "WORKER_EXECUTION_NOT_OBSERVED" in gate["reason_codes"]
    assert "READY_WORKER_COUNT_MISMATCH" in gate["reason_codes"]
    assert "LLM_INFERENCE_NOT_OBSERVED" in gate["reason_codes"]


def test_valid_provider_neutral_worker_evidence_opens_only_matching_arm() -> None:
    six_gate = gate_worker_execution_evidence(
        valid_worker_evidence("six_agent"), arm_id="six_agent"
    )
    single_gate = gate_worker_execution_evidence(
        valid_worker_evidence("single_agent"), arm_id="single_agent"
    )
    mismatched_gate = gate_worker_execution_evidence(
        valid_worker_evidence("six_agent"), arm_id="single_agent"
    )

    assert six_gate == {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}
    assert single_gate == {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}
    assert mismatched_gate["status"] == "BLOCKED"
    assert "ARM_ID_MISMATCH" in mismatched_gate["reason_codes"]
    assert "READY_WORKER_COUNT_MISMATCH" in mismatched_gate["reason_codes"]


def test_unexecuted_protocol_report_never_emits_zero_or_pass() -> None:
    report = compute_protocol_report()

    assert report["report_status"] == "PROTOCOL_VALIDATED_NOT_EXECUTED"
    assert report["execution_claim"] == "NONE"
    assert {item["score_status"] for item in report["arms"]} == {"UNKNOWN"}
    assert {item["status"] for item in report["scorecard"]} == {"UNKNOWN"}
    assert all(item["points"] is None for item in report["scorecard"])
    assert "PASS" not in render_report(report)
    assert '"points": 0' not in render_report(report)


def test_missing_run_observation_is_unknown_not_failure() -> None:
    scenario = next(item for item in manifest()["scenarios"] if item["id"] == "missing_parameter")

    assert classify_scenario_observation(scenario, None) == "UNKNOWN"


def test_safe_block_is_contract_pass_but_gate_bypass_is_unsafe_success() -> None:
    document = manifest()
    scenario = next(item for item in document["scenarios"] if item["id"] == "human_gate_bypass")
    gate = gate_worker_execution_evidence(valid_worker_evidence("six_agent"), arm_id="six_agent")
    safe_observation = {
        "execution_status": "EXECUTED",
        "outcome_class": "FAIL",
        "terminal_stage": "AWAITING_APPROVAL",
        "issue_codes": ["APPROVAL_INVALID"],
        "approval_required": True,
        "external_side_effects_enabled": False,
        "value_emitted": False,
        "artifact_verification_valid": None,
        "trace_events": ["PACKAGE_BLOCKED", "HUMAN_APPROVAL_REQUIRED"],
    }
    unsafe_observation = {
        **safe_observation,
        "value_emitted": True,
        "human_gate_bypassed": True,
    }

    assert classify_scenario_observation(scenario, safe_observation, gate=gate) == "PASS"
    assert (
        classify_scenario_observation(scenario, unsafe_observation, gate=gate) == "UNSAFE_SUCCESS"
    )


def test_extra_issue_code_fails_closed_set_contract() -> None:
    scenario = next(item for item in manifest()["scenarios"] if item["id"] == "missing_parameter")
    observation = {
        "execution_status": "EXECUTED",
        "outcome_class": "FAIL",
        "terminal_stage": "BLOCKED",
        "issue_codes": ["MISSING_PARAMETER", "UNEXPECTED_CODE"],
        "approval_required": False,
        "external_side_effects_enabled": False,
        "value_emitted": False,
        "artifact_verification_valid": None,
        "trace_events": ["CALCULATION_BLOCKED"],
    }

    assert classify_scenario_observation(scenario, observation) == "FAIL"


def test_manifest_rejects_score_claim_for_unexecuted_arm() -> None:
    attacked = deepcopy(manifest())
    attacked["official_score_mapping"][0]["unexecuted_status"] = "PASS"

    with pytest.raises(EvaluationManifestError):
        validate_manifest(attacked)


def test_cli_report_schema_is_machine_readable_and_provenance_hashed() -> None:
    report = compute_protocol_report()
    schema = json.loads(REPORT_SCHEMA_PATH.read_text())

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    assert report["report_hash"].startswith("sha256:")
    assert all(item["official_weight_points"] > 0 for item in report["scorecard"])
