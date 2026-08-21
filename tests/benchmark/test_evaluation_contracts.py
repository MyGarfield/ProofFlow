import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from benchmarks.evaluation.fixture import fixture_manifest_digest
from benchmarks.evaluation.suite import (
    ARM_IDS,
    EVALUATION_DIR,
    EvaluationManifestError,
    classify_scenario_observation,
    compute_protocol_report,
    file_digest,
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


TEST_REPOSITORY_COMMIT = "a" * 40


def valid_worker_evidence(arm_id: str = "six_agent", scenario_id: str = "happy_path") -> dict:
    specialist_names = (
        []
        if arm_id == "single_agent"
        else ["evidence-agent", "rule-agent", "calculation-agent", "strategy-agent", "audit-agent"]
    )
    specialist_skills = {
        "case-manager": ["document_package", "human_approval"],
        "evidence-agent": ["evidence_ingest", "timeline_build"],
        "rule-agent": ["rule_retrieve"],
        "calculation-agent": ["deterministic_calculate"],
        "strategy-agent": [],
        "audit-agent": ["conflict_detect", "decision_audit"],
    }
    if arm_id == "single_agent":
        specialist_skills = {"case-manager": specialist_skills["case-manager"]}
    scenario = next(item for item in manifest()["scenarios"] if item["id"] == scenario_id)
    human_policy = scenario["evidence_gate"]["human_gate_receipt"]
    human_decision = scenario["evidence_gate"]["required_human_decision"]
    return {
        "schema_version": "proofflow.worker-run-evidence/v2",
        "evidence_kind": "worker-orchestration-run",
        "arm_id": arm_id,
        "scenario_id": scenario_id,
        "run_id": "run-synthetic-001",
        "trace_id": "trace-synthetic-001",
        "fixture_manifest_sha256": fixture_manifest_digest(),
        "scenario_manifest_sha256": file_digest(MANIFEST_PATH),
        "worker_execution_observed": True,
        "llm_inference_observed": True,
        "team_operational_ready": True,
        "leader_phase": "Running",
        "specialist_ready_workers": len(specialist_names),
        "total_worker_containers": 1 + len(specialist_names),
        "worker_roster": {
            "leader_worker_name": "case-manager",
            "specialist_worker_names": specialist_names,
        },
        "specialist_phases": {name: "Running" for name in specialist_names},
        "task_event_ids": ["task-event-001"],
        "matrix_event_ids": ["matrix-event-001"],
        "task_event_receipts": [
            {
                "event_id": "task-event-001",
                "event_type": "TASK_COMPLETED",
                "run_id": "run-synthetic-001",
                "scenario_id": scenario_id,
                "trace_id": "trace-synthetic-001",
                "worker_name": "case-manager",
            }
        ],
        "matrix_event_receipts": [
            {
                "event_id": "matrix-event-001",
                "event_type": "MATRIX_COMPLETED",
                "run_id": "run-synthetic-001",
                "scenario_id": scenario_id,
                "trace_id": "trace-synthetic-001",
                "worker_name": "case-manager",
            }
        ],
        "worker_mcp_call_receipts": [
            {
                "receipt_id": "mcp-receipt-001",
                "worker_name": "case-manager",
                "worker_role": "LEADER",
                "tool": "evidence_ingest",
                "run_id": "run-synthetic-001",
                "scenario_id": scenario_id,
                "trace_id": "trace-synthetic-001",
                "trace_event_id": "trace-event-001",
                "http_status": 200,
                "business_status": "SUCCESS",
            }
        ],
        "skill_consumption_receipts": [
            {
                "receipt_id": f"skill-receipt-{index:03d}",
                "worker_name": worker,
                "worker_role": "LEADER" if worker == "case-manager" else "SPECIALIST",
                "skill_name": skill,
                "skill_sha256": "sha256:" + "3" * 64,
                "run_id": "run-synthetic-001",
                "scenario_id": scenario_id,
                "trace_id": "trace-synthetic-001",
                "trace_event_id": f"trace-skill-{index:03d}",
            }
            for index, (worker, skill) in enumerate(
                (
                    pair
                    for worker, skills in specialist_skills.items()
                    for pair in [(worker, skill) for skill in skills]
                ),
                start=1,
            )
        ],
        "skill_coverage": specialist_skills,
        "capture_completeness": {
            "harness_capture_complete": True,
            "sut_trace_complete": scenario["evidence_gate"]["sut_trace_complete"],
            "captured_trace_event_ids": [
                "trace-event-001",
                "trace-event-003",
                *[
                    f"trace-skill-{index:03d}"
                    for index in range(1, sum(map(len, specialist_skills.values())) + 1)
                ],
            ],
        },
        "sut_trace_events": scenario["expected"]["required_trace_events"],
        **(
            {
                "human_gate_receipt": {
                    "receipt_id": "human-receipt-001",
                    "receipt_present": True,
                    "run_id": "run-synthetic-001",
                    "scenario_id": scenario_id,
                    "trace_id": "trace-synthetic-001",
                    "worker_name": "case-manager",
                    "decision": human_decision or "APPROVED",
                    "decision_subject_hash": "sha256:" + "4" * 64,
                    "trace_event_id": "trace-event-003",
                }
            }
            if human_policy != "NOT_REQUIRED"
            else {}
        ),
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


def test_public_fixture_bundle_is_hashed_and_covers_all_scenarios() -> None:
    document = validate_manifest()

    assert document["fixture_manifest"]["sha256"] == fixture_manifest_digest()
    assert document["fixture_manifest"]["path"] == "benchmarks/evaluation/fixtures/manifest.json"


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
        "leader_phase": team["leader_worker_phase"],
        "specialist_ready_workers": team["ready_workers"],
        "total_worker_containers": smoke["resources"]["proof_flow_worker_containers"],
        "specialist_phases": {
            item["name"]: item["phase"]
            for item in smoke["resources"]["workers"]
            if item["role"] == "worker"
        },
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
    assert gate["reason_codes"] == ["EVIDENCE_SCHEMA_INVALID"]


def test_valid_provider_neutral_worker_evidence_opens_only_matching_arm() -> None:
    six_gate = gate_worker_execution_evidence(
        valid_worker_evidence("six_agent"),
        arm_id="six_agent",
        scenario_id="happy_path",
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )
    single_gate = gate_worker_execution_evidence(
        valid_worker_evidence("single_agent"),
        arm_id="single_agent",
        scenario_id="happy_path",
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )
    mismatched_gate = gate_worker_execution_evidence(
        valid_worker_evidence("six_agent"),
        arm_id="single_agent",
        scenario_id="happy_path",
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )

    assert six_gate == {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}
    assert single_gate == {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}
    assert mismatched_gate["status"] == "BLOCKED"
    assert "ARM_ID_MISMATCH" in mismatched_gate["reason_codes"]
    assert "SPECIALIST_READY_COUNT_MISMATCH" in mismatched_gate["reason_codes"]


def test_six_agent_rejects_ready_workers_six_as_specialist_count() -> None:
    evidence = valid_worker_evidence("six_agent")
    evidence["specialist_ready_workers"] = 6

    gate = gate_worker_execution_evidence(
        evidence,
        arm_id="six_agent",
        scenario_id="happy_path",
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )

    assert gate["status"] == "BLOCKED"
    assert "SPECIALIST_READY_COUNT_MISMATCH" in gate["reason_codes"]


def test_six_agent_requires_running_leader_separately_from_specialists() -> None:
    evidence = valid_worker_evidence("six_agent")
    evidence["leader_phase"] = "Stopped"

    gate = gate_worker_execution_evidence(
        evidence,
        arm_id="six_agent",
        scenario_id="happy_path",
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )

    assert gate["status"] == "BLOCKED"
    assert "LEADER_NOT_RUNNING" in gate["reason_codes"]


def test_single_agent_leader_only_topology_is_one_total_and_zero_specialists() -> None:
    gate = gate_worker_execution_evidence(
        valid_worker_evidence("single_agent"),
        arm_id="single_agent",
        scenario_id="happy_path",
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )

    assert gate == {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}


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
    gate = gate_worker_execution_evidence(
        valid_worker_evidence("six_agent", "human_gate_bypass"),
        arm_id="six_agent",
        scenario_id="human_gate_bypass",
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )
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
    assert report["provenance"]["fixture_manifest_sha256"] == fixture_manifest_digest()
    assert all(item["official_weight_points"] > 0 for item in report["scorecard"])
