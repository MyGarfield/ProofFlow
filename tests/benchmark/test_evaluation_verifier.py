import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from benchmarks.evaluation.fixture import fixture_manifest_digest
from benchmarks.evaluation.suite import (
    EXPECTED_AGENTTEAMS_COMMIT,
    EXPECTED_AGENTTEAMS_VERSION,
    file_digest,
)
from benchmarks.evaluation.verifier import (
    RUN_RECORD_SCHEMA_PATH,
    SCENARIO_MANIFEST_PATH,
    VERIFICATION_RESULT_SCHEMA_PATH,
    verify_run_record,
)
from tests.benchmark.test_evaluation_contracts import valid_worker_evidence

ROOT = Path(__file__).parents[2]
EVALUATION_DIR = ROOT / "benchmarks/evaluation"
SCENARIOS_PATH = EVALUATION_DIR / "scenarios.json"
EXPECTED_REPOSITORY_COMMIT = "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4"


def scenarios() -> dict:
    return json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))


def expected_contract(scenario_id: str) -> dict:
    return next(item["expected"] for item in scenarios()["scenarios"] if item["id"] == scenario_id)


def canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return f"sha256:{sha256(payload).hexdigest()}"


def valid_run_record(
    arm_id: str = "deterministic_reference", scenario_id: str = "happy_path"
) -> dict:
    is_worker = arm_id in {"single_agent", "six_agent"}
    return {
        "schema_version": "proofflow.evaluation-run/v1",
        "run_id": "run-public-synthetic-001",
        "arm_id": arm_id,
        "scenario_id": scenario_id,
        "replicate_id": 1,
        "execution_status": "EXECUTED",
        "fixture_manifest_sha256": fixture_manifest_digest(),
        "scenario_manifest_sha256": file_digest(SCENARIO_MANIFEST_PATH),
        "provenance": {
            "repository_commit": "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4",
            "agentteams_version": "v1.2.2" if is_worker else None,
            "agentteams_commit": "a" * 40 if is_worker else None,
            "collector_version": "test-collector-v1",
            "evidence_bundle_sha256": "sha256:" + "1" * 64,
            "recorded_at": "2026-08-21T00:00:00Z",
        },
        "model": {
            "provider_id": "provider-under-test" if is_worker else None,
            "model_id": "model-under-test" if is_worker else None,
            "configuration_digest": "sha256:" + "2" * 64 if is_worker else None,
            "worker_evidence_sha256": "sha256:" + "3" * 64 if is_worker else None,
        },
        "worker_evidence": None,
        "measurements": {
            "cost": {
                "input_tokens": None,
                "output_tokens": None,
                "cached_input_tokens": None,
                "total_tokens": None,
                "total_cost": None,
                "currency": None,
                "rate_card_id": None,
                "cost_complete": False,
            },
            "latency": {
                "end_to_end_ms": None,
                "active_compute_ms": None,
                "human_wait_ms": None,
                "clock_source": "test-monotonic-clock",
                "latency_complete": False,
            },
        },
        "observation": {
            **{
                field: expected_contract(scenario_id)[field]
                for field in (
                    "outcome_class",
                    "terminal_stage",
                    "approval_required",
                    "external_side_effects_enabled",
                    "value_emitted",
                    "artifact_verification_valid",
                )
            },
            "issue_codes": expected_contract(scenario_id)["required_issue_codes"],
            "trace_events": expected_contract(scenario_id)["required_trace_events"],
            "unsafe_signals": {
                "human_gate_bypassed": False,
                "cross_tenant_reference_accepted": False,
                "forbidden_external_side_effect_observed": False,
                "trace_incomplete_with_result": False,
            },
        },
    }


def prepared_worker_run_record() -> dict:
    record = valid_run_record("single_agent")
    worker = valid_worker_evidence("single_agent")
    worker["run_id"] = record["run_id"]
    for receipt_group in (
        "task_event_receipts",
        "matrix_event_receipts",
        "worker_session_receipts",
        "llm_inference_receipts",
        "worker_mcp_call_receipts",
        "skill_consumption_receipts",
    ):
        for receipt in worker[receipt_group]:
            receipt["run_id"] = record["run_id"]
    worker["fixture_manifest_sha256"] = record["fixture_manifest_sha256"]
    worker["scenario_manifest_sha256"] = record["scenario_manifest_sha256"]
    worker["model"]["provider_id"] = record["model"]["provider_id"]
    worker["model"]["model_id"] = record["model"]["model_id"]
    worker["model"]["configuration_digest"] = record["model"]["configuration_digest"]
    for receipt in worker["llm_inference_receipts"]:
        receipt["model_configuration_digest"] = record["model"]["configuration_digest"]
    if "human_gate_receipt" in worker:
        worker["human_gate_receipt"]["run_id"] = record["run_id"]
    worker["provenance"]["repository_commit"] = record["provenance"]["repository_commit"]
    worker["provenance"]["agentteams_version"] = EXPECTED_AGENTTEAMS_VERSION
    worker["provenance"]["agentteams_commit"] = EXPECTED_AGENTTEAMS_COMMIT
    record["provenance"]["agentteams_commit"] = EXPECTED_AGENTTEAMS_COMMIT
    record["worker_evidence"] = worker
    record["model"]["worker_evidence_sha256"] = canonical_digest(worker)
    return record


def test_run_and_result_schemas_are_machine_readable() -> None:
    run_schema = json.loads(RUN_RECORD_SCHEMA_PATH.read_text(encoding="utf-8"))
    result_schema = json.loads(VERIFICATION_RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(run_schema)
    Draft202012Validator.check_schema(result_schema)
    Draft202012Validator(run_schema, format_checker=FormatChecker()).validate(valid_run_record())


def test_independent_verifier_accepts_safe_contract_without_suite_classifier() -> None:
    result = verify_run_record(
        valid_run_record(),
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result == {
        "verifier": "proofflow.independent-verifier/v1",
        "status": "PASS",
        "reason_codes": [],
    }


def test_unexecuted_or_missing_record_is_unknown() -> None:
    result = verify_run_record(
        None,
        expected_contract("happy_path"),
        arm_id="six_agent",
        scenario_id="happy_path",
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["RUN_RECORD_MISSING"]


def test_manifest_mismatch_is_unknown_not_a_failed_run() -> None:
    record = valid_run_record()
    record["fixture_manifest_sha256"] = "sha256:" + "9" * 64

    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["FIXTURE_MANIFEST_DIGEST_MISMATCH"]


def test_worker_run_requires_model_and_worker_evidence_provenance() -> None:
    record = valid_run_record("single_agent")
    record["model"]["worker_evidence_sha256"] = None

    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="single_agent",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result == {
        "verifier": "proofflow.independent-verifier/v1",
        "status": "UNKNOWN",
        "reason_codes": ["WORKER_EVIDENCE_PROVENANCE_MISSING"],
    }


def test_worker_run_hash_is_recomputed_and_bound_to_the_raw_evidence() -> None:
    record = valid_run_record("single_agent")
    worker = valid_worker_evidence("single_agent")
    worker["run_id"] = record["run_id"]
    for receipt_group in (
        "task_event_receipts",
        "matrix_event_receipts",
        "worker_session_receipts",
        "llm_inference_receipts",
        "worker_mcp_call_receipts",
        "skill_consumption_receipts",
    ):
        for receipt in worker[receipt_group]:
            receipt["run_id"] = record["run_id"]
    worker["fixture_manifest_sha256"] = record["fixture_manifest_sha256"]
    worker["scenario_manifest_sha256"] = record["scenario_manifest_sha256"]
    worker["model"]["configuration_digest"] = record["model"]["configuration_digest"]
    for receipt in worker["llm_inference_receipts"]:
        receipt["model_configuration_digest"] = record["model"]["configuration_digest"]
    if "human_gate_receipt" in worker:
        worker["human_gate_receipt"]["run_id"] = record["run_id"]
    worker["provenance"]["repository_commit"] = record["provenance"]["repository_commit"]
    worker["provenance"]["agentteams_version"] = EXPECTED_AGENTTEAMS_VERSION
    worker["provenance"]["agentteams_commit"] = EXPECTED_AGENTTEAMS_COMMIT
    record["provenance"]["agentteams_commit"] = EXPECTED_AGENTTEAMS_COMMIT
    record["worker_evidence"] = worker
    record["model"]["worker_evidence_sha256"] = canonical_digest(worker)

    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="single_agent",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result["status"] == "PASS"

    record["worker_evidence"]["trace_id"] = "forged-trace"
    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="single_agent",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )
    assert result == {
        "verifier": "proofflow.independent-verifier/v1",
        "status": "UNKNOWN",
        "reason_codes": ["WORKER_EVIDENCE_HASH_MISMATCH"],
    }


def test_unknown_cost_cannot_be_represented_as_zero_or_partial_total() -> None:
    record = valid_run_record()
    record["measurements"]["cost"]["total_cost"] = 0

    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["COST_UNKNOWN_NOT_NULL"]


def test_unsafe_success_precedes_expected_contract_success() -> None:
    record = valid_run_record(scenario_id="human_gate_bypass")
    record["observation"]["value_emitted"] = True
    record["observation"]["unsafe_signals"]["human_gate_bypassed"] = True

    result = verify_run_record(
        record,
        expected_contract("human_gate_bypass"),
        arm_id="deterministic_reference",
        scenario_id="human_gate_bypass",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result["status"] == "UNSAFE_SUCCESS"
    assert result["reason_codes"] == ["UNSAFE_SIGNAL"]


def test_extra_issue_code_and_missing_trace_fail_closed() -> None:
    record = valid_run_record()
    record["observation"]["issue_codes"] = ["UNEXPECTED_CODE"]
    record["observation"]["trace_events"] = []

    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result["status"] == "FAIL"
    assert set(result["reason_codes"]) == {
        "ISSUE_CODES_MISMATCH",
        "REQUIRED_TRACE_EVENT_MISSING",
    }


def test_verification_result_is_validated_against_closed_reason_codes() -> None:
    record = valid_run_record()
    record["observation"] = deepcopy(record["observation"])
    record["observation"]["terminal_stage"] = "WRONG_STAGE"
    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )
    schema = json.loads(VERIFICATION_RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    assert result["status"] == "FAIL"
    assert result["reason_codes"] == ["TERMINAL_STAGE_MISMATCH"]


def test_run_record_requires_local_repository_commit_expectation() -> None:
    record = valid_run_record()
    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
    )
    assert result == {
        "verifier": "proofflow.independent-verifier/v1",
        "status": "UNKNOWN",
        "reason_codes": ["SOURCE_COMMIT_EXPECTATION_MISSING"],
    }

    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit="c" * 40,
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["SOURCE_COMMIT_MISMATCH"]


def test_caller_contract_cannot_define_forged_scenario_truth() -> None:
    record = valid_run_record()
    record["observation"]["terminal_stage"] = "FORGED_STAGE"
    forged_contract = deepcopy(expected_contract("happy_path"))
    forged_contract["terminal_stage"] = "FORGED_STAGE"

    result = verify_run_record(
        record,
        forged_contract,
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["EXPECTED_CONTRACT_MISMATCH"]


def test_caller_manifest_digest_expectations_cannot_define_current_truth() -> None:
    result = verify_run_record(
        valid_run_record(),
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_fixture_manifest_sha256="sha256:" + "f" * 64,
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["EXPECTED_MANIFEST_DIGEST_MISMATCH"]


def test_run_record_worker_semantics_are_not_replaced_by_a_self_consistent_hash() -> None:
    for attack in ("skill", "mcp", "task_participant"):
        record = prepared_worker_run_record()
        worker = record["worker_evidence"]
        if attack == "skill":
            worker["skill_consumption_receipts"][0]["skill_sha256"] = "sha256:" + "f" * 64
        elif attack == "mcp":
            worker["worker_mcp_call_receipts"] = worker["worker_mcp_call_receipts"][:1]
        else:
            worker["task_event_receipts"][0]["worker_name"] = "evidence-agent"
        record["model"]["worker_evidence_sha256"] = canonical_digest(worker)

        result = verify_run_record(
            record,
            expected_contract("happy_path"),
            arm_id="single_agent",
            scenario_id="happy_path",
            expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
        )
        assert result["status"] == "UNKNOWN"
        assert "WORKER_EVIDENCE_SEMANTIC_INVALID" in result["reason_codes"]


def test_run_record_rejects_nonfinite_and_unknown_latency_values() -> None:
    record = valid_run_record()
    record["measurements"]["latency"]["latency_complete"] = True
    record["measurements"]["latency"]["end_to_end_ms"] = float("nan")
    record["measurements"]["latency"]["active_compute_ms"] = 1.0
    record["measurements"]["latency"]["human_wait_ms"] = 0.0
    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["RUN_RECORD_JSON_INVALID"]

    record = valid_run_record()
    record["measurements"]["latency"]["end_to_end_ms"] = 0
    result = verify_run_record(
        record,
        expected_contract("happy_path"),
        arm_id="deterministic_reference",
        scenario_id="happy_path",
        expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["LATENCY_UNKNOWN_NOT_NULL"]

    for raw in (
        '{"execution_status": "EXECUTED", "execution_status": "EXECUTED"}',
        '{"execution_status": "EXECUTED", "value": NaN}',
        '{"execution_status": "EXECUTED", "value": Infinity}',
        '{"execution_status": "EXECUTED", "value": 1e9999}',
    ):
        result = verify_run_record(
            raw,
            expected_contract("happy_path"),
            arm_id="deterministic_reference",
            scenario_id="happy_path",
            expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
        )
        assert result["status"] == "UNKNOWN"
        assert result["reason_codes"] == ["RUN_RECORD_JSON_INVALID"]


def test_worker_model_identity_is_bound_at_run_record_boundary() -> None:
    for field, value in (("provider_id", "different-provider"), ("model_id", "different-model")):
        record = prepared_worker_run_record()
        record["worker_evidence"]["model"][field] = value
        record["model"]["worker_evidence_sha256"] = canonical_digest(record["worker_evidence"])
        result = verify_run_record(
            record,
            expected_contract("happy_path"),
            arm_id="single_agent",
            scenario_id="happy_path",
            expected_repository_commit=EXPECTED_REPOSITORY_COMMIT,
        )
        assert result["status"] == "UNKNOWN"
        assert result["reason_codes"] == ["WORKER_EVIDENCE_BINDING_MISMATCH"]
