"""P0 corpus for malformed and semantically forged Worker evidence."""

from copy import deepcopy

import pytest

from benchmarks.evaluation.suite import gate_worker_execution_evidence
from tests.benchmark.test_evaluation_contracts import TEST_REPOSITORY_COMMIT, valid_worker_evidence


def _gate(evidence: object, scenario_id: str = "happy_path") -> dict:
    return gate_worker_execution_evidence(
        evidence,
        arm_id="six_agent",
        scenario_id=scenario_id,
        expected_repository_commit=TEST_REPOSITORY_COMMIT,
    )


@pytest.mark.parametrize(
    ("attack", "mutate"),
    [
        ("missing_schema_version", lambda value: value.pop("schema_version")),
        ("missing_rule_catalog_digest", lambda value: value.pop("rule_catalog_sha256")),
        ("missing_formula_version", lambda value: value.pop("formula_version")),
        (
            "invalid_digest",
            lambda value: value.__setitem__("fixture_manifest_sha256", "sha256:not-a-digest"),
        ),
        (
            "invalid_commit",
            lambda value: value["provenance"].__setitem__("repository_commit", "not-a-commit"),
        ),
        ("empty_mcp_receipts", lambda value: value.__setitem__("worker_mcp_call_receipts", [])),
        ("empty_skill_receipts", lambda value: value.__setitem__("skill_consumption_receipts", [])),
        ("missing_worker_session_receipts", lambda value: value.pop("worker_session_receipts")),
        ("missing_llm_inference_receipts", lambda value: value.pop("llm_inference_receipts")),
        ("incomplete_human_receipt", lambda value: value.__setitem__("human_gate_receipt", {})),
        (
            "arbitrary_specialist_names",
            lambda value: value["worker_roster"].__setitem__(
                "specialist_worker_names", ["forged-specialist-1"]
            ),
        ),
    ],
)
def test_malformed_six_agent_evidence_is_blocked_before_semantic_fallback(
    attack: str, mutate
) -> None:
    evidence = deepcopy(valid_worker_evidence("six_agent"))
    mutate(evidence)

    gate = _gate(evidence)

    assert gate["status"] == "BLOCKED", attack
    assert gate["score_status"] == "UNKNOWN", attack
    assert gate["reason_codes"] == ["EVIDENCE_SCHEMA_INVALID"], attack


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("specialist_ready_workers", 6, "SPECIALIST_READY_COUNT_MISMATCH"),
        ("leader_phase", "Stopped", "LEADER_NOT_RUNNING"),
    ],
)
def test_valid_shape_with_wrong_agentteams_topology_is_blocked(
    field: str, value: object, reason: str
) -> None:
    evidence = deepcopy(valid_worker_evidence("six_agent"))
    evidence[field] = value

    gate = _gate(evidence)

    assert gate["status"] == "BLOCKED"
    assert gate["score_status"] == "UNKNOWN"
    assert reason in gate["reason_codes"]


def test_stopped_specialist_is_not_ready() -> None:
    evidence = deepcopy(valid_worker_evidence("six_agent"))
    evidence["specialist_phases"]["rule-agent"] = "Stopped"

    gate = _gate(evidence)

    assert gate["status"] == "BLOCKED"
    assert "SPECIALIST_NOT_RUNNING" in gate["reason_codes"]


def test_early_block_without_human_approval_receipt_is_valid_capture() -> None:
    gate = _gate(valid_worker_evidence("six_agent", "missing_parameter"), "missing_parameter")

    assert gate == {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}


def test_trace_gap_separates_harness_capture_from_sut_trace_outcome() -> None:
    gate = _gate(valid_worker_evidence("six_agent", "trace_gap"), "trace_gap")

    assert gate == {"status": "READY", "score_status": "ELIGIBLE", "reason_codes": []}


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda value: value.__setitem__("fixture_manifest_sha256", "sha256:" + "9" * 64),
            "FIXTURE_MANIFEST_DIGEST_MISMATCH",
        ),
        (
            lambda value: value.__setitem__("scenario_manifest_sha256", "sha256:" + "9" * 64),
            "SCENARIO_MANIFEST_DIGEST_MISMATCH",
        ),
        (
            lambda value: value.__setitem__("rule_catalog_sha256", "sha256:" + "9" * 64),
            "RULE_CATALOG_DIGEST_MISMATCH",
        ),
        (
            lambda value: value.__setitem__("formula_version", "forged-formula-v9"),
            "FORMULA_VERSION_MISMATCH",
        ),
        (
            lambda value: value["provenance"].__setitem__("repository_commit", "b" * 40),
            "SOURCE_COMMIT_MISMATCH",
        ),
        (
            lambda value: value["worker_mcp_call_receipts"][0].__setitem__("run_id", "forged-run"),
            "RECEIPT_RUN_ID_MISMATCH",
        ),
        (
            lambda value: value["skill_coverage"].__setitem__("case-manager", ["evidence_ingest"]),
            "SKILL_COVERAGE_MISMATCH",
        ),
    ],
)
def test_cross_field_provenance_and_receipt_bindings_are_fail_closed(mutate, reason: str) -> None:
    evidence = deepcopy(valid_worker_evidence("six_agent"))
    mutate(evidence)

    gate = _gate(evidence)

    assert gate["status"] == "BLOCKED"
    assert gate["score_status"] == "UNKNOWN"
    assert reason in gate["reason_codes"]


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda value: value.__setitem__(
                "worker_mcp_call_receipts", value["worker_mcp_call_receipts"][:1]
            ),
            "MCP_RECEIPT_COVERAGE_MISMATCH",
        ),
        (
            lambda value: [
                item.__setitem__("worker_name", "case-manager")
                for item in (*value["task_event_receipts"], *value["matrix_event_receipts"])
            ],
            "TASK_EVENT_PARTICIPANT_SET_MISMATCH",
        ),
        (
            lambda value: value["skill_consumption_receipts"][0].__setitem__(
                "skill_sha256", "sha256:" + "8" * 64
            ),
            "SKILL_DIGEST_MISMATCH",
        ),
        (
            lambda value: value["provenance"].__setitem__("agentteams_version", "v9.9.9"),
            "AGENTTEAMS_VERSION_MISMATCH",
        ),
        (
            lambda value: value["provenance"].__setitem__("agentteams_commit", "c" * 40),
            "AGENTTEAMS_COMMIT_MISMATCH",
        ),
    ],
)
def test_worker_evidence_coverage_and_pinned_provenance_are_fail_closed(
    mutate, reason: str
) -> None:
    evidence = deepcopy(valid_worker_evidence("six_agent"))
    mutate(evidence)

    gate = _gate(evidence)

    assert gate["status"] == "BLOCKED"
    assert gate["score_status"] == "UNKNOWN"
    assert reason in gate["reason_codes"]


def test_matrix_roster_cannot_be_forged_by_reusing_the_leader() -> None:
    evidence = deepcopy(valid_worker_evidence("six_agent"))
    for receipt in evidence["matrix_event_receipts"]:
        receipt["worker_name"] = "case-manager"

    gate = _gate(evidence)

    assert gate["status"] == "BLOCKED"
    assert "MATRIX_EVENT_PARTICIPANT_SET_MISMATCH" in gate["reason_codes"]


def test_bare_execution_booleans_without_session_or_llm_receipts_are_schema_blocked() -> None:
    evidence = deepcopy(valid_worker_evidence("six_agent"))
    evidence.pop("worker_session_receipts")
    evidence.pop("llm_inference_receipts")

    gate = _gate(evidence)

    assert gate == {
        "status": "BLOCKED",
        "score_status": "UNKNOWN",
        "reason_codes": ["EVIDENCE_SCHEMA_INVALID"],
    }


def test_duplicate_keys_and_nan_are_rejected_by_strict_json_entrypoint() -> None:
    duplicate = '{"schema_version":"proofflow.worker-run-evidence/v2","schema_version":"forged"}'
    nan = '{"schema_version":"proofflow.worker-run-evidence/v2","value":NaN}'

    assert _gate(duplicate)["reason_codes"] == ["EVIDENCE_JSON_INVALID"]
    assert _gate(nan)["reason_codes"] == ["EVIDENCE_JSON_INVALID"]
