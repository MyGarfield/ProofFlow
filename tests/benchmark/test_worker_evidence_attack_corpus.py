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


def test_duplicate_keys_and_nan_are_rejected_by_strict_json_entrypoint() -> None:
    duplicate = '{"schema_version":"proofflow.worker-run-evidence/v2","schema_version":"forged"}'
    nan = '{"schema_version":"proofflow.worker-run-evidence/v2","value":NaN}'

    assert _gate(duplicate)["reason_codes"] == ["EVIDENCE_JSON_INVALID"]
    assert _gate(nan)["reason_codes"] == ["EVIDENCE_JSON_INVALID"]
