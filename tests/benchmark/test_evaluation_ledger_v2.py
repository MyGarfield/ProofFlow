import json
from copy import deepcopy

from jsonschema import Draft202012Validator, FormatChecker

from benchmarks.evaluation.ledger import build_run_ledger
from benchmarks.evaluation.ledger_verifier import (
    LEDGER_SCHEMA_PATH,
    REPORT_SCHEMA_PATH,
    aggregate_run_ledger,
    verify_run_ledger,
)

TEST_COMMIT = "f3dc335" + "0" * 33


def test_v2_ledger_executes_all_ten_deterministic_scenarios_and_keeps_workers_unknown(
    tmp_path,
) -> None:
    ledger = build_run_ledger(tmp_path / "runs", repository_commit=TEST_COMMIT)

    result = verify_run_ledger(ledger, expected_repository_commit=TEST_COMMIT)
    report = aggregate_run_ledger(ledger, expected_repository_commit=TEST_COMMIT)

    assert result["status"] == "VERIFIED"
    assert result["entries_verified"] == 37
    deterministic = next(
        item for item in report["arms"] if item["arm_id"] == "deterministic_reference"
    )
    single = next(item for item in report["arms"] if item["arm_id"] == "single_agent")
    six = next(item for item in report["arms"] if item["arm_id"] == "six_agent")
    assert deterministic["execution_status"] == "EXECUTED"
    assert deterministic["status_counts"] == {
        "PASS": 10,
        "FAIL": 0,
        "UNKNOWN": 0,
        "UNSAFE_SUCCESS": 0,
    }
    assert single["execution_status"] == six["execution_status"] == "NOT_EXECUTED"
    assert single["status_counts"]["UNKNOWN"] == 13
    assert six["status_counts"]["UNKNOWN"] == 14
    assert report["execution_claim"] == "DETERMINISTIC_REFERENCE_ONLY"
    assert all(item["points"] is None for item in report["scorecard"])
    assert report["ledger_sha256"].startswith("sha256:")


def test_ledger_and_mixed_report_are_draft_2020_12_documents(tmp_path) -> None:
    ledger = build_run_ledger(tmp_path / "runs", repository_commit=TEST_COMMIT)
    report = aggregate_run_ledger(ledger, expected_repository_commit=TEST_COMMIT)
    ledger_schema = json.loads(LEDGER_SCHEMA_PATH.read_text(encoding="utf-8"))
    report_schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(ledger_schema)
    Draft202012Validator.check_schema(report_schema)
    Draft202012Validator(ledger_schema, format_checker=FormatChecker()).validate(ledger)
    Draft202012Validator(report_schema, format_checker=FormatChecker()).validate(report)


def test_ledger_verifier_rejects_duplicate_pair_and_unknown_cost_as_unknown(tmp_path) -> None:
    ledger = build_run_ledger(tmp_path / "runs", repository_commit=TEST_COMMIT)
    attacked = deepcopy(ledger)
    duplicate = deepcopy(attacked["entries"][0])
    duplicate["entry_id"] = "forged-distinct-entry-id"
    attacked["entries"].append(duplicate)
    assert (
        "LEDGER_ENTRY_KEY_NOT_UNIQUE"
        in verify_run_ledger(attacked, expected_repository_commit=TEST_COMMIT)["reason_codes"]
    )

    attacked = deepcopy(ledger)
    unexecuted = next(
        item for item in attacked["entries"] if item["execution_status"] == "NOT_EXECUTED"
    )
    unexecuted["cost"]["total_cost"] = 0
    result = verify_run_ledger(attacked, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "COST_UNKNOWN_SEMANTICS_INVALID" in result["reason_codes"]

    attacked = deepcopy(ledger)
    unexecuted = next(
        item for item in attacked["entries"] if item["execution_status"] == "NOT_EXECUTED"
    )
    unexecuted["worker_evidence_sha256"] = "sha256:" + "8" * 64
    result = verify_run_ledger(attacked, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "UNEXECUTED_WORKER_EVIDENCE_NOT_NULL" in result["reason_codes"]


def test_ledger_verifier_rejects_coverage_deletion_reorder_and_hash_attacks(tmp_path) -> None:
    ledger = build_run_ledger(tmp_path / "runs", repository_commit=TEST_COMMIT)

    deleted_group = deepcopy(ledger)
    deleted_group["entries"] = [
        item for item in deleted_group["entries"] if item["scenario_id"] != "happy_path"
    ]
    result = verify_run_ledger(deleted_group, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "LEDGER_RUN_PLAN_COVERAGE_MISSING" in result["reason_codes"]

    deleted_entry = deepcopy(ledger)
    deleted_entry["entries"].pop()
    result = verify_run_ledger(deleted_entry, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "LEDGER_RUN_PLAN_COVERAGE_MISSING" in result["reason_codes"]

    reordered = deepcopy(ledger)
    reordered["entries"][0], reordered["entries"][1] = (
        reordered["entries"][1],
        reordered["entries"][0],
    )
    result = verify_run_ledger(reordered, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "LEDGER_PREVIOUS_HASH_MISMATCH" in result["reason_codes"]

    previous_hash_attack = deepcopy(ledger)
    previous_hash_attack["entries"][1]["previous_entry_sha256"] = "sha256:" + "9" * 64
    result = verify_run_ledger(previous_hash_attack, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "LEDGER_PREVIOUS_HASH_MISMATCH" in result["reason_codes"]

    root_attack = deepcopy(ledger)
    root_attack["ledger_root_sha256"] = "sha256:" + "9" * 64
    result = verify_run_ledger(root_attack, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "LEDGER_ROOT_HASH_MISMATCH" in result["reason_codes"]


def test_ledger_plan_and_aggregation_keep_attempt_as_pairing_dimension(tmp_path) -> None:
    ledger = build_run_ledger(tmp_path / "runs", repository_commit=TEST_COMMIT, attempts=(1, 2))

    result = verify_run_ledger(ledger, expected_repository_commit=TEST_COMMIT)
    report = aggregate_run_ledger(ledger, expected_repository_commit=TEST_COMMIT)

    assert result["status"] == "VERIFIED"
    assert result["entries_verified"] == 74
    assert report["pairing_summary"]["unit"] == "scenario_id+replicate_id+attempt"
    assert report["pairing_summary"]["incomplete_pairs"] == 28
