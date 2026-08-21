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
