import json
from copy import deepcopy
from hashlib import sha256

from jsonschema import Draft202012Validator, FormatChecker

from benchmarks.evaluation.ledger import build_run_ledger
from benchmarks.evaluation.ledger_verifier import (
    LEDGER_SCHEMA_PATH,
    REPORT_SCHEMA_PATH,
    aggregate_run_ledger,
    verify_run_ledger,
)
from benchmarks.evaluation.suite import EXPECTED_AGENTTEAMS_COMMIT, EXPECTED_AGENTTEAMS_VERSION
from tests.benchmark.test_evaluation_contracts import valid_worker_evidence

TEST_COMMIT = "f3dc335" + "0" * 33


def canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return f"sha256:{sha256(payload).hexdigest()}"


def reseal_ledger(ledger: dict) -> None:
    previous = "sha256:" + "0" * 64
    for index, entry in enumerate(ledger["entries"], start=1):
        entry["entry_index"] = index
        entry["previous_entry_sha256"] = previous
        entry["entry_sha256"] = canonical_digest(
            {key: value for key, value in entry.items() if key != "entry_sha256"}
        )
        previous = entry["entry_sha256"]
    ledger["ledger_root_sha256"] = canonical_digest(
        {key: value for key, value in ledger.items() if key != "ledger_root_sha256"}
    )


def ledger_with_executed_worker(tmp_path) -> dict:
    ledger = build_run_ledger(tmp_path / "runs", repository_commit=TEST_COMMIT)
    entry = next(
        item
        for item in ledger["entries"]
        if item["arm_id"] == "single_agent" and item["scenario_id"] == "happy_path"
    )
    worker = valid_worker_evidence("single_agent")
    worker["run_id"] = entry["run_id"]
    for receipt_group in (
        "task_event_receipts",
        "matrix_event_receipts",
        "worker_session_receipts",
        "llm_inference_receipts",
        "worker_mcp_call_receipts",
        "skill_consumption_receipts",
    ):
        for receipt in worker[receipt_group]:
            receipt["run_id"] = entry["run_id"]
    if "human_gate_receipt" in worker:
        worker["human_gate_receipt"]["run_id"] = entry["run_id"]
    worker["fixture_manifest_sha256"] = entry["fixture_manifest_sha256"]
    worker["scenario_manifest_sha256"] = entry["scenario_manifest_sha256"]
    worker["provenance"]["repository_commit"] = TEST_COMMIT
    worker["provenance"]["agentteams_version"] = EXPECTED_AGENTTEAMS_VERSION
    worker["provenance"]["agentteams_commit"] = EXPECTED_AGENTTEAMS_COMMIT
    entry["model_provider_id"] = worker["model"]["provider_id"]
    entry["model_id"] = worker["model"]["model_id"]
    entry["model_configuration_digest"] = worker["model"]["configuration_digest"]
    for receipt in worker["llm_inference_receipts"]:
        receipt["model_configuration_digest"] = entry["model_configuration_digest"]
    entry["agentteams_version"] = EXPECTED_AGENTTEAMS_VERSION
    entry["agentteams_commit"] = EXPECTED_AGENTTEAMS_COMMIT
    entry["worker_evidence"] = worker
    entry["worker_evidence_sha256"] = canonical_digest(worker)
    entry["execution_status"] = "EXECUTED"
    reference_result = next(
        item["result"]
        for item in ledger["entries"]
        if item["arm_id"] == "deterministic_reference" and item["scenario_id"] == "happy_path"
    )
    entry["result"] = deepcopy(reference_result)
    entry["status"] = "PASS"
    entry["issue_codes"] = []
    reseal_ledger(ledger)
    return ledger


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


def test_ledger_worker_entry_reuses_full_semantic_gate(tmp_path) -> None:
    ledger = ledger_with_executed_worker(tmp_path)
    result = verify_run_ledger(ledger, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "VERIFIED"
    assert result["entries_verified"] == 37

    for attack in ("skill", "mcp", "task_participant"):
        attacked = deepcopy(ledger)
        entry = next(
            item
            for item in attacked["entries"]
            if item["arm_id"] == "single_agent" and item["scenario_id"] == "happy_path"
        )
        worker = entry["worker_evidence"]
        if attack == "skill":
            worker["skill_consumption_receipts"][0]["skill_sha256"] = "sha256:" + "f" * 64
        elif attack == "mcp":
            worker["worker_mcp_call_receipts"] = worker["worker_mcp_call_receipts"][:1]
        else:
            worker["task_event_receipts"][0]["worker_name"] = "evidence-agent"
        entry["worker_evidence_sha256"] = canonical_digest(worker)
        reseal_ledger(attacked)
        result = verify_run_ledger(attacked, expected_repository_commit=TEST_COMMIT)
        assert result["status"] == "UNKNOWN"
        assert "WORKER_EVIDENCE_SEMANTIC_INVALID" in result["reason_codes"]


def test_ledger_worker_entry_binds_manifest_model_and_agentteams_provenance(tmp_path) -> None:
    ledger = ledger_with_executed_worker(tmp_path)
    entry = next(
        item
        for item in ledger["entries"]
        if item["arm_id"] == "single_agent" and item["scenario_id"] == "happy_path"
    )

    attacked = deepcopy(ledger)
    attacked_entry = next(
        item
        for item in attacked["entries"]
        if item["arm_id"] == "single_agent" and item["scenario_id"] == "happy_path"
    )
    attacked_entry["worker_evidence"]["fixture_manifest_sha256"] = "sha256:" + "9" * 64
    attacked_entry["worker_evidence_sha256"] = canonical_digest(attacked_entry["worker_evidence"])
    reseal_ledger(attacked)
    result = verify_run_ledger(attacked, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "WORKER_EVIDENCE_BINDING_MISMATCH" in result["reason_codes"]

    attacked = deepcopy(ledger)
    attacked_entry = next(
        item
        for item in attacked["entries"]
        if item["arm_id"] == "single_agent" and item["scenario_id"] == "happy_path"
    )
    attacked_entry["agentteams_commit"] = "b" * 40
    attacked_entry["worker_evidence"]["provenance"]["agentteams_commit"] = "b" * 40
    attacked_entry["worker_evidence_sha256"] = canonical_digest(attacked_entry["worker_evidence"])
    reseal_ledger(attacked)
    result = verify_run_ledger(attacked, expected_repository_commit=TEST_COMMIT)
    assert result["status"] == "UNKNOWN"
    assert "AGENTTEAMS_COMMIT_MISMATCH" in result["reason_codes"]
    assert "WORKER_EVIDENCE_SEMANTIC_INVALID" in result["reason_codes"]

    assert entry["model_provider_id"] == entry["worker_evidence"]["model"]["provider_id"]
