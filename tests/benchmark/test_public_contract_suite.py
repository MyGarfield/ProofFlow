import json
import platform
import shutil
from importlib import metadata
from pathlib import Path

from pytest import CaptureFixture, MonkeyPatch

from benchmarks.run_contract_suite import main
from benchmarks.suite import (
    ROOT,
    _mismatches,
    _provenance,
    _runtime_image_provenance,
    compute_report_hash,
    load_suite_manifest,
    render_report,
    run_suite,
)

EXPECTED_SCENARIOS = {
    "approval_toctou",
    "cross_tenant_calculation",
    "evidence_tamper",
    "happy_path",
    "missing_parameter",
    "package_tamper",
    "parser_field_allowlist",
    "resealed_value_tamper",
    "rule_scope_and_time",
    "seal_tamper",
    "unresolved_calculation_boundary",
}


def test_manifest_declares_every_required_public_scenario() -> None:
    manifest = load_suite_manifest()

    assert {scenario["id"] for scenario in manifest["scenarios"]} == EXPECTED_SCENARIOS
    assert manifest["data_classification"] == "PUBLIC_SYNTHETIC"
    assert manifest["comparison_policy"] == "STRICT_RECURSIVE_CLOSED_SET"
    assert not manifest["legal_accuracy_measured"]
    assert not manifest["performance_measured"]


def test_strict_comparison_rejects_missing_changed_and_additional_output() -> None:
    expected = {"decision": {"blocked": True}, "issue_codes": ["EXPECTED"]}

    assert _mismatches(expected, expected) == []
    assert _mismatches(expected, {**expected, "external_action": "SENT"}) == [
        "$.external_action:unexpected"
    ]
    assert _mismatches(expected, {"decision": {}, "issue_codes": ["EXPECTED"]}) == [
        "$.decision.blocked:missing"
    ]
    assert _mismatches(expected, {"decision": {"blocked": False}, "issue_codes": ["EXPECTED"]}) == [
        "$.decision.blocked:value_mismatch"
    ]


def test_public_suite_satisfies_all_frozen_contracts(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.delenv("PROOFFLOW_RUNTIME_IMAGE_DIGEST", raising=False)
    report = run_suite(tmp_path)

    assert report["summary"]["all_contracts_satisfied"]
    assert report["summary"]["total"] == 11
    assert report["summary"]["passed"] == 11
    assert report["summary"]["failed"] == 0
    assert report["summary"]["contract_pass_fraction"] == "11/11"
    assert all(result["passed"] for result in report["results"])
    assert report["report_hash"].startswith("sha256:")
    assert report["report_hash_semantics"] == {
        "algorithm": "SHA-256",
        "authenticity_verified": False,
        "digital_signature_present": False,
        "kind": "UNSIGNED_CONTENT_DIGEST",
    }
    assert report["report_hash"] == compute_report_hash(report)

    parser_result = next(
        result for result in report["results"] if result["id"] == "parser_field_allowlist"
    )
    assert (
        parser_result["coverage_boundary"] == "PARSER_FIELD_ALLOWLIST_ONLY_NO_LLM_MCP_OR_AGENTTEAMS"
    )


def test_provenance_binds_inputs_without_absolute_user_paths(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("PROOFFLOW_RUNTIME_IMAGE_DIGEST", raising=False)
    provenance = _provenance()

    assert provenance["uv_lock"]["sha256"].startswith("sha256:")
    assert provenance["scenario_manifest"]["sha256"].startswith("sha256:")
    assert provenance["fixtures"]["file_count"] >= 4
    assert provenance["rules"]["file_count"] >= 1
    assert provenance["git"]["head_tree"]
    assert provenance["python"]["implementation"] == "cpython"
    assert provenance["python"]["version"] == platform.python_version()
    assert not provenance["git"]["dirty_paths_disclosed"]
    assert provenance["runtime_image"] == {
        "digest": None,
        "source": None,
        "verified": False,
    }
    assert not provenance["hashes_are_digital_signatures"]
    assert str(ROOT) not in json.dumps(provenance, ensure_ascii=False, sort_keys=True)


def test_dependency_provenance_matches_installed_versions_and_uv_lock() -> None:
    dependencies = _provenance()["dependencies"]
    observed = {item["name"]: item for item in dependencies["distributions"]}

    assert dependencies["source"] == "LOCAL_INSTALLED_DISTRIBUTION_METADATA"
    assert dependencies["uv_lock_parsed"]
    assert dependencies["all_installed_versions_match_uv_lock"]
    assert not dependencies["installed_metadata_is_signed"]
    assert set(observed) == {
        "annotated-types",
        "pydantic",
        "pydantic-core",
        "typing-extensions",
        "typing-inspection",
    }
    for name, item in observed.items():
        installed_version = metadata.version(name)
        assert item["installed_version"] == installed_version
        assert item["locked_versions"] == [installed_version]
        assert item["matches_uv_lock"]


def test_fixture_mutation_changes_provenance_and_derived_report_hash(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.delenv("PROOFFLOW_RUNTIME_IMAGE_DIGEST", raising=False)
    snapshot_root = tmp_path / "provenance-inputs"
    shutil.copytree(
        ROOT / "benchmarks",
        snapshot_root / "benchmarks",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(ROOT / "examples/cases", snapshot_root / "examples/cases")
    shutil.copytree(ROOT / "data/rules", snapshot_root / "data/rules")
    shutil.copy2(ROOT / "uv.lock", snapshot_root / "uv.lock")

    before = _provenance(root=snapshot_root)
    fixture = snapshot_root / "examples/cases/happy_path/contract.json"
    fixture.write_bytes(fixture.read_bytes() + b"\n")
    after = _provenance(root=snapshot_root)

    assert before["fixtures"]["bundle_sha256"] != after["fixtures"]["bundle_sha256"]
    assert before["scenario_manifest"] == after["scenario_manifest"]
    assert before["uv_lock"] == after["uv_lock"]

    report = run_suite(tmp_path / "benchmark-run")
    before_hash = compute_report_hash({**report, "provenance": before})
    after_hash = compute_report_hash({**report, "provenance": after})
    assert before_hash != after_hash


def test_runtime_image_environment_value_remains_unverified(monkeypatch: MonkeyPatch) -> None:
    digest = "sha256:" + "a" * 64
    monkeypatch.setenv("PROOFFLOW_RUNTIME_IMAGE_DIGEST", digest)

    assert _runtime_image_provenance() == {
        "digest": digest,
        "source": "UNVERIFIED_ENVIRONMENT_ASSERTION",
        "verified": False,
    }


def test_report_is_byte_for_byte_deterministic(tmp_path: Path) -> None:
    first = run_suite(tmp_path / "first")
    second = run_suite(tmp_path / "second")

    assert render_report(first) == render_report(second)


def test_cli_emits_and_writes_machine_readable_json(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    output_path = tmp_path / "reports/public-contracts.json"

    exit_code = main(["--output", str(output_path)])
    captured = capsys.readouterr()
    stdout_report = json.loads(captured.out)
    file_report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert stdout_report == file_report
    assert stdout_report["schema_version"] == "proofflow.benchmark-report/v1"
    assert stdout_report["measurement_scope"] == "QUALITY_AND_SAFETY_CONTRACTS_ONLY"
    assert not stdout_report["legal_accuracy_measured"]
