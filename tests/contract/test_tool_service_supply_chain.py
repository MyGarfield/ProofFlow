import importlib.util
import json
import shutil
import subprocess
import warnings
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]
EVIDENCE = ROOT / "deploy/tool-service/evidence"
VALIDATOR_PATH = ROOT / "deploy/tool-service/scripts/validate_supply_chain_evidence.py"
COLLECTOR_PATH = ROOT / "deploy/tool-service/scripts/collect_supply_chain_evidence.py"
REPORT_NAME = "supply-chain-evidence.json"
REPOSITORY_URL = "https://github.com/MyGarfield/ProofFlow"
BASE_NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def test_tool_service_build_context_is_minimal_and_excludes_generated_bytecode() -> None:
    dockerignore = set((ROOT / ".dockerignore").read_text().splitlines())
    assert {
        "demo",
        "tests",
        "benchmarks",
        "docs",
        "examples",
        "schemas",
        "specs",
        "submission/private",
        "**/__pycache__/",
        "**/*.py[cod]",
    } <= dockerignore

    dockerfile = (ROOT / "deploy/tool-service/Dockerfile").read_text()
    copy_instructions = [line for line in dockerfile.splitlines() if line.startswith("COPY ")]
    assert copy_instructions == [
        "COPY deploy/tool-service/requirements.lock /tmp/requirements.lock",
        "COPY src/ /app/src/",
        "COPY data/rules/ /app/data/rules/",
        "COPY LICENSE NOTICE /usr/share/doc/proofflow/",
        "COPY deploy/tool-service/THIRD_PARTY_NOTICES.md /usr/share/doc/proofflow/",
    ]


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("supply_chain_validator", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_collector() -> ModuleType:
    spec = importlib.util.spec_from_file_location("supply_chain_collector", COLLECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text())
    assert isinstance(document, dict)
    return document


def copy_evidence(tmp_path: Path) -> Path:
    destination = tmp_path / "evidence"
    shutil.copytree(EVIDENCE, destination)
    return destination


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def refresh_artifact_record(report: dict[str, Any], evidence: Path, filename: str) -> None:
    payload = (evidence / filename).read_bytes()
    record = next(item for item in report["artifacts"] if item["path"] == filename)
    record["bytes"] = len(payload)
    record["sha256"] = f"sha256:{sha256(payload).hexdigest()}"


def git_value(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def rebind_v1p2(report: dict[str, Any], validator: ModuleType) -> None:
    report["raw_artifact_set"] = validator._expected_raw_artifact_set(report)
    identifier = validator.release_binding_sha256(report)
    report["evidence_set_id"] = identifier
    report["release_binding"] = {
        "algorithm": validator.RELEASE_BINDING_ALGORITHM,
        "bound_fields": list(validator.RELEASE_BINDING_FIELDS),
        "evidence_set_id": identifier,
    }


def pin_external_release_artifacts(policy: dict[str, Any], report: dict[str, Any]) -> None:
    policy["expected_raw_artifacts"] = {
        item["path"]: {
            "media_type": item["media_type"],
            "sha256": item["sha256"],
            "bytes": item["bytes"],
        }
        for item in report["raw_artifact_set"]
    }
    policy["expected_database"] = deepcopy(report["vulnerability_database"])
    policy["expected_evidence_set_id"] = report["evidence_set_id"]


def replace_trivy_vulnerabilities(
    validator: ModuleType,
    evidence: Path,
    report: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
) -> None:
    trivy_path = evidence / "vulnerabilities.trivy.json"
    trivy = load_json(trivy_path)
    trivy["Results"][0]["Vulnerabilities"] = vulnerabilities
    write_json(trivy_path, trivy)
    counts, targets, findings = validator._trivy_summary(trivy)
    total = sum(counts.values())
    report["summary"].update(
        {
            "vulnerability_records": counts,
            "total_vulnerability_records": total,
            "findings_by_target": targets,
            "high_or_critical_findings": findings,
            "verdict": (
                "HIGH_OR_CRITICAL_FOUND"
                if counts["HIGH"] or counts["CRITICAL"]
                else "NO_HIGH_OR_CRITICAL_FOUND"
            ),
        }
    )
    record = next(
        item for item in report["artifacts"] if item["path"] == "vulnerabilities.trivy.json"
    )
    record["record_count"] = total
    refresh_artifact_record(report, evidence, trivy_path.name)
    rebind_v1p2(report, validator)


def make_v1p2_evidence(tmp_path: Path) -> tuple[ModuleType, Path, dict[str, Any], dict[str, Any]]:
    validator = load_validator()
    evidence = copy_evidence(tmp_path)
    report = load_json(evidence / REPORT_NAME)
    report["schema_version"] = "1.2.0"
    report["collected_at"] = BASE_NOW.isoformat().replace("+00:00", "Z")
    report["scan"] = {
        "started_at": (BASE_NOW - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "completed_at": report["collected_at"],
    }
    report["source"] = {
        "repository": REPOSITORY_URL,
        "commit_sha": git_value("rev-parse", "HEAD"),
        "tree_sha": git_value("rev-parse", "HEAD^{tree}"),
        "working_tree_clean": True,
    }
    provenance = report["build_input_provenance"]
    provenance["inputs"] = validator._expected_build_input_records()
    provenance["aggregate_sha256"] = validator._build_input_binding_sha256(provenance)
    report["vulnerability_database"].update(
        {
            "updated_at": (BASE_NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "downloaded_at": (BASE_NOW - timedelta(minutes=6)).isoformat().replace("+00:00", "Z"),
            "next_update": (BASE_NOW + timedelta(hours=23)).isoformat().replace("+00:00", "Z"),
            "refresh": {
                "status": "SUCCEEDED",
                "started_at": (BASE_NOW - timedelta(minutes=8)).isoformat().replace("+00:00", "Z"),
                "completed_at": (BASE_NOW - timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "network_scope": "VULNERABILITY_DATABASE_ONLY",
            },
        }
    )
    rebind_v1p2(report, validator)
    write_json(evidence / REPORT_NAME, report)
    subject = report["subject"]
    policy = {
        "schema_version": "1.0.0",
        "max_snapshot_age_seconds": 21600,
        "max_database_age_seconds": 86400,
        "max_scan_duration_seconds": 1800,
        "max_future_skew_seconds": 300,
        "blocked_severities": ["HIGH", "CRITICAL"],
        "expected_source": deepcopy(report["source"]),
        "expected_build_input_sha256": provenance["aggregate_sha256"],
        "expected_subject": {
            "immutable_reference": subject["immutable_reference"],
            "image_id": subject["image_id"],
            "image_config_digest": subject["image_config_digest"],
            "platform": subject["platform"],
        },
    }
    pin_external_release_artifacts(policy, report)
    return validator, evidence, report, policy


def test_public_supply_chain_evidence_is_valid_historical_but_stale_for_release() -> None:
    validator = load_validator()
    report = load_json(EVIDENCE / REPORT_NAME)
    schema = load_json(EVIDENCE / "supply-chain-evidence.schema.json")

    Draft202012Validator.check_schema(schema)
    assert (
        list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(report)) == []
    )
    result = validator.verify(EVIDENCE / REPORT_NAME, mode="consistency")
    assert result.release_eligible is False
    assert result.status == "HISTORICAL_CONSISTENT_STALE"
    validator.validate(EVIDENCE / REPORT_NAME, expect_stale_build_inputs=True)
    for kwargs in ({"mode": "release"}, {"release_gate": True}):
        with pytest.raises(validator.EvidenceValidationError) as caught:
            validator.validate(EVIDENCE / REPORT_NAME, **kwargs)
        assert caught.value.code == "HISTORICAL_SCHEMA_NOT_RELEASE_ELIGIBLE"

    assert report["subject"]["image_id"] == (
        "sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775"
    )
    assert report["summary"]["vulnerability_records"] == {
        "UNKNOWN": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }
    assert report["summary"]["verdict"] == "NO_HIGH_OR_CRITICAL_FOUND"
    assert report["schema_version"] == "1.1.0"
    provenance = report["build_input_provenance"]
    assert provenance["hashes_are_digital_signatures"] is False
    assert provenance["build_relationship_attested"] is False
    assert [item["path"] for item in provenance["inputs"]] == [
        ".dockerignore",
        "deploy/tool-service/Dockerfile",
        "deploy/tool-service/requirements.lock",
        "deploy/tool-service/THIRD_PARTY_NOTICES.md",
        "LICENSE",
        "NOTICE",
        "src",
        "data/rules",
    ]
    assert "proof that no vulnerability exists" in report["limitations"][-1]


@pytest.mark.parametrize(
    ("attack", "expected"),
    [
        ("extra-root", "schema validation failed"),
        ("claim-escalation", "schema validation failed"),
        ("repin-image", "schema validation failed"),
        ("forge-build-input", "historical build-input provenance snapshot was altered"),
        ("signature-escalation", "schema validation failed"),
        ("absolute-artifact", "schema validation failed"),
        ("weaken-limitations", "limitations were weakened"),
    ],
)
def test_manifest_attacks_fail_closed(tmp_path: Path, attack: str, expected: str) -> None:
    validator = load_validator()
    evidence = copy_evidence(tmp_path)
    report = load_json(evidence / REPORT_NAME)
    if attack == "extra-root":
        report["private_material"] = "not accepted"
    elif attack == "claim-escalation":
        report["claim_level"] = "PRODUCTION_SECURITY_CERTIFICATION"
    elif attack == "repin-image":
        report["subject"]["image_id"] = "sha256:" + "f" * 64
    elif attack == "forge-build-input":
        report["build_input_provenance"]["inputs"][0]["sha256"] = "sha256:" + "f" * 64
    elif attack == "signature-escalation":
        report["build_input_provenance"]["hashes_are_digital_signatures"] = True
    elif attack == "absolute-artifact":
        report["artifacts"][0]["path"] = "/Users/example/private.json"
    elif attack == "weaken-limitations":
        report["limitations"][-1] = "This proves that no vulnerability exists in the image."
    else:
        raise AssertionError(f"unknown attack: {attack}")
    write_json(evidence / REPORT_NAME, report)

    with pytest.raises(validator.EvidenceValidationError, match=expected):
        validator.validate(evidence / REPORT_NAME, expect_stale_build_inputs=True)


def test_artifact_digest_tampering_fails_closed(tmp_path: Path) -> None:
    validator = load_validator()
    evidence = copy_evidence(tmp_path)
    path = evidence / "sbom.cyclonedx.json"
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(validator.EvidenceValidationError, match=r"artifact .* mismatch"):
        validator.validate(evidence / REPORT_NAME, expect_stale_build_inputs=True)


@pytest.mark.parametrize(
    "leak_value",
    [
        "/Users/" + "example/private",
        "Bearer " + "A" * 32,
        "1" + "3" * 10,
        "\u4e2a\u4eba\u8d44\u6599",
    ],
)
def test_public_artifact_leakage_fails_closed(tmp_path: Path, leak_value: str) -> None:
    validator = load_validator()
    evidence = copy_evidence(tmp_path)
    report = load_json(evidence / REPORT_NAME)
    trivy_path = evidence / "vulnerabilities.trivy.json"
    trivy = load_json(trivy_path)
    trivy["Metadata"]["synthetic_leak_test"] = leak_value
    write_json(trivy_path, trivy)
    refresh_artifact_record(report, evidence, trivy_path.name)
    write_json(evidence / REPORT_NAME, report)

    with pytest.raises(validator.EvidenceValidationError, match="detected"):
        validator.validate(evidence / REPORT_NAME, expect_stale_build_inputs=True)


def test_release_gate_uses_recomputed_high_findings(tmp_path: Path) -> None:
    validator = load_validator()
    evidence = copy_evidence(tmp_path)
    report = load_json(evidence / REPORT_NAME)
    trivy_path = evidence / "vulnerabilities.trivy.json"
    trivy = load_json(trivy_path)
    attacked = deepcopy(trivy)
    attacked["Results"][0]["Vulnerabilities"] = [
        {
            "VulnerabilityID": "CVE-2099-0001",
            "PkgName": "synthetic-package",
            "InstalledVersion": "0",
            "FixedVersion": "1",
            "Status": "fixed",
            "Severity": "HIGH",
            "PrimaryURL": "https://example.invalid/CVE-2099-0001",
        }
    ]
    write_json(trivy_path, attacked)
    counts, targets, findings = validator._trivy_summary(attacked)
    report["summary"].update(
        {
            "vulnerability_records": counts,
            "total_vulnerability_records": 1,
            "findings_by_target": targets,
            "high_or_critical_findings": findings,
            "verdict": "HIGH_OR_CRITICAL_FOUND",
        }
    )
    record = next(
        item for item in report["artifacts"] if item["path"] == "vulnerabilities.trivy.json"
    )
    record["record_count"] = 1
    refresh_artifact_record(report, evidence, trivy_path.name)
    write_json(evidence / REPORT_NAME, report)

    validator.validate(evidence / REPORT_NAME, expect_stale_build_inputs=True)
    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.validate(evidence / REPORT_NAME, release_gate=True)
    assert caught.value.code == "HISTORICAL_SCHEMA_NOT_RELEASE_ELIGIBLE"


def test_v1p2_consistency_never_implies_release_and_release_requires_policy(
    tmp_path: Path,
) -> None:
    validator, evidence, _report, policy = make_v1p2_evidence(tmp_path)

    consistency = validator.verify(evidence / REPORT_NAME, mode="consistency")
    assert consistency.release_eligible is False
    assert consistency.status == "CONSISTENT_CURRENT_BUILD_INPUTS_NOT_RELEASE_EVALUATED"
    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(evidence / REPORT_NAME, mode="release", now=BASE_NOW)
    assert caught.value.code == "RELEASE_POLICY_MISSING"

    release = validator.verify(
        evidence / REPORT_NAME,
        mode="release",
        release_policy=policy,
        now=BASE_NOW,
    )
    assert release.release_eligible is True
    assert release.status == "RELEASE_ELIGIBLE"


def test_schema_versions_cannot_smuggle_each_others_release_fields(tmp_path: Path) -> None:
    validator = load_validator()
    historical = copy_evidence(tmp_path / "historical")
    historical_report = load_json(historical / REPORT_NAME)
    historical_report["evidence_set_id"] = "sha256:" + "0" * 64
    write_json(historical / REPORT_NAME, historical_report)
    with pytest.raises(validator.EvidenceValidationError, match="schema validation failed"):
        validator.verify(historical / REPORT_NAME)

    validator, current, report, _policy = make_v1p2_evidence(tmp_path / "current")
    report.pop("release_binding")
    write_json(current / REPORT_NAME, report)
    with pytest.raises(validator.EvidenceValidationError, match="schema validation failed"):
        validator.verify(current / REPORT_NAME)


def test_v1p2_consistency_can_validate_a_stale_bound_snapshot(tmp_path: Path) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    report["build_input_provenance"]["inputs"][0]["sha256"] = "sha256:" + "f" * 64
    report["build_input_provenance"]["aggregate_sha256"] = validator._build_input_binding_sha256(
        report["build_input_provenance"]
    )
    rebind_v1p2(report, validator)
    write_json(evidence / REPORT_NAME, report)

    result = validator.verify(evidence / REPORT_NAME, mode="consistency")
    assert result.release_eligible is False
    assert result.status == "CONSISTENT_STALE"
    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert caught.value.code == "BUILD_INPUT_MISMATCH"


@pytest.mark.parametrize(
    ("mutation", "now_offset", "expected_code"),
    [
        ("timestamp-order", timedelta(), "TIMESTAMP_ORDER_INVALID"),
        ("future", timedelta(), "CLOCK_SKEW_FUTURE"),
        ("snapshot-expired", timedelta(hours=6, microseconds=1), "SNAPSHOT_EXPIRED"),
        ("database-expired", timedelta(), "DATABASE_EXPIRED"),
        ("database-due", timedelta(hours=1), "DATABASE_REFRESH_DUE"),
        ("refresh-failed", timedelta(), "DATABASE_REFRESH_FAILED"),
    ],
)
def test_release_freshness_failures_have_stable_codes(
    tmp_path: Path,
    mutation: str,
    now_offset: timedelta,
    expected_code: str,
) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    if mutation == "timestamp-order":
        report["scan"]["started_at"] = (BASE_NOW + timedelta(seconds=1)).isoformat()
    elif mutation == "future":
        future = BASE_NOW + timedelta(minutes=5, microseconds=1)
        report["collected_at"] = future.isoformat()
        report["scan"]["completed_at"] = future.isoformat()
        report["vulnerability_database"]["next_update"] = (BASE_NOW + timedelta(days=1)).isoformat()
    elif mutation == "refresh-failed":
        report["vulnerability_database"]["refresh"]["status"] = "FAILED"
    elif mutation == "database-expired":
        report["vulnerability_database"]["updated_at"] = (
            BASE_NOW - timedelta(hours=24, microseconds=1)
        ).isoformat()
    elif mutation == "database-due":
        report["vulnerability_database"]["next_update"] = (
            BASE_NOW + timedelta(hours=1)
        ).isoformat()
    elif mutation != "snapshot-expired":
        raise AssertionError(mutation)
    rebind_v1p2(report, validator)
    pin_external_release_artifacts(policy, report)
    write_json(evidence / REPORT_NAME, report)

    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW + now_offset,
        )
    assert caught.value.code == expected_code


def test_release_freshness_inclusive_age_and_scan_boundaries_pass(tmp_path: Path) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    report["scan"]["started_at"] = (BASE_NOW - timedelta(minutes=30)).isoformat()
    report["vulnerability_database"]["refresh"]["started_at"] = (
        BASE_NOW - timedelta(minutes=20)
    ).isoformat()
    report["vulnerability_database"]["downloaded_at"] = (
        BASE_NOW - timedelta(minutes=18)
    ).isoformat()
    report["vulnerability_database"]["refresh"]["completed_at"] = (
        BASE_NOW - timedelta(minutes=17)
    ).isoformat()
    report["vulnerability_database"]["updated_at"] = (BASE_NOW - timedelta(hours=18)).isoformat()
    report["vulnerability_database"]["next_update"] = (BASE_NOW + timedelta(hours=7)).isoformat()
    rebind_v1p2(report, validator)
    pin_external_release_artifacts(policy, report)
    write_json(evidence / REPORT_NAME, report)

    result = validator.verify(
        evidence / REPORT_NAME,
        mode="release",
        release_policy=policy,
        now=BASE_NOW + timedelta(hours=6),
    )
    assert result.release_eligible is True


def test_future_skew_equality_passes_and_scan_overrun_fails(tmp_path: Path) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    future_limit = BASE_NOW + timedelta(minutes=5)
    report["collected_at"] = future_limit.isoformat()
    report["scan"]["completed_at"] = future_limit.isoformat()
    report["vulnerability_database"]["next_update"] = (BASE_NOW + timedelta(days=1)).isoformat()
    rebind_v1p2(report, validator)
    pin_external_release_artifacts(policy, report)
    write_json(evidence / REPORT_NAME, report)
    assert validator.verify(
        evidence / REPORT_NAME,
        mode="release",
        release_policy=policy,
        now=BASE_NOW,
    ).release_eligible

    report["scan"]["started_at"] = (
        future_limit - timedelta(minutes=30, microseconds=1)
    ).isoformat()
    rebind_v1p2(report, validator)
    pin_external_release_artifacts(policy, report)
    write_json(evidence / REPORT_NAME, report)
    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert caught.value.code == "TIMESTAMP_ORDER_INVALID"


def test_now_equal_to_database_next_update_fails(tmp_path: Path) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    due = BASE_NOW + timedelta(minutes=1)
    report["vulnerability_database"]["next_update"] = due.isoformat()
    rebind_v1p2(report, validator)
    pin_external_release_artifacts(policy, report)
    write_json(evidence / REPORT_NAME, report)

    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=due,
        )
    assert caught.value.code == "DATABASE_REFRESH_DUE"


@pytest.mark.parametrize(
    ("attack", "expected_code"),
    [
        ("source", "SOURCE_REVISION_MISMATCH"),
        ("source-live", "SOURCE_REVISION_MISMATCH"),
        ("build", "BUILD_INPUT_MISMATCH"),
        ("subject", "SUBJECT_MISMATCH"),
        ("artifact-set", "ARTIFACT_SET_MISMATCH"),
        ("binding", "RELEASE_BINDING_INVALID"),
        ("policy-raw", "ARTIFACT_SET_MISMATCH"),
        ("policy-database", "RELEASE_BINDING_INVALID"),
        ("policy-evidence-id", "RELEASE_BINDING_INVALID"),
    ],
)
def test_release_binding_attacks_fail_closed(
    tmp_path: Path, attack: str, expected_code: str
) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    if attack == "source":
        policy["expected_source"]["commit_sha"] = "f" * 40
    elif attack == "source-live":
        report["source"]["commit_sha"] = "f" * 40
        policy["expected_source"]["commit_sha"] = "f" * 40
        rebind_v1p2(report, validator)
        write_json(evidence / REPORT_NAME, report)
    elif attack == "build":
        policy["expected_build_input_sha256"] = "sha256:" + "f" * 64
    elif attack == "subject":
        policy["expected_subject"]["image_id"] = "sha256:" + "f" * 64
    elif attack == "artifact-set":
        report["raw_artifact_set"][0]["sha256"] = "sha256:" + "f" * 64
        write_json(evidence / REPORT_NAME, report)
    elif attack == "binding":
        report["evidence_set_id"] = "sha256:" + "f" * 64
        write_json(evidence / REPORT_NAME, report)
    elif attack == "policy-raw":
        policy["expected_raw_artifacts"]["vulnerabilities.trivy.json"]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif attack == "policy-database":
        policy["expected_database"]["sha256"] = "sha256:" + "f" * 64
    elif attack == "policy-evidence-id":
        policy["expected_evidence_set_id"] = "sha256:" + "f" * 64
    else:
        raise AssertionError(attack)

    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert caught.value.code == expected_code


def test_v1p2_release_recomputes_high_and_critical_findings(tmp_path: Path) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    replace_trivy_vulnerabilities(
        validator,
        evidence,
        report,
        [
            {
                "VulnerabilityID": "CVE-2099-0001",
                "PkgName": "synthetic-package",
                "InstalledVersion": "0",
                "FixedVersion": "1",
                "Status": "fixed",
                "Severity": "CRITICAL",
                "PrimaryURL": "https://example.invalid/CVE-2099-0001",
            }
        ],
    )
    pin_external_release_artifacts(policy, report)
    write_json(evidence / REPORT_NAME, report)

    validator.verify(evidence / REPORT_NAME, mode="consistency")
    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert caught.value.code == "RELEASE_BLOCKED_FINDINGS"


def test_external_policy_blocks_removing_critical_and_rebinding_everything(
    tmp_path: Path,
) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    critical = {
        "VulnerabilityID": "CVE-2099-0001",
        "PkgName": "synthetic-package",
        "InstalledVersion": "0",
        "FixedVersion": "1",
        "Status": "fixed",
        "Severity": "CRITICAL",
        "PrimaryURL": "https://example.invalid/CVE-2099-0001",
    }
    replace_trivy_vulnerabilities(validator, evidence, report, [critical])
    pin_external_release_artifacts(policy, report)
    write_json(evidence / REPORT_NAME, report)
    with pytest.raises(validator.EvidenceValidationError) as originally_blocked:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert originally_blocked.value.code == "RELEASE_BLOCKED_FINDINGS"

    replace_trivy_vulnerabilities(validator, evidence, report, [])
    write_json(evidence / REPORT_NAME, report)
    with pytest.raises(validator.EvidenceValidationError) as rewritten:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert rewritten.value.code == "ARTIFACT_SET_MISMATCH"


def test_external_policy_blocks_database_rewrite_with_recomputed_evidence_id(
    tmp_path: Path,
) -> None:
    validator, evidence, report, policy = make_v1p2_evidence(tmp_path)
    report["vulnerability_database"]["sha256"] = "sha256:" + "f" * 64
    rebind_v1p2(report, validator)
    write_json(evidence / REPORT_NAME, report)

    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert caught.value.code == "RELEASE_BINDING_INVALID"


@pytest.mark.parametrize(
    "missing_pin",
    ["expected_raw_artifacts", "expected_database", "expected_evidence_set_id"],
)
def test_release_policy_missing_external_pin_is_stably_invalid(
    tmp_path: Path, missing_pin: str
) -> None:
    validator, evidence, _report, policy = make_v1p2_evidence(tmp_path)
    policy.pop(missing_pin)
    with pytest.raises(validator.EvidenceValidationError) as caught:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy,
            now=BASE_NOW,
        )
    assert caught.value.code == "RELEASE_POLICY_INVALID"


def test_path_policy_requires_and_verifies_external_file_digest(tmp_path: Path) -> None:
    validator, evidence, _report, policy = make_v1p2_evidence(tmp_path / "evidence-root")
    policy_path = tmp_path / "approved-release-policy.json"
    write_json(policy_path, policy)
    policy_sha256 = f"sha256:{sha256(policy_path.read_bytes()).hexdigest()}"

    with pytest.raises(validator.EvidenceValidationError) as missing:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy_path,
            now=BASE_NOW,
        )
    assert missing.value.code == "RELEASE_POLICY_MISSING"

    with pytest.raises(validator.EvidenceValidationError) as wrong:
        validator.verify(
            evidence / REPORT_NAME,
            mode="release",
            release_policy=policy_path,
            release_policy_sha256="sha256:" + "f" * 64,
            now=BASE_NOW,
        )
    assert wrong.value.code == "RELEASE_POLICY_INVALID"

    result = validator.verify(
        evidence / REPORT_NAME,
        mode="release",
        release_policy=policy_path,
        release_policy_sha256=policy_sha256,
        now=BASE_NOW,
    )
    assert result.release_eligible is True


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"schema_version":"1.2.0","schema_version":"1.2.0"}', "duplicate"),
        ('{"schema_version":"1.2.0","value":NaN}', "non-finite"),
    ],
)
def test_strict_json_rejects_duplicate_and_nonfinite_values(
    tmp_path: Path, payload: str, expected: str
) -> None:
    validator = load_validator()
    attacked = tmp_path / REPORT_NAME
    attacked.write_text(payload)
    with pytest.raises(validator.EvidenceValidationError, match=expected):
        validator.verify(attacked)


def test_production_cli_has_no_clock_rollback_flag() -> None:
    completed = subprocess.run(
        ["uv", "run", "python", str(VALIDATOR_PATH), "--help"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--now" not in completed.stdout


def test_collector_cli_cannot_self_assert_release_eligibility() -> None:
    completed = subprocess.run(
        ["uv", "run", "python", str(COLLECTOR_PATH), "--help"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--release-policy" not in completed.stdout


def test_collector_build_input_aggregate_is_recomputable() -> None:
    collector = load_collector()
    validator = load_validator()
    provenance = collector.build_input_provenance()
    assert provenance["aggregate_sha256"] == validator._build_input_binding_sha256(provenance)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b'{"a":1,"a":1}', "duplicate"),
        (b'{"a":NaN}', "non-finite"),
    ],
)
def test_collector_strict_json_rejects_duplicate_and_nonfinite_values(
    payload: bytes, expected: str
) -> None:
    collector = load_collector()
    with pytest.raises(collector.CollectionError, match=expected):
        collector.load_json_bytes(payload, "synthetic")


@pytest.mark.parametrize("symlink_location", ["terminal", "parent"])
def test_collection_rejects_symlink_output_chain_before_source_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    symlink_location: str,
) -> None:
    collector = load_collector()
    source_called = False

    def observe_source() -> dict[str, Any]:
        nonlocal source_called
        source_called = True
        return {"synthetic": True}

    monkeypatch.setattr(collector, "source_revision", observe_source)
    if symlink_location == "terminal":
        real_output = tmp_path / "real-evidence"
        real_output.mkdir()
        (real_output / "previous.json").write_text("previous\n")
        output = tmp_path / "evidence-link"
        output.symlink_to(real_output, target_is_directory=True)
    else:
        real_parent = tmp_path / "real-parent"
        real_parent.mkdir()
        (real_parent / "previous.json").write_text("previous\n")
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        output = linked_parent / "evidence"

    with pytest.raises(collector.CollectionError, match="must not contain symlinks"):
        collector.collect(output)

    assert source_called is False
    assert list(tmp_path.rglob(".*.staging-*")) == []


def test_collection_validation_failure_preserves_previous_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = load_collector()
    output = tmp_path / "evidence"
    output.mkdir()
    marker = output / "previous.json"
    marker.write_text('{"status":"historical"}\n')

    monkeypatch.setattr(collector, "source_revision", lambda: {"synthetic": True})

    def fake_collect(candidate: Path, **_kwargs: Any) -> dict[str, Any]:
        candidate.mkdir()
        (candidate / REPORT_NAME).write_text('{"schema_version":"1.2.0"}\n')
        return {"schema_version": "1.2.0"}

    def reject_candidate(_candidate: Path, **_kwargs: Any) -> None:
        raise collector.CollectionError("synthetic validation failure")

    monkeypatch.setattr(collector, "_collect_into", fake_collect)
    monkeypatch.setattr(collector, "_self_validate", reject_candidate)
    with pytest.raises(collector.CollectionError, match="synthetic validation failure"):
        collector.collect(output)

    assert marker.read_text() == '{"status":"historical"}\n'
    assert list(tmp_path.glob(".evidence.staging-*")) == []


def test_collection_promotes_only_after_complete_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = load_collector()
    output = tmp_path / "evidence"
    output.mkdir()
    (output / "previous.json").write_text('{"status":"historical"}\n')
    validation_observations: list[bool] = []

    monkeypatch.setattr(collector, "source_revision", lambda: {"synthetic": True})

    def fake_collect(candidate: Path, **_kwargs: Any) -> dict[str, Any]:
        candidate.mkdir()
        (candidate / REPORT_NAME).write_text('{"schema_version":"1.2.0"}\n')
        return {"schema_version": "1.2.0"}

    def accept_candidate(candidate: Path, **_kwargs: Any) -> None:
        validation_observations.append((candidate / REPORT_NAME).is_file())

    monkeypatch.setattr(collector, "_collect_into", fake_collect)
    monkeypatch.setattr(collector, "_self_validate", accept_candidate)
    report = collector.collect(output)

    assert validation_observations == [True]
    assert report == {"schema_version": "1.2.0"}
    assert (output / REPORT_NAME).is_file()
    assert not (output / "previous.json").exists()
    assert (output / "supply-chain-evidence.schema.json").is_file()
    assert (output / "supply-chain-release-policy.schema.json").is_file()


def test_atomic_promotion_failure_restores_previous_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = load_collector()
    output = tmp_path / "evidence"
    candidate = tmp_path / "candidate"
    output.mkdir()
    candidate.mkdir()
    (output / "previous.json").write_text("previous\n")
    (candidate / "candidate.json").write_text("candidate\n")
    original_replace = collector.os.replace
    calls = 0

    def fail_second_replace(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic promotion failure")
        original_replace(source, destination)

    monkeypatch.setattr(collector.os, "replace", fail_second_replace)
    with pytest.raises(OSError, match="synthetic promotion failure"):
        collector._promote_directory(candidate, output)

    assert (output / "previous.json").read_text() == "previous\n"
    assert (candidate / "candidate.json").read_text() == "candidate\n"


def test_backup_cleanup_failure_is_nonfatal_after_candidate_is_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    collector = load_collector()
    output = tmp_path / "evidence"
    candidate = tmp_path / "candidate"
    output.mkdir()
    candidate.mkdir()
    (output / "previous.json").write_text("previous\n")
    (candidate / "candidate.json").write_text("candidate\n")

    def fail_backup_cleanup(_path: Path) -> None:
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(collector.shutil, "rmtree", fail_backup_cleanup)
    with warnings.catch_warnings(), caplog.at_level(30, logger=collector.LOGGER.name):
        warnings.simplefilter("error")
        retained_backup = collector._promote_directory(candidate, output)

    assert retained_backup is not None
    assert "validated evidence is live; previous backup retained" in caplog.text
    assert retained_backup.is_dir()
    assert (retained_backup / "previous.json").read_text() == "previous\n"
    assert (output / "candidate.json").read_text() == "candidate\n"
