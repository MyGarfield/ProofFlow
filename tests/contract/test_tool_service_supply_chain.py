import importlib.util
import json
import shutil
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]
EVIDENCE = ROOT / "deploy/tool-service/evidence"
VALIDATOR_PATH = ROOT / "deploy/tool-service/scripts/validate_supply_chain_evidence.py"
REPORT_NAME = "supply-chain-evidence.json"


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


def test_public_supply_chain_evidence_passes_schema_semantics_and_release_gate() -> None:
    validator = load_validator()
    report = load_json(EVIDENCE / REPORT_NAME)
    schema = load_json(EVIDENCE / "supply-chain-evidence.schema.json")

    Draft202012Validator.check_schema(schema)
    assert (
        list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(report)) == []
    )
    validator.validate(EVIDENCE / REPORT_NAME)
    validator.validate(EVIDENCE / REPORT_NAME, release_gate=True)

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
        ("forge-build-input", "build-input provenance differs"),
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
        validator.validate(evidence / REPORT_NAME)


def test_artifact_digest_tampering_fails_closed(tmp_path: Path) -> None:
    validator = load_validator()
    evidence = copy_evidence(tmp_path)
    path = evidence / "sbom.cyclonedx.json"
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(validator.EvidenceValidationError, match=r"artifact .* mismatch"):
        validator.validate(evidence / REPORT_NAME)


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
        validator.validate(evidence / REPORT_NAME)


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

    validator.validate(evidence / REPORT_NAME)
    with pytest.raises(validator.EvidenceValidationError, match="release gate rejected"):
        validator.validate(evidence / REPORT_NAME, release_gate=True)
