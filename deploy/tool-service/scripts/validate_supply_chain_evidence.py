#!/usr/bin/env python3
"""Validate ProofFlow's public tool-image supply-chain evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE = ROOT / "deploy/tool-service/evidence/supply-chain-evidence.json"
DEFAULT_SCHEMA = ROOT / "deploy/tool-service/evidence/supply-chain-evidence.schema.json"

SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
EXPECTED_ARTIFACTS = {
    "sbom.cyclonedx.json": "application/vnd.cyclonedx+json",
    "sbom.spdx.json": "application/spdx+json",
    "vulnerabilities.trivy.json": "application/vnd.aquasec.trivy.report+json",
}
EXPECTED_IMAGE_ENV_KEYS = {
    "GPG_KEY",
    "LANG",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONPATH",
    "PYTHONUNBUFFERED",
    "PYTHON_SHA256",
    "PYTHON_VERSION",
}
BUILD_INPUT_FILES = (
    ".dockerignore",
    "deploy/tool-service/Dockerfile",
    "deploy/tool-service/requirements.lock",
    "deploy/tool-service/THIRD_PARTY_NOTICES.md",
    "LICENSE",
    "NOTICE",
)
BUILD_INPUT_DIRECTORIES = ("src", "data/rules")
DIRECTORY_BUNDLE_FORMAT = "PATH_LENGTH_U64_BE_PATH_BYTES_CONTENT_LENGTH_U64_BE_CONTENT_BYTES_V1"
EXPECTED_LIMITATIONS = (
    "This is a point-in-time scan against one mutable vulnerability database snapshot.",
    (
        "Scanner and advisory database false positives, false negatives, and coverage gaps "
        "remain possible."
    ),
    "The scan covers final-image OS and language packages, not dynamic application behavior.",
    (
        "Runtime configuration, running-container environment, credentials, secrets, and "
        "network behavior were not inspected."
    ),
    (
        "Unsigned build-input hashes are not a build attestation or digital signature and do "
        "not verify deployment or production security."
    ),
    (
        "No finding at a severity is evidence of scanner non-detection, not proof that no "
        "vulnerability exists."
    ),
)

HOST_PATH_MARKERS = (
    "/Users/",
    "/var/folders/",
    "\\Users\\",
    "Documents/Codex/",
)
SENSITIVE_TEXT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?<![A-Za-z0-9])(?:ghp_|github_pat_|xox[baprs]-)[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])"),
)
MOBILE_VALUE = re.compile(r"1[3-9][0-9]{9}")
CJK_TEXT = re.compile(r"[\u3400-\u9fff]")


class EvidenceValidationError(ValueError):
    """Raised for a public-evidence contract violation."""


def _reject_constant(value: str) -> None:
    del value
    raise EvidenceValidationError("non-finite JSON numbers are not allowed")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceValidationError("duplicate JSON object keys are not allowed")
        result[key] = value
    return result


def load_json_strict(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"invalid JSON file: {path.name}") from exc
    if not isinstance(parsed, dict):
        raise EvidenceValidationError(f"JSON root must be an object: {path.name}")
    return parsed


def _validate_schema(document: dict[str, Any], schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    if errors:
        error = errors[0]
        location = "/".join(str(item) for item in error.absolute_path) or "<root>"
        raise EvidenceValidationError(f"schema validation failed at {location} ({error.validator})")


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _is_generated_python_cache(relative_path: Path) -> bool:
    return "__pycache__" in relative_path.parts or relative_path.suffix in {".pyc", ".pyo"}


def _directory_input_files(relative_directory: str) -> list[Path]:
    directory = ROOT / relative_directory
    if not directory.is_dir() or directory.is_symlink():
        raise EvidenceValidationError(
            f"build input directory is missing or unsafe: {relative_directory}"
        )
    files: list[Path] = []
    for candidate in directory.rglob("*"):
        relative_path = candidate.relative_to(directory)
        if _is_generated_python_cache(relative_path):
            continue
        if candidate.is_symlink():
            raise EvidenceValidationError(f"build input symlink is not allowed: {candidate}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise EvidenceValidationError(f"build input is not a regular file: {candidate}")
        if relative_directory == "src":
            allowed = candidate.suffix == ".py" or candidate.name == "py.typed"
        else:
            allowed = candidate.suffix == ".json"
        if not allowed:
            raise EvidenceValidationError(f"unexpected build input file: {candidate}")
        files.append(candidate)
    if not files:
        raise EvidenceValidationError(f"build input directory is empty: {relative_directory}")
    return sorted(files, key=lambda item: item.relative_to(directory).as_posix())


def _expected_build_input_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for relative_path in BUILD_INPUT_FILES:
        source = ROOT / relative_path
        if not source.is_file() or source.is_symlink():
            raise EvidenceValidationError(f"build input file is missing or unsafe: {relative_path}")
        payload = source.read_bytes()
        records.append(
            {
                "path": relative_path,
                "kind": "FILE_BYTES",
                "sha256": _sha256(payload),
                "bytes": len(payload),
                "file_count": 1,
            }
        )
    for relative_directory in BUILD_INPUT_DIRECTORIES:
        directory = ROOT / relative_directory
        digest = hashlib.sha256()
        total_bytes = 0
        files = _directory_input_files(relative_directory)
        for source in files:
            relative_path = source.relative_to(directory).as_posix().encode("utf-8")
            payload = source.read_bytes()
            digest.update(len(relative_path).to_bytes(8, byteorder="big"))
            digest.update(relative_path)
            digest.update(len(payload).to_bytes(8, byteorder="big"))
            digest.update(payload)
            total_bytes += len(payload)
        records.append(
            {
                "path": relative_directory,
                "kind": "DIRECTORY_BUNDLE_V1",
                "sha256": f"sha256:{digest.hexdigest()}",
                "bytes": total_bytes,
                "file_count": len(files),
            }
        )
    return records


def _validate_build_input_provenance(report: dict[str, Any]) -> None:
    provenance = report["build_input_provenance"]
    if provenance["directory_bundle_format"] != DIRECTORY_BUNDLE_FORMAT:
        raise EvidenceValidationError("unexpected build-input directory bundle format")
    dockerignore = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
    if not {"demo", "**/__pycache__/", "**/*.py[cod]"} <= dockerignore:
        raise EvidenceValidationError("Docker build context exclusions were weakened")
    if provenance["inputs"] != _expected_build_input_records():
        raise EvidenceValidationError("build-input provenance differs from repository bytes")


def _parse_datetime(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceValidationError(f"{label} is not an RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise EvidenceValidationError(f"{label} must carry an offset")
    return parsed.astimezone(UTC)


def _walk_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            strings.append(key)
            strings.extend(_walk_strings(child))
    elif isinstance(value, list):
        for child in value:
            strings.extend(_walk_strings(child))
    return strings


def _validate_no_public_leakage(filename: str, payload: bytes, document: dict[str, Any]) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceValidationError(f"public artifact is not UTF-8: {filename}") from exc
    if any(marker in text for marker in HOST_PATH_MARKERS):
        raise EvidenceValidationError(f"host absolute path detected in {filename}")
    if CJK_TEXT.search(text):
        raise EvidenceValidationError(f"unexpected personal-language text detected in {filename}")
    if any(pattern.search(text) for pattern in SENSITIVE_TEXT_PATTERNS):
        raise EvidenceValidationError(f"credential-shaped material detected in {filename}")
    for value in _walk_strings(document):
        if CJK_TEXT.search(value):
            raise EvidenceValidationError(
                f"unexpected personal-language text detected in {filename}"
            )
        if MOBILE_VALUE.fullmatch(value):
            raise EvidenceValidationError(f"mobile-number-shaped value detected in {filename}")


def _artifact_paths(
    evidence_path: Path, report: dict[str, Any]
) -> tuple[dict[str, Path], dict[str, dict[str, Any]]]:
    evidence_dir = evidence_path.parent.resolve()
    paths: dict[str, Path] = {}
    records: dict[str, dict[str, Any]] = {}
    for record in report["artifacts"]:
        raw_path = record["path"]
        posix = PurePosixPath(raw_path)
        if posix.is_absolute() or ".." in posix.parts or len(posix.parts) != 1:
            raise EvidenceValidationError("artifact paths must be relative basenames")
        if raw_path in records:
            raise EvidenceValidationError("artifact paths must be unique")
        resolved = (evidence_dir / raw_path).resolve()
        if resolved.parent != evidence_dir:
            raise EvidenceValidationError("artifact path escapes the evidence directory")
        if not resolved.is_file():
            raise EvidenceValidationError(f"artifact is missing: {raw_path}")
        records[raw_path] = record
        paths[raw_path] = resolved
    if set(paths) != set(EXPECTED_ARTIFACTS):
        raise EvidenceValidationError("artifact set does not match the public contract")
    return paths, records


def _validate_artifact_integrity(
    paths: dict[str, Path], records: dict[str, dict[str, Any]]
) -> None:
    for name, path in paths.items():
        payload = path.read_bytes()
        record = records[name]
        if record["media_type"] != EXPECTED_ARTIFACTS[name]:
            raise EvidenceValidationError(f"artifact media type mismatch: {name}")
        if record["bytes"] != len(payload):
            raise EvidenceValidationError(f"artifact byte count mismatch: {name}")
        if record["sha256"] != _sha256(payload):
            raise EvidenceValidationError(f"artifact digest mismatch: {name}")


def _high_or_critical_findings(trivy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in trivy["Results"]:
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = vulnerability.get("Severity", "UNKNOWN")
            if severity not in {"HIGH", "CRITICAL"}:
                continue
            findings.append(
                {
                    "target": result.get("Target", ""),
                    "class": result.get("Class", ""),
                    "type": result.get("Type", ""),
                    "vulnerability_id": vulnerability.get("VulnerabilityID", ""),
                    "package_name": vulnerability.get("PkgName", ""),
                    "installed_version": vulnerability.get("InstalledVersion", ""),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "status": vulnerability.get("Status", ""),
                    "severity": severity,
                    "primary_url": vulnerability.get("PrimaryURL", ""),
                }
            )
    return sorted(
        findings,
        key=lambda item: (item["severity"], item["vulnerability_id"], item["package_name"]),
    )


def _trivy_summary(
    trivy: dict[str, Any],
) -> tuple[dict[str, int], list[dict[str, Any]], list[dict[str, Any]]]:
    counts: Counter[str] = Counter()
    targets: list[dict[str, Any]] = []
    for result in trivy["Results"]:
        target_counts: Counter[str] = Counter()
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise EvidenceValidationError("Trivy Vulnerabilities must be an array or null")
        for vulnerability in vulnerabilities:
            severity = vulnerability.get("Severity", "UNKNOWN")
            if severity not in SEVERITIES:
                raise EvidenceValidationError("Trivy report contains an unknown severity")
            counts[severity] += 1
            target_counts[severity] += 1
        targets.append(
            {
                "target": result.get("Target", ""),
                "class": result.get("Class", ""),
                "type": result.get("Type", ""),
                "records": {severity: target_counts[severity] for severity in SEVERITIES},
                "total": sum(target_counts.values()),
            }
        )
    return (
        {severity: counts[severity] for severity in SEVERITIES},
        targets,
        _high_or_critical_findings(trivy),
    )


def _validate_cyclonedx(
    document: dict[str, Any], report: dict[str, Any], record: dict[str, Any]
) -> str:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.7":
        raise EvidenceValidationError("unexpected CycloneDX format or version")
    components = document.get("components")
    if not isinstance(components, list):
        raise EvidenceValidationError("CycloneDX components must be an array")
    if len(components) != record["record_count"]:
        raise EvidenceValidationError("CycloneDX record count mismatch")
    if len(components) != report["summary"]["cyclonedx_components"]:
        raise EvidenceValidationError("CycloneDX summary count mismatch")
    metadata = document.get("metadata") or {}
    target = metadata.get("component") or {}
    if target.get("name") != "target.tar" or target.get("type") != "container":
        raise EvidenceValidationError("CycloneDX target identity mismatch")
    tools = (metadata.get("tools") or {}).get("components") or []
    if not any(
        item.get("name") == "syft" and item.get("version") == report["tools"]["syft"]["version"]
        for item in tools
    ):
        raise EvidenceValidationError("CycloneDX did not record the pinned Syft version")
    image_artifact_id = target.get("version")
    if not isinstance(image_artifact_id, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", image_artifact_id
    ):
        raise EvidenceValidationError("CycloneDX image artifact ID is invalid")
    return image_artifact_id


def _validate_spdx(
    document: dict[str, Any],
    report: dict[str, Any],
    record: dict[str, Any],
    syft_target_version: str,
) -> None:
    if document.get("spdxVersion") != "SPDX-2.3" or document.get("name") != "target.tar":
        raise EvidenceValidationError("unexpected SPDX format or target")
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise EvidenceValidationError("SPDX packages must be an array")
    if len(packages) != record["record_count"]:
        raise EvidenceValidationError("SPDX record count mismatch")
    if len(packages) != report["summary"]["spdx_packages"]:
        raise EvidenceValidationError("SPDX summary count mismatch")
    creators = (document.get("creationInfo") or {}).get("creators") or []
    if f"Tool: syft-{report['tools']['syft']['version']}" not in creators:
        raise EvidenceValidationError("SPDX did not record the pinned Syft version")
    targets = [
        package
        for package in packages
        if package.get("name") == "target.tar"
        and package.get("primaryPackagePurpose") == "CONTAINER"
    ]
    if len(targets) != 1 or targets[0].get("versionInfo") != syft_target_version:
        raise EvidenceValidationError("CycloneDX and SPDX identify different Syft targets")


def _validate_trivy(
    document: dict[str, Any], report: dict[str, Any], record: dict[str, Any]
) -> None:
    if document.get("SchemaVersion") != 2:
        raise EvidenceValidationError("unexpected Trivy report schema")
    if (
        document.get("ArtifactName") != "target.tar"
        or document.get("ArtifactType") != "container_image"
    ):
        raise EvidenceValidationError("Trivy target identity mismatch")
    if document.get("ArtifactID") != report["subject"]["image_config_digest"]:
        raise EvidenceValidationError("Trivy artifact ID differs from the image config digest")
    if (document.get("Trivy") or {}).get("Version") != report["tools"]["trivy"]["version"]:
        raise EvidenceValidationError("Trivy report did not record the pinned scanner version")

    image_config = (document.get("Metadata") or {}).get("ImageConfig") or {}
    if image_config.get("architecture") != "amd64" or image_config.get("os") != "linux":
        raise EvidenceValidationError("Trivy image platform mismatch")
    config = image_config.get("config") or {}
    if config.get("User") != "65532:65532":
        raise EvidenceValidationError("Trivy image config did not preserve the non-root user")
    environment = config.get("Env") or []
    if not isinstance(environment, list):
        raise EvidenceValidationError("Trivy image environment must be an array")
    environment_keys = {item.partition("=")[0] for item in environment if isinstance(item, str)}
    if environment_keys != EXPECTED_IMAGE_ENV_KEYS:
        raise EvidenceValidationError("image environment key set is not allowlisted")

    counts, targets, high_findings = _trivy_summary(document)
    summary = report["summary"]
    if counts != summary["vulnerability_records"]:
        raise EvidenceValidationError("Trivy severity counts do not match the summary")
    total = sum(counts.values())
    if total != record["record_count"] or total != summary["total_vulnerability_records"]:
        raise EvidenceValidationError("Trivy total count mismatch")
    if targets != summary["findings_by_target"]:
        raise EvidenceValidationError("Trivy target breakdown mismatch")
    if high_findings != summary["high_or_critical_findings"]:
        raise EvidenceValidationError("Trivy high/critical detail mismatch")
    expected_verdict = (
        "HIGH_OR_CRITICAL_FOUND"
        if counts["HIGH"] + counts["CRITICAL"]
        else "NO_HIGH_OR_CRITICAL_FOUND"
    )
    if summary["verdict"] != expected_verdict:
        raise EvidenceValidationError("vulnerability verdict is inconsistent with record counts")


def validate(evidence_path: Path = DEFAULT_EVIDENCE, *, release_gate: bool = False) -> None:
    evidence_path = evidence_path.resolve()
    report = load_json_strict(evidence_path)
    schema = load_json_strict(DEFAULT_SCHEMA)
    _validate_schema(report, schema)
    _validate_build_input_provenance(report)

    dockerfile = (ROOT / "deploy/tool-service/Dockerfile").read_text(encoding="utf-8")
    expected_from = f"FROM {report['scope']['base_image']}\n"
    if not dockerfile.startswith(expected_from):
        raise EvidenceValidationError("Dockerfile base image differs from the evidence")

    paths, records = _artifact_paths(evidence_path, report)
    _validate_artifact_integrity(paths, records)
    documents: dict[str, dict[str, Any]] = {}
    for name, path in paths.items():
        document = load_json_strict(path)
        _validate_no_public_leakage(name, path.read_bytes(), document)
        documents[name] = document

    syft_target_version = _validate_cyclonedx(
        documents["sbom.cyclonedx.json"],
        report,
        records["sbom.cyclonedx.json"],
    )
    _validate_spdx(
        documents["sbom.spdx.json"],
        report,
        records["sbom.spdx.json"],
        syft_target_version,
    )
    _validate_trivy(
        documents["vulnerabilities.trivy.json"],
        report,
        records["vulnerabilities.trivy.json"],
    )

    collected_at = _parse_datetime(report["collected_at"], "collected_at")
    database = report["vulnerability_database"]
    updated_at = _parse_datetime(database["updated_at"], "database.updated_at")
    downloaded_at = _parse_datetime(database["downloaded_at"], "database.downloaded_at")
    next_update = _parse_datetime(database["next_update"], "database.next_update")
    if not updated_at <= downloaded_at <= collected_at < next_update:
        raise EvidenceValidationError("vulnerability database timestamps are inconsistent")
    if tuple(report["limitations"]) != EXPECTED_LIMITATIONS:
        raise EvidenceValidationError("limitations were weakened or rewritten")

    _validate_no_public_leakage(evidence_path.name, evidence_path.read_bytes(), report)
    if release_gate:
        counts = report["summary"]["vulnerability_records"]
        if counts["HIGH"] or counts["CRITICAL"]:
            raise EvidenceValidationError("release gate rejected high or critical findings")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument(
        "--release-gate",
        action="store_true",
        help="also fail when HIGH or CRITICAL vulnerability records are present",
    )
    arguments = parser.parse_args()
    try:
        validate(arguments.evidence, release_gate=arguments.release_gate)
    except EvidenceValidationError as exc:
        print(f"invalid supply-chain evidence: {exc}", file=sys.stderr)
        return 1
    print("valid supply-chain evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
