#!/usr/bin/env python3
"""Validate ProofFlow's public tool-image supply-chain evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, NamedTuple

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE = ROOT / "deploy/tool-service/evidence/supply-chain-evidence.json"
DEFAULT_SCHEMA = ROOT / "deploy/tool-service/evidence/supply-chain-evidence.schema.json"
DEFAULT_RELEASE_POLICY_SCHEMA = (
    ROOT / "deploy/tool-service/evidence/supply-chain-release-policy.schema.json"
)

ValidationMode = Literal["consistency", "release"]
CURRENT_SCHEMA_VERSION = "1.2.0"
HISTORICAL_SCHEMA_VERSION = "1.1.0"
MAX_SNAPSHOT_AGE = timedelta(hours=6)
MAX_DATABASE_AGE = timedelta(hours=24)
MAX_SCAN_DURATION = timedelta(minutes=30)
MAX_FUTURE_SKEW = timedelta(minutes=5)
RELEASE_BINDING_ALGORITHM = "CANONICAL_JSON_SHA256_V1"
RELEASE_BINDING_FIELDS = (
    "scan",
    "source",
    "build_input_provenance",
    "subject",
    "raw_artifact_set",
    "vulnerability_database",
)

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
EXPECTED_SRC_DATA_FILES = {
    "proofflow/demo_assets/README.md",
    "proofflow/demo_assets/case/contract.json",
    "proofflow/demo_assets/case/manifest.json",
    "proofflow/demo_assets/case/payroll.json",
    "proofflow/demo_assets/case/termination_notice.json",
    "proofflow/demo_assets/rules/cn_labor_contract_law.catalog.json",
    "proofflow/py.typed",
}
DIRECTORY_BUNDLE_FORMAT = "PATH_LENGTH_U64_BE_PATH_BYTES_CONTENT_LENGTH_U64_BE_CONTENT_BYTES_V1"
HISTORICAL_BUILD_INPUT_PROVENANCE_SHA256 = (
    "sha256:0d836899ce9862f0a0239811d1866327bcfb7747de2a5456d6bb123421789d46"
)
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


class VerificationResult(NamedTuple):
    """Successful verification outcome with an explicit non-escalating release decision."""

    mode: ValidationMode
    schema_version: str
    evidence_set_id: str | None
    release_eligible: bool
    status: str

    def to_dict(self) -> dict[str, Any]:
        return self._asdict()


class EvidenceValidationError(ValueError):
    """Raised for a public-evidence contract violation with a stable machine code."""

    def __init__(self, message: str, *, code: str = "EVIDENCE_CONTRACT_INVALID") -> None:
        super().__init__(message)
        self.code = code


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
            allowed = candidate.suffix == ".py" or relative_path.as_posix() in (
                EXPECTED_SRC_DATA_FILES
            )
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


def _build_input_provenance_sha256(provenance: dict[str, Any]) -> str:
    payload = json.dumps(
        provenance,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256(payload)


def _build_input_binding_sha256(provenance: Mapping[str, Any]) -> str:
    bound = {key: value for key, value in provenance.items() if key != "aggregate_sha256"}
    payload = json.dumps(
        bound,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256(payload)


def _validate_build_input_provenance(
    report: dict[str, Any], *, expect_stale_build_inputs: bool, require_current: bool
) -> bool:
    provenance = report["build_input_provenance"]
    if provenance["directory_bundle_format"] != DIRECTORY_BUNDLE_FORMAT:
        raise EvidenceValidationError("unexpected build-input directory bundle format")
    if require_current:
        dockerignore = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
        if not {"demo", "**/__pycache__/", "**/*.py[cod]"} <= dockerignore:
            raise EvidenceValidationError(
                "Docker build context exclusions were weakened",
                code="BUILD_INPUT_MISMATCH",
            )
    try:
        matches_current = provenance["inputs"] == _expected_build_input_records()
    except EvidenceValidationError:
        if require_current:
            raise
        matches_current = False
    if report["schema_version"] == CURRENT_SCHEMA_VERSION:
        if provenance["aggregate_sha256"] != _build_input_binding_sha256(provenance):
            raise EvidenceValidationError(
                "build-input aggregate digest is inconsistent",
                code="BUILD_INPUT_MISMATCH",
            )
        if expect_stale_build_inputs:
            raise EvidenceValidationError(
                "v1.2 evidence cannot use the v1.1 historical-staleness override",
                code="BUILD_INPUT_MISMATCH",
            )
        if require_current and not matches_current:
            raise EvidenceValidationError(
                "build-input provenance differs from repository bytes",
                code="BUILD_INPUT_MISMATCH",
            )
        return matches_current
    if expect_stale_build_inputs:
        if _build_input_provenance_sha256(provenance) != (HISTORICAL_BUILD_INPUT_PROVENANCE_SHA256):
            raise EvidenceValidationError("historical build-input provenance snapshot was altered")
        return False
    if not matches_current:
        raise EvidenceValidationError("build-input provenance differs from repository bytes")
    return True


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
            raise EvidenceValidationError(
                "artifact paths must be relative basenames",
                code="ARTIFACT_SET_MISMATCH",
            )
        if raw_path in records:
            raise EvidenceValidationError(
                "artifact paths must be unique",
                code="ARTIFACT_SET_MISMATCH",
            )
        resolved = (evidence_dir / raw_path).resolve()
        if resolved.parent != evidence_dir:
            raise EvidenceValidationError("artifact path escapes the evidence directory")
        if not resolved.is_file():
            raise EvidenceValidationError(
                f"artifact is missing: {raw_path}",
                code="ARTIFACT_SET_MISMATCH",
            )
        records[raw_path] = record
        paths[raw_path] = resolved
    if set(paths) != set(EXPECTED_ARTIFACTS):
        raise EvidenceValidationError(
            "artifact set does not match the public contract",
            code="ARTIFACT_SET_MISMATCH",
        )
    return paths, records


def _validate_artifact_integrity(
    paths: dict[str, Path], records: dict[str, dict[str, Any]]
) -> None:
    for name, path in paths.items():
        payload = path.read_bytes()
        record = records[name]
        if record["media_type"] != EXPECTED_ARTIFACTS[name]:
            raise EvidenceValidationError(
                f"artifact media type mismatch: {name}",
                code="ARTIFACT_SET_MISMATCH",
            )
        if record["bytes"] != len(payload):
            raise EvidenceValidationError(
                f"artifact byte count mismatch: {name}",
                code="ARTIFACT_SET_MISMATCH",
            )
        if record["sha256"] != _sha256(payload):
            raise EvidenceValidationError(
                f"artifact digest mismatch: {name}",
                code="ARTIFACT_SET_MISMATCH",
            )


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


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceValidationError(
            "release binding contains a non-canonical value",
            code="RELEASE_BINDING_INVALID",
        ) from exc
    return _sha256(payload)


def _expected_raw_artifact_set(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        [
            {
                "path": record["path"],
                "media_type": record["media_type"],
                "sha256": record["sha256"],
                "bytes": record["bytes"],
            }
            for record in report["artifacts"]
        ],
        key=lambda record: record["path"],
    )


def release_binding_payload(report: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical v1.2 fields covered by ``evidence_set_id``."""

    return {field: report[field] for field in RELEASE_BINDING_FIELDS}


def release_binding_sha256(report: Mapping[str, Any]) -> str:
    """Compute the self-contained v1.2 evidence-set identifier."""

    return _canonical_sha256(release_binding_payload(report))


def _validate_release_binding(report: dict[str, Any]) -> None:
    expected_artifacts = _expected_raw_artifact_set(report)
    if report["raw_artifact_set"] != expected_artifacts:
        raise EvidenceValidationError(
            "release raw-artifact set differs from artifact records",
            code="ARTIFACT_SET_MISMATCH",
        )
    binding = report["release_binding"]
    if binding["algorithm"] != RELEASE_BINDING_ALGORITHM:
        raise EvidenceValidationError(
            "release binding algorithm is unsupported",
            code="RELEASE_BINDING_INVALID",
        )
    if tuple(binding["bound_fields"]) != RELEASE_BINDING_FIELDS:
        raise EvidenceValidationError(
            "release binding field set or order is invalid",
            code="RELEASE_BINDING_INVALID",
        )
    expected_identifier = release_binding_sha256(report)
    if (
        report["evidence_set_id"] != expected_identifier
        or binding["evidence_set_id"] != expected_identifier
    ):
        raise EvidenceValidationError(
            "release evidence-set digest does not bind the declared fields",
            code="RELEASE_BINDING_INVALID",
        )


def _validate_timestamp_order(report: dict[str, Any]) -> dict[str, datetime]:
    scan = report["scan"]
    database = report["vulnerability_database"]
    refresh = database["refresh"]
    timestamps = {
        "collected_at": _parse_datetime(report["collected_at"], "collected_at"),
        "scan.started_at": _parse_datetime(scan["started_at"], "scan.started_at"),
        "scan.completed_at": _parse_datetime(scan["completed_at"], "scan.completed_at"),
        "database.updated_at": _parse_datetime(database["updated_at"], "database.updated_at"),
        "database.downloaded_at": _parse_datetime(
            database["downloaded_at"], "database.downloaded_at"
        ),
        "database.next_update": _parse_datetime(database["next_update"], "database.next_update"),
        "database.refresh.started_at": _parse_datetime(
            refresh["started_at"], "database.refresh.started_at"
        ),
        "database.refresh.completed_at": _parse_datetime(
            refresh["completed_at"], "database.refresh.completed_at"
        ),
    }
    if not (
        timestamps["collected_at"] == timestamps["scan.completed_at"]
        and timestamps["scan.started_at"]
        <= timestamps["database.refresh.started_at"]
        <= timestamps["database.downloaded_at"]
        <= timestamps["database.refresh.completed_at"]
        <= timestamps["scan.completed_at"]
        < timestamps["database.next_update"]
        and timestamps["database.updated_at"] <= timestamps["database.downloaded_at"]
    ):
        raise EvidenceValidationError(
            "scan and database timestamps violate the v1.2 ordering contract",
            code="TIMESTAMP_ORDER_INVALID",
        )
    return timestamps


def _normalise_now(now: datetime | None) -> datetime:
    observed = datetime.now(UTC) if now is None else now
    if observed.tzinfo is None:
        raise EvidenceValidationError(
            "verification clock must be timezone-aware",
            code="CLOCK_SKEW_FUTURE",
        )
    return observed.astimezone(UTC)


def _load_release_policy(
    policy: Path | Mapping[str, Any] | None,
    *,
    expected_policy_sha256: str | None,
) -> dict[str, Any]:
    if policy is None:
        raise EvidenceValidationError(
            "release mode requires an explicit release policy",
            code="RELEASE_POLICY_MISSING",
        )
    try:
        if isinstance(policy, Path):
            if expected_policy_sha256 is None:
                raise EvidenceValidationError(
                    "path-based release policy requires an independently supplied SHA-256",
                    code="RELEASE_POLICY_MISSING",
                )
            try:
                payload = policy.resolve().read_bytes()
            except OSError as exc:
                raise EvidenceValidationError(
                    "release policy file could not be read",
                    code="RELEASE_POLICY_INVALID",
                ) from exc
            if _sha256(payload) != expected_policy_sha256:
                raise EvidenceValidationError(
                    "release policy file differs from the external policy SHA-256",
                    code="RELEASE_POLICY_INVALID",
                )
            parsed = json.loads(
                payload,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_constant,
            )
        else:
            serialised = json.dumps(policy, ensure_ascii=False, allow_nan=False)
            parsed = json.loads(
                serialised,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_constant,
            )
            if expected_policy_sha256 is not None and _canonical_sha256(parsed) != (
                expected_policy_sha256
            ):
                raise EvidenceValidationError(
                    "trusted release policy mapping differs from its external SHA-256",
                    code="RELEASE_POLICY_INVALID",
                )
    except EvidenceValidationError as exc:
        if exc.code in {"RELEASE_POLICY_MISSING", "RELEASE_POLICY_INVALID"}:
            raise
        raise EvidenceValidationError(
            "release policy is not strict JSON",
            code="RELEASE_POLICY_INVALID",
        ) from exc
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(
            "release policy is not strict JSON",
            code="RELEASE_POLICY_INVALID",
        ) from exc
    if not isinstance(parsed, dict):
        raise EvidenceValidationError(
            "release policy root must be an object",
            code="RELEASE_POLICY_INVALID",
        )
    document = parsed
    try:
        schema = load_json_strict(DEFAULT_RELEASE_POLICY_SCHEMA)
        _validate_schema(document, schema)
    except EvidenceValidationError as exc:
        raise EvidenceValidationError(
            "release policy failed its strict schema",
            code="RELEASE_POLICY_INVALID",
        ) from exc
    expected_limits = {
        "max_snapshot_age_seconds": int(MAX_SNAPSHOT_AGE.total_seconds()),
        "max_database_age_seconds": int(MAX_DATABASE_AGE.total_seconds()),
        "max_scan_duration_seconds": int(MAX_SCAN_DURATION.total_seconds()),
        "max_future_skew_seconds": int(MAX_FUTURE_SKEW.total_seconds()),
    }
    if any(document[key] != value for key, value in expected_limits.items()):
        raise EvidenceValidationError(
            "release policy freshness limits are unsupported",
            code="RELEASE_POLICY_INVALID",
        )
    return document


def _validate_policy_binding(report: dict[str, Any], policy: dict[str, Any]) -> None:
    expected_source = policy["expected_source"]
    source = report["source"]
    if any(source[key] != expected_source[key] for key in expected_source):
        raise EvidenceValidationError(
            "evidence source revision differs from release policy",
            code="SOURCE_REVISION_MISMATCH",
        )
    try:
        observed_commit = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        observed_tree = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceValidationError(
            "release verifier could not observe the repository revision",
            code="SOURCE_REVISION_MISMATCH",
        ) from exc
    if source["commit_sha"] != observed_commit or source["tree_sha"] != observed_tree:
        raise EvidenceValidationError(
            "evidence source revision differs from the checked-out repository",
            code="SOURCE_REVISION_MISMATCH",
        )
    if (
        report["build_input_provenance"]["aggregate_sha256"]
        != policy["expected_build_input_sha256"]
    ):
        raise EvidenceValidationError(
            "evidence build inputs differ from release policy",
            code="BUILD_INPUT_MISMATCH",
        )
    expected_subject = policy["expected_subject"]
    subject = report["subject"]
    if any(subject[key] != expected_subject[key] for key in expected_subject):
        raise EvidenceValidationError(
            "evidence subject differs from release policy",
            code="SUBJECT_MISMATCH",
        )
    observed_raw_artifacts = {
        item["path"]: {
            "media_type": item["media_type"],
            "sha256": item["sha256"],
            "bytes": item["bytes"],
        }
        for item in report["raw_artifact_set"]
    }
    if observed_raw_artifacts != policy["expected_raw_artifacts"]:
        raise EvidenceValidationError(
            "evidence raw-artifact identities differ from release policy",
            code="ARTIFACT_SET_MISMATCH",
        )
    if report["vulnerability_database"] != policy["expected_database"]:
        raise EvidenceValidationError(
            "vulnerability database identity differs from release policy",
            code="RELEASE_BINDING_INVALID",
        )
    if report["evidence_set_id"] != policy["expected_evidence_set_id"]:
        raise EvidenceValidationError(
            "evidence-set identifier differs from release policy",
            code="RELEASE_BINDING_INVALID",
        )


def _validate_release_freshness(
    report: dict[str, Any], policy: dict[str, Any], *, now: datetime | None
) -> None:
    timestamps = _validate_timestamp_order(report)
    observed_now = _normalise_now(now)
    future_limit = observed_now + timedelta(seconds=policy["max_future_skew_seconds"])
    future_checked = (
        "collected_at",
        "scan.started_at",
        "scan.completed_at",
        "database.updated_at",
        "database.downloaded_at",
        "database.refresh.started_at",
        "database.refresh.completed_at",
    )
    if any(timestamps[label] > future_limit for label in future_checked):
        raise EvidenceValidationError(
            "evidence timestamp is beyond the allowed future clock skew",
            code="CLOCK_SKEW_FUTURE",
        )
    scan_duration = timestamps["scan.completed_at"] - timestamps["scan.started_at"]
    if scan_duration > timedelta(seconds=policy["max_scan_duration_seconds"]):
        raise EvidenceValidationError(
            "scan duration exceeds the release policy",
            code="TIMESTAMP_ORDER_INVALID",
        )
    if report["vulnerability_database"]["refresh"]["status"] != "SUCCEEDED":
        raise EvidenceValidationError(
            "vulnerability database refresh did not succeed",
            code="DATABASE_REFRESH_FAILED",
        )
    snapshot_age = observed_now - timestamps["scan.completed_at"]
    if snapshot_age > timedelta(seconds=policy["max_snapshot_age_seconds"]):
        raise EvidenceValidationError(
            "scan snapshot exceeds the release maximum age",
            code="SNAPSHOT_EXPIRED",
        )
    database_age = observed_now - timestamps["database.updated_at"]
    if database_age > timedelta(seconds=policy["max_database_age_seconds"]):
        raise EvidenceValidationError(
            "vulnerability database exceeds the release maximum age",
            code="DATABASE_EXPIRED",
        )
    if observed_now >= timestamps["database.next_update"]:
        raise EvidenceValidationError(
            "vulnerability database has reached its declared refresh time",
            code="DATABASE_REFRESH_DUE",
        )


def _validate_common(
    evidence_path: Path = DEFAULT_EVIDENCE,
    *,
    expect_stale_build_inputs: bool = False,
    require_current_build_inputs: bool = False,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], bool]:
    evidence_path = evidence_path.resolve()
    report = load_json_strict(evidence_path)
    schema = load_json_strict(DEFAULT_SCHEMA)
    _validate_schema(report, schema)
    build_inputs_current = _validate_build_input_provenance(
        report,
        expect_stale_build_inputs=expect_stale_build_inputs,
        require_current=require_current_build_inputs,
    )

    dockerfile = (ROOT / "deploy/tool-service/Dockerfile").read_text(encoding="utf-8")
    expected_from = f"FROM {report['scope']['base_image']}\n"
    if build_inputs_current and not dockerfile.startswith(expected_from):
        raise EvidenceValidationError(
            "Dockerfile base image differs from the evidence",
            code="BUILD_INPUT_MISMATCH",
        )

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
        raise EvidenceValidationError(
            "vulnerability database timestamps are inconsistent",
            code="TIMESTAMP_ORDER_INVALID",
        )
    if tuple(report["limitations"]) != EXPECTED_LIMITATIONS:
        raise EvidenceValidationError("limitations were weakened or rewritten")

    _validate_no_public_leakage(evidence_path.name, evidence_path.read_bytes(), report)
    if report["schema_version"] == CURRENT_SCHEMA_VERSION:
        _validate_release_binding(report)
        _validate_timestamp_order(report)
    return report, documents, build_inputs_current


def verify(
    evidence_path: Path = DEFAULT_EVIDENCE,
    *,
    mode: ValidationMode = "consistency",
    release_policy: Path | Mapping[str, Any] | None = None,
    release_policy_sha256: str | None = None,
    now: datetime | None = None,
    expect_stale_build_inputs: bool | None = None,
) -> VerificationResult:
    """Verify historical consistency or current release eligibility.

    ``now`` is deliberately a library-only dependency-injection seam. The production CLI always
    obtains the current UTC clock and exposes no rollback flag.
    """

    if mode not in {"consistency", "release"}:
        raise EvidenceValidationError("unsupported verification mode")
    evidence_path = evidence_path.resolve()
    report_header = load_json_strict(evidence_path)
    schema_version = report_header.get("schema_version")
    if mode == "release" and schema_version == HISTORICAL_SCHEMA_VERSION:
        raise EvidenceValidationError(
            "v1.1 is a historical consistency schema and is not release eligible",
            code="HISTORICAL_SCHEMA_NOT_RELEASE_ELIGIBLE",
        )
    historical = schema_version == HISTORICAL_SCHEMA_VERSION
    if expect_stale_build_inputs is not None and expect_stale_build_inputs != historical:
        raise EvidenceValidationError(
            "historical build-input expectation conflicts with the evidence schema"
        )
    policy = (
        _load_release_policy(
            release_policy,
            expected_policy_sha256=release_policy_sha256,
        )
        if mode == "release" and schema_version == CURRENT_SCHEMA_VERSION
        else None
    )
    report, _documents, build_inputs_current = _validate_common(
        evidence_path,
        expect_stale_build_inputs=historical,
        require_current_build_inputs=mode == "release",
    )
    if mode == "consistency":
        status = (
            "HISTORICAL_CONSISTENT_STALE"
            if historical
            else (
                "CONSISTENT_CURRENT_BUILD_INPUTS_NOT_RELEASE_EVALUATED"
                if build_inputs_current
                else "CONSISTENT_STALE"
            )
        )
        return VerificationResult(
            mode=mode,
            schema_version=report["schema_version"],
            evidence_set_id=report.get("evidence_set_id"),
            release_eligible=False,
            status=status,
        )
    if report["schema_version"] != CURRENT_SCHEMA_VERSION:
        raise EvidenceValidationError(
            "release mode requires v1.2 evidence",
            code="HISTORICAL_SCHEMA_NOT_RELEASE_ELIGIBLE",
        )
    assert policy is not None
    _validate_policy_binding(report, policy)
    _validate_release_freshness(report, policy, now=now)
    counts = report["summary"]["vulnerability_records"]
    if counts["HIGH"] or counts["CRITICAL"]:
        raise EvidenceValidationError(
            "release policy rejected recomputed HIGH or CRITICAL findings",
            code="RELEASE_BLOCKED_FINDINGS",
        )
    return VerificationResult(
        mode=mode,
        schema_version=report["schema_version"],
        evidence_set_id=report["evidence_set_id"],
        release_eligible=True,
        status="RELEASE_ELIGIBLE",
    )


def validate(
    evidence_path: Path = DEFAULT_EVIDENCE,
    *,
    mode: ValidationMode = "consistency",
    release_policy: Path | Mapping[str, Any] | None = None,
    release_policy_sha256: str | None = None,
    now: datetime | None = None,
    release_gate: bool = False,
    expect_stale_build_inputs: bool | None = None,
) -> None:
    """Compatibility wrapper that raises on failure and discards the structured result."""

    if release_gate:
        if mode != "consistency":
            raise EvidenceValidationError("release mode was selected more than once")
        mode = "release"
    verify(
        evidence_path,
        mode=mode,
        release_policy=release_policy,
        release_policy_sha256=release_policy_sha256,
        now=now,
        expect_stale_build_inputs=expect_stale_build_inputs,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument(
        "--mode",
        choices=("consistency", "release"),
        default="consistency",
        help="validate historical/internal consistency or evaluate release eligibility",
    )
    parser.add_argument(
        "--release-policy",
        type=Path,
        help="strict external binding and freshness policy required by release mode",
    )
    parser.add_argument(
        "--release-policy-sha256",
        help=(
            "independently supplied sha256:<64hex> of the exact policy file; required with a "
            "path-based release policy"
        ),
    )
    parser.add_argument(
        "--expect-stale-build-inputs",
        action="store_true",
        help=("deprecated compatibility assertion for the committed v1.1 historical snapshot"),
    )
    arguments = parser.parse_args()
    try:
        result = verify(
            arguments.evidence,
            mode=arguments.mode,
            release_policy=arguments.release_policy,
            release_policy_sha256=arguments.release_policy_sha256,
            expect_stale_build_inputs=(True if arguments.expect_stale_build_inputs else None),
        )
    except EvidenceValidationError as exc:
        print(
            json.dumps(
                {
                    "code": exc.code,
                    "message": str(exc),
                    "release_eligible": False,
                    "valid": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({**result.to_dict(), "valid": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
