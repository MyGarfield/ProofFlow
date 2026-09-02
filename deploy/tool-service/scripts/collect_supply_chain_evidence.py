#!/usr/bin/env python3
"""Collect point-in-time SBOM and vulnerability evidence for the pinned tool image.

The scanners never receive the Docker socket. The target is exported with
``docker image save`` and then scanned as a read-only archive. Trivy's only
networked phase downloads its vulnerability database without mounting the target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT = ROOT / "deploy/tool-service/evidence"
LOGGER = logging.getLogger(__name__)

TARGET_TAG = "proofflow-tool-service:0.1.0a1"
BASE_IMAGE_REFERENCE = (
    "python:3.12-alpine@sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb"
)

SYFT_VERSION = "1.51.0"
SYFT_IMAGE_INDEX_DIGEST = "sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0"
SYFT_AMD64_MANIFEST_DIGEST = (
    "sha256:41f8289664101d6ebab30a97ac8df6b6f86b92d8343285ca90f428e2bc353106"
)
SYFT_IMAGE = f"anchore/syft@{SYFT_IMAGE_INDEX_DIGEST}"

TRIVY_VERSION = "0.74.0"
TRIVY_IMAGE_INDEX_DIGEST = "sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
TRIVY_AMD64_MANIFEST_DIGEST = (
    "sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9"
)
TRIVY_IMAGE = f"aquasec/trivy@{TRIVY_IMAGE_INDEX_DIGEST}"

SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
ARTIFACT_NAMES = {
    "cyclonedx": "sbom.cyclonedx.json",
    "spdx": "sbom.spdx.json",
    "trivy": "vulnerabilities.trivy.json",
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


class CollectionError(RuntimeError):
    """Raised when a collection precondition or scanner contract fails."""


def run(arguments: list[str], *, timeout: int = 900) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace")[-4000:]
        raise CollectionError(
            f"command failed ({exc.returncode}): {arguments[0]}: {stderr}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CollectionError(f"command timed out after {timeout}s: {arguments[0]}") from exc


def _reject_json_constant(value: str) -> None:
    del value
    raise CollectionError("non-finite JSON numbers are not allowed")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError("duplicate JSON object keys are not allowed")
        result[key] = value
    return result


def load_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectionError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CollectionError(f"{label} root must be an object")
    return value


def sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def canonical_sha256(value: dict[str, Any]) -> str:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CollectionError("release binding contains a non-canonical value") from exc
    return sha256_bytes(payload)


def _is_generated_python_cache(relative_path: Path) -> bool:
    return "__pycache__" in relative_path.parts or relative_path.suffix in {".pyc", ".pyo"}


def _directory_input_files(relative_directory: str) -> list[Path]:
    directory = ROOT / relative_directory
    if not directory.is_dir() or directory.is_symlink():
        raise CollectionError(f"build input directory is missing or unsafe: {relative_directory}")
    files: list[Path] = []
    for candidate in directory.rglob("*"):
        relative_path = candidate.relative_to(directory)
        if _is_generated_python_cache(relative_path):
            continue
        if candidate.is_symlink():
            raise CollectionError(f"build input symlink is not allowed: {candidate}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise CollectionError(f"build input is not a regular file: {candidate}")
        if relative_directory == "src":
            allowed = candidate.suffix == ".py" or relative_path.as_posix() in (
                EXPECTED_SRC_DATA_FILES
            )
        else:
            allowed = candidate.suffix == ".json"
        if not allowed:
            raise CollectionError(f"unexpected build input file: {candidate}")
        files.append(candidate)
    if not files:
        raise CollectionError(f"build input directory is empty: {relative_directory}")
    return sorted(files, key=lambda item: item.relative_to(directory).as_posix())


def build_input_provenance() -> dict[str, Any]:
    inputs: list[dict[str, Any]] = []
    for relative_path in BUILD_INPUT_FILES:
        source = ROOT / relative_path
        if not source.is_file() or source.is_symlink():
            raise CollectionError(f"build input file is missing or unsafe: {relative_path}")
        payload = source.read_bytes()
        inputs.append(
            {
                "path": relative_path,
                "kind": "FILE_BYTES",
                "sha256": sha256_bytes(payload),
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
        inputs.append(
            {
                "path": relative_directory,
                "kind": "DIRECTORY_BUNDLE_V1",
                "sha256": f"sha256:{digest.hexdigest()}",
                "bytes": total_bytes,
                "file_count": len(files),
            }
        )
    provenance: dict[str, Any] = {
        "claim_level": "UNSIGNED_LOCAL_BUILD_INPUT_DIGEST_SNAPSHOT",
        "hash_algorithm": "SHA-256",
        "directory_bundle_format": DIRECTORY_BUNDLE_FORMAT,
        "hashes_are_digital_signatures": False,
        "build_relationship_attested": False,
        "inputs": inputs,
    }
    provenance["aggregate_sha256"] = canonical_sha256(provenance)
    return provenance


def source_revision() -> dict[str, Any]:
    git = ["git", "-C", str(ROOT)]
    commit_sha = run([*git, "rev-parse", "HEAD"], timeout=30).stdout.decode("ascii").strip()
    tree_sha = run([*git, "rev-parse", "HEAD^{tree}"], timeout=30).stdout.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha) or not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
        raise CollectionError("Git returned an invalid source revision")
    working_tree_status = run([*git, "status", "--porcelain"], timeout=30).stdout
    if working_tree_status.strip():
        raise CollectionError("working tree must be clean before evidence collection")
    return {
        "repository": "https://github.com/MyGarfield/ProofFlow",
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "working_tree_clean": True,
    }


def docker_image_metadata(target_tag: str) -> dict[str, Any]:
    template = "{{.Id}}\t{{.Os}}\t{{.Architecture}}\t{{.Created}}\t{{json .RepoDigests}}"
    output = run(["docker", "image", "inspect", "--format", template, target_tag]).stdout
    fields = output.decode("utf-8").strip().split("\t", maxsplit=4)
    if len(fields) != 5:
        raise CollectionError("unexpected docker image inspect output")
    image_id, operating_system, architecture, created_at, repo_digests_json = fields
    repo_digests = json.loads(repo_digests_json)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise CollectionError("target image ID is not an immutable SHA-256 digest")
    if (operating_system, architecture) != ("linux", "amd64"):
        raise CollectionError(
            "unsupported scan platform: expected linux/amd64, observed "
            f"{operating_system}/{architecture}"
        )
    repository = target_tag.rsplit(":", maxsplit=1)[0]
    immutable_reference = f"{repository}@{image_id}"
    if repo_digests and immutable_reference not in repo_digests:
        raise CollectionError("target tag RepoDigests conflict with the observed image ID")
    return {
        "tag": target_tag,
        "immutable_reference": immutable_reference,
        "image_id": image_id,
        "platform": f"{operating_system}/{architecture}",
        "created_at": created_at,
    }


def docker_archive_config_digest(path: Path) -> str:
    with tarfile.open(path, mode="r") as archive:
        try:
            manifest_member = archive.getmember("manifest.json")
        except KeyError as exc:
            raise CollectionError("Docker archive omitted manifest.json") from exc
        if manifest_member.size > 1024 * 1024:
            raise CollectionError("Docker archive manifest is unexpectedly large")
        manifest_stream = archive.extractfile(manifest_member)
        if manifest_stream is None:
            raise CollectionError("Docker archive manifest is not a regular file")
        try:
            manifest = json.loads(manifest_stream.read(), parse_constant=_reject_json_constant)
        except json.JSONDecodeError as exc:
            raise CollectionError("Docker archive manifest is invalid JSON") from exc
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise CollectionError("Docker archive must contain exactly one image manifest")
        config_path = manifest[0].get("Config") if isinstance(manifest[0], dict) else None
        match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", config_path or "")
        if match is None:
            raise CollectionError("Docker archive config path is not content-addressed")
        config_member = archive.getmember(config_path)
        config_stream = archive.extractfile(config_member)
        if config_stream is None:
            raise CollectionError("Docker archive image config is not a regular file")
        config_payload = config_stream.read()
        observed = hashlib.sha256(config_payload).hexdigest()
        if observed != match.group(1):
            raise CollectionError("Docker archive image config digest mismatch")
        return f"sha256:{observed}"


def scanner_run(
    image: str,
    arguments: list[str],
    *,
    workdir: Path | None = None,
    cache_volume: str | None = None,
    network: str = "none",
) -> bytes:
    command = ["docker", "run", "--rm", "--network", network]
    if workdir is not None:
        command.extend(
            [
                "--workdir",
                "/work",
                "--mount",
                f"type=bind,src={workdir},dst=/work,readonly",
            ]
        )
    if cache_volume is not None:
        command.extend(
            [
                "--mount",
                f"type=volume,src={cache_volume},dst=/root/.cache/trivy",
            ]
        )
    command.extend([image, *arguments])
    return run(command).stdout


@contextmanager
def temporary_docker_volume() -> Iterator[str]:
    name = f"proofflow-trivy-evidence-{os.getpid()}"
    created = run(["docker", "volume", "create", name]).stdout.decode("utf-8").strip()
    if created != name:
        raise CollectionError("Docker returned an unexpected temporary volume name")
    try:
        yield name
    finally:
        cleanup = subprocess.run(
            ["docker", "volume", "rm", name],
            check=False,
            capture_output=True,
            timeout=30,
        )
        if cleanup.returncode != 0:
            raise CollectionError("failed to remove the temporary Trivy cache volume")


def database_identity(cache_volume: str) -> tuple[str, int]:
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--mount",
        f"type=volume,src={cache_volume},dst=/root/.cache/trivy",
        "--entrypoint",
        "/bin/sh",
        TRIVY_IMAGE,
        "-c",
        (
            "set -eu; "
            "sha256sum /root/.cache/trivy/db/trivy.db; "
            "wc -c < /root/.cache/trivy/db/trivy.db"
        ),
    ]
    lines = run(command).stdout.decode("ascii").splitlines()
    if len(lines) != 2:
        raise CollectionError("unexpected Trivy database identity output")
    digest = lines[0].split(maxsplit=1)[0]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CollectionError("invalid Trivy database digest output")
    try:
        size = int(lines[1].strip())
    except ValueError as exc:
        raise CollectionError("invalid Trivy database size output") from exc
    if size < 1:
        raise CollectionError("Trivy database must not be empty")
    return f"sha256:{digest}", size


def count_vulnerabilities(
    report: dict[str, Any],
) -> tuple[dict[str, int], list[dict[str, Any]], list[dict[str, Any]]]:
    counts: Counter[str] = Counter()
    targets: list[dict[str, Any]] = []
    high_or_critical: list[dict[str, Any]] = []
    results = report.get("Results")
    if not isinstance(results, list):
        raise CollectionError("Trivy report has no Results array")
    for result in results:
        if not isinstance(result, dict):
            raise CollectionError("Trivy result must be an object")
        target_counts: Counter[str] = Counter()
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise CollectionError("Trivy Vulnerabilities must be an array or null")
        for vulnerability in vulnerabilities:
            severity = vulnerability.get("Severity", "UNKNOWN")
            if severity not in SEVERITIES:
                raise CollectionError(f"unexpected Trivy severity: {severity}")
            counts[severity] += 1
            target_counts[severity] += 1
            if severity in {"HIGH", "CRITICAL"}:
                high_or_critical.append(
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
        sorted(
            high_or_critical,
            key=lambda item: (
                item["severity"],
                item["vulnerability_id"],
                item["package_name"],
            ),
        ),
    )


def artifact_record(path: Path, *, media_type: str, record_count: int) -> dict[str, Any]:
    payload = path.read_bytes()
    return {
        "path": path.name,
        "media_type": media_type,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
        "record_count": record_count,
    }


def write_atomic(path: Path, payload: bytes) -> None:
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _collect_into(
    output_dir: Path,
    *,
    target_tag: str,
    source: dict[str, Any],
    scan_started_at: datetime,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=False)
    subject = docker_image_metadata(target_tag)

    # The AgentTeams Docker daemon runs in a VM that shares the repository's
    # /Users path but not macOS's /var/folders default temporary directory.
    with (
        tempfile.TemporaryDirectory(prefix=".proofflow-supply-chain-", dir=ROOT) as directory,
        temporary_docker_volume() as cache_volume,
    ):
        workdir = Path(directory)
        os.chmod(workdir, 0o755)
        archive = workdir / "target.tar"
        run(["docker", "image", "save", "--output", str(archive), subject["image_id"]])
        archive.chmod(0o644)
        subject["image_config_digest"] = docker_archive_config_digest(archive)

        syft_version_raw = scanner_run(SYFT_IMAGE, ["version", "-o", "json"])
        syft_version = load_json_bytes(syft_version_raw, "Syft version")
        if syft_version.get("version") != SYFT_VERSION:
            raise CollectionError("pinned Syft image returned an unexpected version")
        if syft_version.get("platform") != "linux/amd64":
            raise CollectionError("pinned Syft image returned an unexpected platform")

        cyclonedx_raw = scanner_run(
            SYFT_IMAGE,
            [
                "scan",
                "docker-archive:target.tar",
                "--scope",
                "squashed",
                "-o",
                "cyclonedx-json",
                "-q",
            ],
            workdir=workdir,
        )
        spdx_raw = scanner_run(
            SYFT_IMAGE,
            ["scan", "docker-archive:target.tar", "--scope", "squashed", "-o", "spdx-json", "-q"],
            workdir=workdir,
        )
        cyclonedx = load_json_bytes(cyclonedx_raw, "CycloneDX SBOM")
        spdx = load_json_bytes(spdx_raw, "SPDX SBOM")

        refresh_started_at = datetime.now(UTC)
        scanner_run(
            TRIVY_IMAGE,
            ["image", "--download-db-only", "--cache-dir", "/root/.cache/trivy", "--quiet"],
            cache_volume=cache_volume,
            network="bridge",
        )
        refresh_completed_at = datetime.now(UTC)
        trivy_version_raw = scanner_run(
            TRIVY_IMAGE,
            ["version", "--format", "json"],
            cache_volume=cache_volume,
        )
        trivy_version = load_json_bytes(trivy_version_raw, "Trivy version")
        if trivy_version.get("Version") != TRIVY_VERSION:
            raise CollectionError("pinned Trivy image returned an unexpected version")

        database_hash_before_scan, database_size = database_identity(cache_volume)

        trivy_raw = scanner_run(
            TRIVY_IMAGE,
            [
                "image",
                "--input",
                "target.tar",
                "--scanners",
                "vuln",
                "--severity",
                ",".join(SEVERITIES),
                "--offline-scan",
                "--skip-db-update",
                "--cache-dir",
                "/root/.cache/trivy",
                "--timeout",
                "10m",
                "--format",
                "json",
                "--quiet",
            ],
            workdir=workdir,
            cache_volume=cache_volume,
        )
        trivy = load_json_bytes(trivy_raw, "Trivy vulnerability report")

        database_hash_after_scan, database_size_after_scan = database_identity(cache_volume)
        if (database_hash_after_scan, database_size_after_scan) != (
            database_hash_before_scan,
            database_size,
        ):
            raise CollectionError("Trivy database changed during the network-disabled target scan")
        database = trivy_version.get("VulnerabilityDB")
        if not isinstance(database, dict):
            raise CollectionError("Trivy version output omitted VulnerabilityDB metadata")

        raw_by_name = {
            ARTIFACT_NAMES["cyclonedx"]: cyclonedx_raw,
            ARTIFACT_NAMES["spdx"]: spdx_raw,
            ARTIFACT_NAMES["trivy"]: trivy_raw,
        }
        for filename, payload in raw_by_name.items():
            write_atomic(output_dir / filename, payload)

        vulnerability_counts, findings_by_target, high_or_critical_findings = count_vulnerabilities(
            trivy
        )
        cyclonedx_components = cyclonedx.get("components") or []
        spdx_packages = spdx.get("packages") or []
        if not isinstance(cyclonedx_components, list) or not isinstance(spdx_packages, list):
            raise CollectionError("SBOM package collections must be arrays")

        artifacts = [
            artifact_record(
                output_dir / ARTIFACT_NAMES["cyclonedx"],
                media_type="application/vnd.cyclonedx+json",
                record_count=len(cyclonedx_components),
            ),
            artifact_record(
                output_dir / ARTIFACT_NAMES["spdx"],
                media_type="application/spdx+json",
                record_count=len(spdx_packages),
            ),
            artifact_record(
                output_dir / ARTIFACT_NAMES["trivy"],
                media_type="application/vnd.aquasec.trivy.report+json",
                record_count=sum(vulnerability_counts.values()),
            ),
        ]

        high_or_critical = vulnerability_counts["HIGH"] + vulnerability_counts["CRITICAL"]
        scan_completed_at = datetime.now(UTC)
        report: dict[str, Any] = {
            "schema_version": "1.2.0",
            "collected_at": scan_completed_at.isoformat().replace("+00:00", "Z"),
            "claim_level": "POINT_IN_TIME_PACKAGE_VULNERABILITY_SCAN",
            "scan": {
                "started_at": scan_started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": scan_completed_at.isoformat().replace("+00:00", "Z"),
            },
            "source": source,
            "subject": subject,
            "build_input_provenance": build_input_provenance(),
            "scope": {
                "acquisition": "DOCKER_IMAGE_SAVE",
                "scanner_target": "READ_ONLY_IMAGE_ARCHIVE",
                "target_archive_published": False,
                "runtime_container_inspected": False,
                "runtime_environment_inspected": False,
                "scanner_network_during_target_analysis": "NONE",
                "scanners": ["OS_PACKAGES", "LANGUAGE_PACKAGES", "KNOWN_VULNERABILITIES"],
                "base_image": BASE_IMAGE_REFERENCE,
            },
            "tools": {
                "syft": {
                    "version": SYFT_VERSION,
                    "release_url": "https://github.com/anchore/syft/releases/tag/v1.51.0",
                    "image": SYFT_IMAGE,
                    "image_index_digest": SYFT_IMAGE_INDEX_DIGEST,
                    "platform_manifest_digest": SYFT_AMD64_MANIFEST_DIGEST,
                    "platform": syft_version["platform"],
                    "git_commit": syft_version["gitCommit"],
                    "build_date": syft_version["buildDate"],
                },
                "trivy": {
                    "version": TRIVY_VERSION,
                    "release_url": "https://github.com/aquasecurity/trivy/releases/tag/v0.74.0",
                    "image": TRIVY_IMAGE,
                    "image_index_digest": TRIVY_IMAGE_INDEX_DIGEST,
                    "platform_manifest_digest": TRIVY_AMD64_MANIFEST_DIGEST,
                    "platform": "linux/amd64",
                },
            },
            "vulnerability_database": {
                "schema_version": database.get("Version"),
                "updated_at": database.get("UpdatedAt"),
                "next_update": database.get("NextUpdate"),
                "downloaded_at": database.get("DownloadedAt"),
                "sha256": database_hash_before_scan,
                "bytes": database_size,
                "refresh": {
                    "status": "SUCCEEDED",
                    "started_at": refresh_started_at.isoformat().replace("+00:00", "Z"),
                    "completed_at": refresh_completed_at.isoformat().replace("+00:00", "Z"),
                    "network_scope": "VULNERABILITY_DATABASE_ONLY",
                },
            },
            "artifacts": artifacts,
            "summary": {
                "cyclonedx_components": len(cyclonedx_components),
                "spdx_packages": len(spdx_packages),
                "vulnerability_records": vulnerability_counts,
                "total_vulnerability_records": sum(vulnerability_counts.values()),
                "findings_by_target": findings_by_target,
                "high_or_critical_findings": high_or_critical_findings,
                "verdict": (
                    "HIGH_OR_CRITICAL_FOUND" if high_or_critical else "NO_HIGH_OR_CRITICAL_FOUND"
                ),
            },
            "reproducibility": {
                "collector": "deploy/tool-service/scripts/collect_supply_chain_evidence.py",
                "validator": "deploy/tool-service/scripts/validate_supply_chain_evidence.py",
                "schema": "deploy/tool-service/evidence/supply-chain-evidence.schema.json",
                "tool_images_pinned_by_digest": True,
                "subject_pinned_by_digest": True,
                "database_bytes_pinned_by_hash": True,
            },
            "limitations": [
                "This is a point-in-time scan against one mutable vulnerability database snapshot.",
                (
                    "Scanner and advisory database false positives, false negatives, and "
                    "coverage gaps remain possible."
                ),
                (
                    "The scan covers final-image OS and language packages, not dynamic "
                    "application behavior."
                ),
                (
                    "Runtime configuration, running-container environment, credentials, "
                    "secrets, and network behavior were not inspected."
                ),
                (
                    "Unsigned build-input hashes are not a build attestation or digital "
                    "signature and do not verify deployment or production security."
                ),
                (
                    "No finding at a severity is evidence of scanner non-detection, not proof "
                    "that no vulnerability exists."
                ),
            ],
        }

        report["raw_artifact_set"] = sorted(
            [
                {
                    "path": record["path"],
                    "media_type": record["media_type"],
                    "sha256": record["sha256"],
                    "bytes": record["bytes"],
                }
                for record in artifacts
            ],
            key=lambda record: record["path"],
        )
        bound_fields = [
            "scan",
            "source",
            "build_input_provenance",
            "subject",
            "raw_artifact_set",
            "vulnerability_database",
        ]
        evidence_set_id = canonical_sha256({field: report[field] for field in bound_fields})
        report["evidence_set_id"] = evidence_set_id
        report["release_binding"] = {
            "algorithm": "CANONICAL_JSON_SHA256_V1",
            "bound_fields": bound_fields,
            "evidence_set_id": evidence_set_id,
        }

    report_path = output_dir / "supply-chain-evidence.json"
    write_atomic(
        report_path,
        (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
    )
    return report


def _seed_contract_files(candidate_dir: Path) -> None:
    for source in DEFAULT_OUTPUT.glob("*.schema.json"):
        if not source.is_file() or source.is_symlink():
            raise CollectionError(f"unsafe schema contract file: {source.name}")
        shutil.copy2(source, candidate_dir / source.name)


def _self_validate(candidate_dir: Path) -> None:
    validator = ROOT / "deploy/tool-service/scripts/validate_supply_chain_evidence.py"
    report = candidate_dir / "supply-chain-evidence.json"
    run(
        [sys.executable, str(validator), str(report), "--mode", "consistency"],
        timeout=120,
    )


def _safe_output_path(output_dir: Path) -> Path:
    """Resolve an output path only after rejecting existing symlink components."""

    absolute = Path(os.path.abspath(os.fspath(output_dir)))

    def reject_symlink_components(path: Path) -> None:
        current = Path(path.anchor)
        for component in path.parts[1:]:
            current /= component
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                break
            except OSError as exc:
                raise CollectionError("could not inspect evidence output path") from exc
            if stat.S_ISLNK(mode):
                raise CollectionError("evidence output path must not contain symlinks")

    reject_symlink_components(absolute)
    absolute.parent.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(absolute)
    resolved_parent = absolute.parent.resolve(strict=True)
    if resolved_parent != absolute.parent:
        raise CollectionError("evidence output parent changed during path validation")
    return resolved_parent / absolute.name


def _promote_directory(candidate_dir: Path, output_dir: Path) -> Path | None:
    if output_dir.is_symlink():
        raise CollectionError("evidence output directory must not be a symlink")
    backup: Path | None = None
    if output_dir.exists():
        if not output_dir.is_dir():
            raise CollectionError("evidence output path must be a directory")
        backup = output_dir.parent / f".{output_dir.name}.backup-{uuid.uuid4().hex}"
        os.replace(output_dir, backup)
    try:
        os.replace(candidate_dir, output_dir)
    except BaseException:
        if backup is not None and not output_dir.exists():
            os.replace(backup, output_dir)
        raise
    if backup is not None:
        try:
            shutil.rmtree(backup)
        except OSError as exc:
            with suppress(Exception):
                LOGGER.warning(
                    "validated evidence is live; previous backup retained as %s: %s",
                    backup.name,
                    exc,
                )
            return backup
    return None


def collect(
    output_dir: Path,
    *,
    target_tag: str = TARGET_TAG,
) -> dict[str, Any]:
    """Collect a consistency-only candidate, validate, then promote without partial overwrite."""

    output_dir = _safe_output_path(output_dir)
    source = source_revision()
    scan_started_at = datetime.now(UTC)
    staging_root = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.staging-", dir=output_dir.parent)
    )
    candidate_dir = staging_root / "candidate"
    try:
        report = _collect_into(
            candidate_dir,
            target_tag=target_tag,
            source=source,
            scan_started_at=scan_started_at,
        )
        _seed_contract_files(candidate_dir)
        _self_validate(candidate_dir)
        _promote_directory(candidate_dir, output_dir)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--target-tag", default=TARGET_TAG)
    arguments = parser.parse_args()
    report = collect(
        arguments.output,
        target_tag=arguments.target_tag,
    )
    print(
        json.dumps(
            {
                "image_id": report["subject"]["image_id"],
                "components": report["summary"]["cyclonedx_components"],
                "vulnerabilities": report["summary"]["vulnerability_records"],
                "verdict": report["summary"]["verdict"],
                "release_validation": "NOT_PERFORMED_EXTERNAL_POLICY_REQUIRED",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
