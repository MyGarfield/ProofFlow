#!/usr/bin/env python3
"""Build wheel/sdist candidates from an immutable, explicitly bound source snapshot."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SUPPLY_CHAIN_VALIDATOR = ROOT / "deploy/tool-service/scripts/validate_supply_chain_evidence.py"
OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SOURCE_TOP_LEVEL_FILES = ("LICENSE", "NOTICE", "README.md", "pyproject.toml")
PACKAGE_ROOT = PurePosixPath("src/proofflow")
PACKAGE_DATA_FILES = {
    "src/proofflow/demo_assets/README.md",
    "src/proofflow/demo_assets/case/contract.json",
    "src/proofflow/demo_assets/case/manifest.json",
    "src/proofflow/demo_assets/case/payroll.json",
    "src/proofflow/demo_assets/case/termination_notice.json",
    "src/proofflow/demo_assets/rules/cn_labor_contract_law.catalog.json",
    "src/proofflow/py.typed",
}
SNAPSHOT_DIGEST_FORMAT = "PATH_LENGTH_U64_BE_PATH_BYTES_CONTENT_LENGTH_U64_BE_CONTENT_BYTES_V1"


class DistributionBuildError(RuntimeError):
    """A path-independent failure from the repository-only build coordinator."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message


@dataclass(frozen=True)
class SourceBinding:
    commit: str
    tree: str
    source_date_epoch: int
    worktree_clean_observed: bool


@dataclass(frozen=True)
class SnapshotReceipt:
    kind: str
    sha256: str
    file_count: int


def _run(
    command: list[str],
    *,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd or ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise DistributionBuildError(
            "BUILD_TOOL_FAILED",
            "the local distribution build tool failed",
        )
    return completed.stdout.strip()


def _run_bytes(command: list[str], *, cwd: Path | None = None) -> bytes:
    completed = subprocess.run(
        command,
        cwd=cwd or ROOT,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise DistributionBuildError(
            "BUILD_TOOL_FAILED",
            "the local distribution build tool failed",
        )
    return completed.stdout


def _git(*arguments: str) -> str:
    try:
        return _run(["git", *arguments])
    except DistributionBuildError as exc:
        raise DistributionBuildError(
            "SOURCE_BINDING_UNAVAILABLE",
            "the source Git binding could not be established",
        ) from exc


def _git_bytes(*arguments: str) -> bytes:
    try:
        return _run_bytes(["git", *arguments])
    except DistributionBuildError as exc:
        raise DistributionBuildError(
            "SOURCE_BINDING_UNAVAILABLE",
            "the source Git binding could not be established",
        ) from exc


def _source_binding() -> SourceBinding:
    commit = _git("rev-parse", "--verify", "HEAD^{commit}")
    tree = _git("rev-parse", "--verify", f"{commit}^{{tree}}")
    if not OID_PATTERN.fullmatch(commit) or not OID_PATTERN.fullmatch(tree):
        raise DistributionBuildError(
            "SOURCE_BINDING_UNAVAILABLE",
            "the source Git binding could not be established",
        )
    try:
        timestamp = int(_git("show", "-s", "--format=%ct", commit))
    except ValueError as exc:
        raise DistributionBuildError(
            "SOURCE_BINDING_UNAVAILABLE",
            "the source Git binding could not be established",
        ) from exc
    return SourceBinding(
        commit=commit,
        tree=tree,
        source_date_epoch=timestamp,
        worktree_clean_observed=not _git("status", "--porcelain", "--untracked-files=all"),
    )


def _release_supply_chain_preflight() -> None:
    completed = subprocess.run(
        [sys.executable, str(SUPPLY_CHAIN_VALIDATOR), "--release-gate"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise DistributionBuildError(
            "SUPPLY_CHAIN_RELEASE_GATE_REJECTED",
            "release build rejected because current supply-chain evidence is not valid",
        )


def _is_allowed_source_path(relative_path: str) -> bool:
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return False
    if relative_path in SOURCE_TOP_LEVEL_FILES:
        return True
    if not path.is_relative_to(PACKAGE_ROOT):
        return False
    return path.suffix == ".py" or relative_path in PACKAGE_DATA_FILES


def _read_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DistributionBuildError(
            "SOURCE_INVENTORY_INVALID",
            "the source inventory contains an unavailable or unsafe file",
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DistributionBuildError(
                "SOURCE_INVENTORY_INVALID",
                "the source inventory contains an unavailable or unsafe file",
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise DistributionBuildError(
                "SOURCE_CHANGED_DURING_SNAPSHOT",
                "a source file changed while the immutable snapshot was created",
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _worktree_inventory(root: Path) -> list[tuple[str, bytes]]:
    records: list[tuple[str, bytes]] = []
    for relative_path in SOURCE_TOP_LEVEL_FILES:
        records.append((relative_path, _read_regular_file(root / relative_path)))
    package_directory = root.joinpath(*PACKAGE_ROOT.parts)
    if package_directory.is_symlink() or not package_directory.is_dir():
        raise DistributionBuildError(
            "SOURCE_INVENTORY_INVALID",
            "the source package directory is missing or unsafe",
        )
    for candidate in sorted(package_directory.rglob("*")):
        relative = candidate.relative_to(root)
        if "__pycache__" in relative.parts or candidate.suffix in {".pyc", ".pyo"}:
            continue
        if candidate.is_symlink():
            raise DistributionBuildError(
                "SOURCE_INVENTORY_INVALID",
                "the source inventory contains an unavailable or unsafe file",
            )
        if candidate.is_dir():
            continue
        relative_path = relative.as_posix()
        if not _is_allowed_source_path(relative_path):
            raise DistributionBuildError(
                "SOURCE_INVENTORY_INVALID",
                "the source inventory contains an unexpected file",
            )
        records.append((relative_path, _read_regular_file(candidate)))
    return sorted(records)


def _git_inventory(commit: str) -> list[tuple[str, bytes]]:
    raw_entries = _git_bytes(
        "ls-tree",
        "-r",
        "-z",
        commit,
        "--",
        *SOURCE_TOP_LEVEL_FILES,
        PACKAGE_ROOT.as_posix(),
    )
    records: list[tuple[str, bytes]] = []
    for raw_entry in raw_entries.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            relative_path = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise DistributionBuildError(
                "SOURCE_INVENTORY_INVALID",
                "the committed source inventory is malformed",
            ) from exc
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or not OID_PATTERN.fullmatch(object_id)
            or not _is_allowed_source_path(relative_path)
        ):
            raise DistributionBuildError(
                "SOURCE_INVENTORY_INVALID",
                "the committed source inventory contains an unsafe or unexpected entry",
            )
        records.append((relative_path, _git_bytes("cat-file", "blob", object_id)))
    present = {relative_path for relative_path, _payload in records}
    if not set(SOURCE_TOP_LEVEL_FILES) <= present or not any(
        relative_path.endswith(".py") for relative_path in present
    ):
        raise DistributionBuildError(
            "SOURCE_INVENTORY_INVALID",
            "the committed source inventory is incomplete",
        )
    return sorted(records)


def _write_snapshot(snapshot_root: Path, records: list[tuple[str, bytes]]) -> None:
    for relative_path, payload in records:
        destination = snapshot_root.joinpath(*PurePosixPath(relative_path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("xb") as handle:
                handle.write(payload)
        except OSError as exc:
            raise DistributionBuildError(
                "SOURCE_SNAPSHOT_WRITE_FAILED",
                "the private source snapshot could not be written",
            ) from exc


def _snapshot_receipt(snapshot_root: Path, kind: str) -> SnapshotReceipt:
    records = _worktree_inventory(snapshot_root)
    digest = hashlib.sha256()
    for relative_path, payload in records:
        encoded_path = relative_path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, byteorder="big"))
        digest.update(encoded_path)
        digest.update(len(payload).to_bytes(8, byteorder="big"))
        digest.update(payload)
    return SnapshotReceipt(
        kind=kind,
        sha256=f"sha256:{digest.hexdigest()}",
        file_count=len(records),
    )


def _project_metadata(snapshot_root: Path) -> dict[str, str]:
    document = tomllib.loads((snapshot_root / "pyproject.toml").read_text(encoding="utf-8"))
    name = document["project"]["name"]
    version = document["project"]["version"]
    if not isinstance(name, str) or not isinstance(version, str):
        raise DistributionBuildError(
            "PROJECT_METADATA_INVALID",
            "the snapshotted project name or version is invalid",
        )
    return {"name": name, "version": version}


def _measure_artifact(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_file(path)
    return (
        {
            "bytes": len(payload),
            "filename": path.name,
            "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        },
        payload,
    )


def _source_record_map(records: list[tuple[str, bytes]]) -> dict[str, bytes]:
    mapped = dict(records)
    if len(mapped) != len(records):
        raise DistributionBuildError(
            "SOURCE_INVENTORY_INVALID",
            "the source inventory contains duplicate paths",
        )
    return mapped


def _validate_sdist_sources(payload: bytes, source_records: list[tuple[str, bytes]]) -> None:
    expected = _source_record_map(source_records)
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            roots = {
                PurePosixPath(member.name).parts[0]
                for member in members
                if PurePosixPath(member.name).parts
            }
            if len(roots) != 1:
                raise DistributionBuildError(
                    "BUILD_SOURCE_BINDING_MISMATCH",
                    "the source distribution does not have one closed package root",
                )
            actual: dict[str, bytes] = {}
            for member in members:
                member_path = PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or member.issym()
                    or member.islnk()
                ):
                    raise DistributionBuildError(
                        "BUILD_SOURCE_BINDING_MISMATCH",
                        "the source distribution contains an unsafe entry",
                    )
                if member.isdir():
                    continue
                if not member.isfile() or len(member_path.parts) < 2:
                    raise DistributionBuildError(
                        "BUILD_SOURCE_BINDING_MISMATCH",
                        "the source distribution contains an unexpected entry",
                    )
                relative_path = PurePosixPath(*member_path.parts[1:]).as_posix()
                extracted = archive.extractfile(member)
                if extracted is None or relative_path in actual:
                    raise DistributionBuildError(
                        "BUILD_SOURCE_BINDING_MISMATCH",
                        "the source distribution contains duplicate or unreadable data",
                    )
                actual[relative_path] = extracted.read()
    except (OSError, tarfile.TarError) as exc:
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the source distribution cannot be verified against its snapshot",
        ) from exc
    if set(actual) != set(expected) | {"PKG-INFO"} or any(
        actual[relative_path] != payload for relative_path, payload in expected.items()
    ):
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the source distribution differs from its immutable source snapshot",
        )


def _validate_wheel_sources(
    payload: bytes,
    source_records: list[tuple[str, bytes]],
    package: dict[str, str],
) -> None:
    source_map = _source_record_map(source_records)
    expected_package_entries = {
        PurePosixPath(*PurePosixPath(relative_path).parts[1:]).as_posix(): payload
        for relative_path, payload in source_records
        if PurePosixPath(relative_path).is_relative_to(PACKAGE_ROOT)
    }
    normalized_name = re.sub(r"[-_.]+", "_", package["name"])
    normalized_version = package["version"].replace("-", "_")
    if not re.fullmatch(r"[A-Za-z0-9_]+", normalized_name) or not re.fullmatch(
        r"[A-Za-z0-9_.]+", normalized_version
    ):
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel identity cannot be normalized safely",
        )
    dist_info = f"{normalized_name}-{normalized_version}.dist-info"
    metadata_path = f"{dist_info}/METADATA"
    wheel_path = f"{dist_info}/WHEEL"
    entry_points_path = f"{dist_info}/entry_points.txt"
    license_path = f"{dist_info}/licenses/LICENSE"
    notice_path = f"{dist_info}/licenses/NOTICE"
    record_path = f"{dist_info}/RECORD"
    expected_members = set(expected_package_entries) | {
        metadata_path,
        wheel_path,
        entry_points_path,
        license_path,
        notice_path,
        record_path,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise DistributionBuildError(
                    "BUILD_SOURCE_BINDING_MISMATCH",
                    "the wheel contains duplicate paths",
                )
            for info in infos:
                member = PurePosixPath(info.filename)
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if (
                    member.is_absolute()
                    or ".." in member.parts
                    or "." in member.parts
                    or "\\" in info.filename
                    or not info.filename
                    or info.filename.endswith("/")
                    or (unix_mode and stat.S_ISLNK(unix_mode))
                ):
                    raise DistributionBuildError(
                        "BUILD_SOURCE_BINDING_MISMATCH",
                        "the wheel contains an unsafe path or member type",
                    )
            if set(names) != expected_members or names[-1] != record_path:
                raise DistributionBuildError(
                    "BUILD_SOURCE_BINDING_MISMATCH",
                    "the wheel member inventory is not the exact release contract",
                )
            actual = {name: archive.read(name) for name in names}
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel cannot be verified against its snapshot",
        ) from exc

    if {name: actual[name] for name in expected_package_entries} != expected_package_entries:
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel differs from its immutable source snapshot",
        )
    if actual[license_path] != source_map["LICENSE"] or actual[notice_path] != source_map["NOTICE"]:
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel license payload differs from its source snapshot",
        )

    project = tomllib.loads(source_map["pyproject.toml"].decode("utf-8"))["project"]
    if project.get("dependencies") != ["cryptography>=46,<47", "pydantic>=2.11,<3"]:
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the snapshotted dependency contract is unexpected",
        )
    metadata_bytes = actual[metadata_path]
    _metadata_headers, metadata_separator, metadata_body = metadata_bytes.partition(b"\n\n")
    metadata = BytesParser(policy=policy.default).parsebytes(metadata_bytes)
    authors = project.get("authors")
    expected_author = authors[0].get("name") if isinstance(authors, list) and authors else None
    if (
        metadata.get("Metadata-Version") != "2.5"
        or metadata.get("Name") != package["name"]
        or metadata.get("Version") != package["version"]
        or metadata.get("Summary") != project.get("description")
        or metadata.get("Author") != expected_author
        or metadata.get("License") != "Apache-2.0"
        or metadata.get("Requires-Python") != "<3.15,>=3.12"
        or metadata.get_all("Requires-Dist") != ["cryptography<47,>=46", "pydantic<3,>=2.11"]
        or metadata.get_all("License-File") != ["LICENSE", "NOTICE"]
        or metadata.get("Description-Content-Type") != "text/markdown"
        or metadata_separator != b"\n\n"
        or metadata_body != source_map["README.md"]
    ):
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel METADATA contract is invalid",
        )

    wheel_metadata = BytesParser(policy=policy.default).parsebytes(actual[wheel_path])
    generator = wheel_metadata.get("Generator")
    if (
        wheel_metadata.get("Wheel-Version") != "1.0"
        or not isinstance(generator, str)
        or not generator.startswith("hatchling ")
        or wheel_metadata.get("Root-Is-Purelib") != "true"
        or wheel_metadata.get_all("Tag") != ["py3-none-any"]
    ):
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel compatibility metadata contract is invalid",
        )
    scripts = project.get("scripts")
    if not isinstance(scripts, dict) or any(
        not isinstance(name, str) or not isinstance(target, str) for name, target in scripts.items()
    ):
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the snapshotted entry-point contract is invalid",
        )
    expected_entry_points = "[console_scripts]\n" + "".join(
        f"{name} = {target}\n" for name, target in sorted(scripts.items())
    )
    if actual[entry_points_path] != expected_entry_points.encode("utf-8"):
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel entry-point contract is invalid",
        )

    try:
        record_text = actual[record_path].decode("utf-8")
        record_rows = list(csv.reader(io.StringIO(record_text, newline=""), strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel RECORD is not canonical UTF-8 CSV",
        ) from exc
    canonical_record = io.StringIO(newline="")
    csv.writer(canonical_record, lineterminator="\n").writerows(record_rows)
    if (
        canonical_record.getvalue() != record_text
        or any(len(row) != 3 for row in record_rows)
        or [row[0] for row in record_rows] != names
    ):
        raise DistributionBuildError(
            "BUILD_SOURCE_BINDING_MISMATCH",
            "the wheel RECORD is not the canonical member closure",
        )
    for member_path, declared_hash, declared_size in record_rows:
        if member_path == record_path:
            if declared_hash or declared_size:
                raise DistributionBuildError(
                    "BUILD_SOURCE_BINDING_MISMATCH",
                    "the wheel RECORD self-entry must omit hash and size",
                )
            continue
        member_payload = actual[member_path]
        encoded_digest = base64.urlsafe_b64encode(hashlib.sha256(member_payload).digest()).rstrip(
            b"="
        )
        if declared_hash != f"sha256={encoded_digest.decode('ascii')}" or declared_size != str(
            len(member_payload)
        ):
            raise DistributionBuildError(
                "BUILD_SOURCE_BINDING_MISMATCH",
                "the wheel RECORD hash or size does not match a member",
            )


def _validate_artifact_source_bindings(
    measured_artifacts: list[tuple[dict[str, Any], bytes]],
    source_records: list[tuple[str, bytes]],
    package: dict[str, str],
) -> None:
    for record, payload in measured_artifacts:
        filename = record["filename"]
        if filename.endswith(".whl"):
            _validate_wheel_sources(payload, source_records, package)
        elif filename.endswith(".tar.gz"):
            _validate_sdist_sources(payload, source_records)
        else:  # pragma: no cover - the caller enforces the closed artifact set.
            raise DistributionBuildError(
                "BUILD_ARTIFACT_SET_INVALID",
                "the build produced an unsupported artifact",
            )


def _prepare_output_directory(output_dir: Path) -> None:
    if output_dir.exists():
        if output_dir.is_symlink() or not output_dir.is_dir() or any(output_dir.iterdir()):
            raise DistributionBuildError(
                "BUILD_OUTPUT_NOT_EMPTY",
                "the distribution output target must be a new or empty directory",
            )
        return
    try:
        output_dir.mkdir(parents=True, mode=0o700)
    except OSError as exc:
        raise DistributionBuildError(
            "BUILD_OUTPUT_UNAVAILABLE",
            "the distribution output directory cannot be created",
        ) from exc


def _publish_file(output_dir: Path, filename: str, payload: bytes) -> None:
    destination = output_dir / filename
    try:
        with destination.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise DistributionBuildError(
            "BUILD_ARTIFACT_PUBLISH_FAILED",
            "a built artifact could not be published without overwriting a file",
        ) from exc


def build_distribution(output_dir: Path, *, release: bool) -> dict[str, Any]:
    binding = _source_binding()
    if release:
        _release_supply_chain_preflight()
        if not binding.worktree_clean_observed:
            raise DistributionBuildError(
                "SOURCE_TREE_DIRTY",
                "release build requires a clean source tree",
            )
    _prepare_output_directory(output_dir)

    with tempfile.TemporaryDirectory(prefix="proofflow-distribution-") as temporary:
        temporary_root = Path(temporary)
        temporary_root.chmod(0o700)
        snapshot_root = temporary_root / "source"
        snapshot_root.mkdir(mode=0o700)
        artifact_staging = temporary_root / "artifacts"
        artifact_staging.mkdir(mode=0o700)

        if binding.worktree_clean_observed:
            snapshot_kind = "GIT_COMMIT_TREE"
            source_records = _git_inventory(binding.commit)
        else:
            snapshot_kind = "WORKTREE_COPY"
            source_records = _worktree_inventory(ROOT)
        _write_snapshot(snapshot_root, source_records)
        before = _snapshot_receipt(snapshot_root, snapshot_kind)
        package = _project_metadata(snapshot_root)

        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = str(binding.source_date_epoch)
        _run(
            [
                "uv",
                "build",
                "--no-config",
                "--out-dir",
                str(artifact_staging),
                str(snapshot_root),
            ],
            environment=environment,
            cwd=snapshot_root,
        )
        after = _snapshot_receipt(snapshot_root, snapshot_kind)
        if after != before:
            raise DistributionBuildError(
                "SOURCE_SNAPSHOT_CHANGED_DURING_BUILD",
                "the private source snapshot changed during the build",
            )

        artifact_paths = sorted(
            (
                candidate
                for candidate in artifact_staging.iterdir()
                if candidate.is_file()
                and (candidate.name.endswith(".whl") or candidate.name.endswith(".tar.gz"))
            ),
            key=lambda path: path.name,
        )
        if (
            len(artifact_paths) != 2
            or sum(path.name.endswith(".whl") for path in artifact_paths) != 1
        ):
            raise DistributionBuildError(
                "BUILD_ARTIFACT_SET_INVALID",
                "the build did not produce exactly one wheel and one source distribution",
            )
        measured_artifacts = [_measure_artifact(path) for path in artifact_paths]
        _validate_artifact_source_bindings(measured_artifacts, source_records, package)

        worktree_clean_after_build = not _git("status", "--porcelain", "--untracked-files=all")
        if release and not worktree_clean_after_build:
            raise DistributionBuildError(
                "SOURCE_TREE_CHANGED_DURING_BUILD",
                "release build rejected because the live source tree changed during the build",
            )
        exact_commit_binding = snapshot_kind == "GIT_COMMIT_TREE"
        manifest: dict[str, Any] = {
            "schema_version": "proofflow.distribution/v1alpha2",
            "status": "RELEASE_GATE_PASSED" if release else "LOCAL_CANDIDATE_NOT_RELEASE_READY",
            "package": package,
            "source": {
                "base_git_commit": binding.commit,
                "base_git_tree": binding.tree,
                "source_date_epoch": binding.source_date_epoch,
                "snapshot_kind": snapshot_kind,
                "snapshot_digest_format": SNAPSHOT_DIGEST_FORMAT,
                "snapshot_sha256": before.sha256,
                "snapshot_file_count": before.file_count,
                "snapshot_stable_during_build": True,
                "exact_commit_binding": exact_commit_binding,
                "worktree_clean_observed_before_snapshot": binding.worktree_clean_observed,
                "worktree_clean_observed_after_build": worktree_clean_after_build,
            },
            "supply_chain_release_gate": "PASSED" if release else "NOT_RUN",
            "artifacts": [record for record, _payload in measured_artifacts],
        }
        for record, payload in measured_artifacts:
            _publish_file(output_dir, record["filename"], payload)
        _publish_file(
            output_dir,
            "artifact-manifest.json",
            (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )
        return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--release",
        action="store_true",
        help="require fresh supply-chain evidence and a clean exact-commit source binding",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        manifest = build_distribution(arguments.output, release=arguments.release)
    except DistributionBuildError as exc:
        print(
            json.dumps(
                {"error": {"code": exc.code, "message": exc.safe_message}},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
