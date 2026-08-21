"""Reproducible GOAI semifinal package builder and submission gate.

This module deliberately treats the portal as an external, mutable system.  It
only builds and verifies a local candidate artifact; it never submits anything,
creates a portal receipt, or makes an eligibility/selection claim.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Literal

MAX_ZIP_BYTES = 1200 * 1024 * 1024
MAX_CUMULATIVE_BYTES = 3600 * 1024 * 1024
MANIFEST_NAME = "SEMIFINAL_SUBMISSION_MANIFEST.json"
REPORT_SUFFIX = ".report.json"
Status = Literal["CANDIDATE_NOT_SUBMIT_READY", "PRE_SUBMIT_READY", "SUBMITTED_RECEIPT_VERIFIED"]
STATUS_CANDIDATE: Status = "CANDIDATE_NOT_SUBMIT_READY"
STATUS_READY: Status = "PRE_SUBMIT_READY"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PUBLIC_URL_RE = re.compile(r"^https://[^/\s]+(?:/[^\s]*)?$")
_SECRET_RE = re.compile(
    rb"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"(?:api[_-]?key|secret|access[_-]?token|private[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{16,})",
    re.IGNORECASE,
)
_PII_RE = re.compile(
    rb"(?:\b[0-9]{17}[0-9Xx]\b|\b1[3-9][0-9]{9}\b|"
    rb"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)",
    re.IGNORECASE,
)
_FORBIDDEN_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
    "private",
}
_FORBIDDEN_NAMES = {".env", ".env.local", ".env.production", "credentials.json"}


class SubmissionBuildError(ValueError):
    """Raised for malformed configuration or unsafe package inputs."""


@dataclass(frozen=True)
class Artifact:
    path: str
    category: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class GateReport:
    status: Status
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _reject_constant(value: str) -> None:
    raise SubmissionBuildError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SubmissionBuildError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _strict_load_json(text: str, *, source: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, SubmissionBuildError) as exc:
        raise SubmissionBuildError(f"invalid strict JSON in {source}: {exc}") from exc


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = _strict_load_json(path.read_text(encoding="utf-8"), source=str(path))
    except (OSError, SubmissionBuildError) as exc:
        raise SubmissionBuildError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise SubmissionBuildError("submission config must be a JSON object")
    return config


def _require_string(config: dict[str, Any], key: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SubmissionBuildError(f"config.{key} is required")
    return value


def _safe_relative_path(raw: Any, *, field: str) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise SubmissionBuildError(f"{field} must be a non-empty POSIX relative path")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise SubmissionBuildError(f"{field} escapes the repository: {raw!r}")
    if any(part in _FORBIDDEN_PARTS or part in _FORBIDDEN_NAMES for part in path.parts):
        raise SubmissionBuildError(f"{field} names a private/cache path: {raw!r}")
    return path.as_posix()


def _validate_public_url(
    value: Any, *, key: str, required: bool, allow_query: bool = False
) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SubmissionBuildError(f"config.{key} must be a public HTTPS URL")
    if not _PUBLIC_URL_RE.fullmatch(value) or any(
        token in value for token in ("@", "localhost", "127.0.0.1")
    ):
        raise SubmissionBuildError(f"config.{key} must be a public HTTPS URL without credentials")
    if ("?" in value or "#" in value) and not allow_query:
        raise SubmissionBuildError(f"config.{key} may not contain query/fragment credentials")
    return value


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SubmissionBuildError(f"git verification failed: {exc}") from exc
    return result.stdout


def _assert_clean_git(root: Path) -> str:
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status.strip():
        raise SubmissionBuildError(
            "worktree is not clean; refusing untracked/modified drift:\n" + status.strip()
        )
    commit = _git(root, "rev-parse", "HEAD").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SubmissionBuildError("git HEAD is not a full commit id")
    return commit


def _assert_tracked(root: Path, relative: str) -> None:
    try:
        _git(root, "ls-files", "--error-unmatch", "--", relative)
    except SubmissionBuildError as exc:
        raise SubmissionBuildError(f"allowlisted path is not tracked: {relative}") from exc


def _scan_bytes(relative: str, data: bytes) -> None:
    # Office files are ZIP containers and may contain arbitrary binary bytes;
    # scanning them for short PII patterns creates false positives.  Secrets,
    # however, are rejected for every file type.
    if _SECRET_RE.search(data):
        raise SubmissionBuildError(f"secret-like material detected in {relative}")
    if Path(relative).suffix.lower() == ".pptx":
        try:
            with zipfile.ZipFile(BytesIO(data)) as office:
                total = 0
                for member in office.infolist():
                    if member.is_dir():
                        continue
                    total += member.file_size
                    if total > 32 * 1024 * 1024 or len(member.filename) > 512:
                        raise SubmissionBuildError(f"office scan limit exceeded in {relative}")
                    member_data = office.read(member)
                    if _SECRET_RE.search(member_data) or _PII_RE.search(member_data):
                        raise SubmissionBuildError(
                            f"secret/PII-like material detected in {relative}"
                        )
        except zipfile.BadZipFile as exc:
            raise SubmissionBuildError(f"invalid office container: {relative}") from exc
    if Path(relative).suffix.lower() not in {
        ".pdf",
        ".pptx",
        ".zip",
        ".png",
        ".jpg",
        ".jpeg",
    } and _PII_RE.search(data):
        raise SubmissionBuildError(f"PII-like material detected in {relative}")


def _validate_context_mapping(config: dict[str, Any]) -> dict[str, Any]:
    mapping = config.get("context_mapping")
    if not isinstance(mapping, dict):
        raise SubmissionBuildError("config.context_mapping is required")
    options = mapping.get("options")
    selected = mapping.get("selected")
    allowed_options = {"rag", "agent_memory", "shared_state", "trajectory_observability"}
    if (
        not isinstance(options, list)
        or len(options) != 4
        or len(set(options)) != 4
        or set(options) != allowed_options
    ):
        raise SubmissionBuildError(
            "context_mapping.options must be RAG, Agent memory, shared state, "
            "trajectory/trace observability"
        )
    if not isinstance(selected, list) or len(selected) != 2 or len(set(selected)) != 2:
        raise SubmissionBuildError("context_mapping.selected must choose exactly two options")
    if not set(selected).issubset(options):
        raise SubmissionBuildError("context_mapping.selected must be drawn from options")
    if not {"shared_state", "trajectory_observability"}.issubset(selected):
        raise SubmissionBuildError(
            "ProofFlow must select shared_state and trajectory_observability"
        )
    evidence_paths = mapping.get("evidence_paths")
    if not isinstance(evidence_paths, list) or not evidence_paths:
        raise SubmissionBuildError("context_mapping.evidence_paths is required")
    evidence_digests = mapping.get("evidence_digests")
    if not isinstance(evidence_digests, dict):
        raise SubmissionBuildError("context_mapping.evidence_digests is required")
    for path, digest in evidence_digests.items():
        _safe_relative_path(path, field="context_mapping.evidence_digests")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise SubmissionBuildError(f"invalid context evidence digest for {path}")
    if set(evidence_paths) != set(evidence_digests):
        raise SubmissionBuildError("context evidence paths and digests must match exactly")
    return {
        "options": options,
        "selected": selected,
        "evidence_paths": evidence_paths,
        "evidence_digests": evidence_digests,
    }


def _required_artifact_paths(config: dict[str, Any]) -> dict[str, list[str]]:
    raw = config.get("required_artifacts")
    if not isinstance(raw, dict):
        raise SubmissionBuildError("config.required_artifacts is required")
    normalized: dict[str, list[str]] = {}
    for category, values in raw.items():
        if not isinstance(category, str) or not isinstance(values, list):
            raise SubmissionBuildError(f"required_artifacts.{category!r} must be a non-empty list")
        if not values and category not in {
            "agent_collaboration_evidence",
            "eligibility_evidence",
            "demo_offline_fallback",
        }:
            raise SubmissionBuildError(f"required_artifacts.{category!r} must be a non-empty list")
        normalized[category] = [
            _safe_relative_path(value, field=f"required_artifacts.{category}") for value in values
        ]
    for category in (
        "deck_pptx",
        "deck_pdf",
        "identity",
        "skill",
        "runtime_entry",
        "dependencies",
        "examples",
        "evidence",
        "disclosure",
        "license",
    ):
        if category not in normalized:
            raise SubmissionBuildError(f"required_artifacts.{category} is required")
    return normalized


def _validate_gate_evidence(config: dict[str, Any]) -> dict[str, Any]:
    evidence = config.get("gate_evidence")
    if not isinstance(evidence, dict):
        raise SubmissionBuildError("config.gate_evidence is required")
    for key in ("eligibility", "real_agent_collaboration"):
        item = evidence.get(key)
        if not isinstance(item, dict):
            raise SubmissionBuildError(f"config.gate_evidence.{key} is required")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list):
            raise SubmissionBuildError(f"config.gate_evidence.{key}.evidence_refs is required")
        for ref in refs:
            if not isinstance(ref, dict):
                raise SubmissionBuildError(f"invalid {key} evidence ref")
            _safe_relative_path(ref.get("path"), field=f"gate_evidence.{key}.path")
            digest = ref.get("sha256")
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                raise SubmissionBuildError(f"invalid {key} evidence digest")
    recheck = evidence.get("official_config_recheck")
    if not isinstance(recheck, dict):
        raise SubmissionBuildError("config.gate_evidence.official_config_recheck is required")
    observed_at = recheck.get("observed_at")
    if observed_at is not None:
        if not isinstance(observed_at, str):
            raise SubmissionBuildError("official config observed_at must be RFC3339")
        try:
            parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SubmissionBuildError("official config observed_at must be RFC3339") from exc
        if parsed.tzinfo is None:
            raise SubmissionBuildError("official config observed_at must carry an offset")
    max_age = recheck.get("max_age_hours", 24)
    if not isinstance(max_age, int) or not 0 < max_age <= 24:
        raise SubmissionBuildError("official config max_age_hours must be between 1 and 24")
    return evidence


def _normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    _require_string(config, "schema_version")
    _require_string(config, "project")
    _require_string(config, "track")
    _validate_public_url(config.get("repository_url"), key="repository_url", required=True)
    _validate_public_url(config.get("demo_url"), key="demo_url", required=False)
    allowlist = config.get("allowlist")
    if not isinstance(allowlist, list) or not allowlist:
        raise SubmissionBuildError("config.allowlist must be a non-empty explicit file list")
    normalized_allowlist = [_safe_relative_path(item, field="allowlist") for item in allowlist]
    if len(set(normalized_allowlist)) != len(normalized_allowlist):
        raise SubmissionBuildError("config.allowlist contains duplicates")
    required = _required_artifact_paths(config)
    missing_allowlist = sorted(
        {path for paths in required.values() for path in paths} - set(normalized_allowlist)
    )
    if missing_allowlist:
        raise SubmissionBuildError(
            "required artifacts are not in allowlist: " + ", ".join(missing_allowlist)
        )
    official = config.get("official")
    if not isinstance(official, dict):
        raise SubmissionBuildError("config.official is required")
    for key in ("track_url", "handbook_url", "site_config_url", "submission_url"):
        _validate_public_url(
            official.get(key), key=f"official.{key}", required=True, allow_query=True
        )
    context = _validate_context_mapping(config)
    gate_evidence = _validate_gate_evidence(config)
    return {
        **config,
        "allowlist": normalized_allowlist,
        "required_artifacts": required,
        "context_mapping": context,
        "gate_evidence": gate_evidence,
        "repository_url": config["repository_url"],
        "demo_url": config.get("demo_url"),
    }


def _assert_safe_file(root: Path, relative: str) -> Path:
    root_resolved = root.resolve()
    candidate = root / relative
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise SubmissionBuildError(f"symlink/path escape is not allowed: {relative}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root_resolved):
        raise SubmissionBuildError(f"path escape is not allowed: {relative}")
    if not resolved.is_file():
        raise SubmissionBuildError(f"allowlisted path is not a regular file: {relative}")
    return resolved


def _collect_artifacts(root: Path, config: dict[str, Any]) -> tuple[Artifact, ...]:
    artifacts: list[Artifact] = []
    for relative in config["allowlist"]:
        source = _assert_safe_file(root, relative)
        _assert_tracked(root, relative)
        data = source.read_bytes()
        _scan_bytes(relative, data)
        category = (
            next(
                category
                for category, paths in config["required_artifacts"].items()
                if relative in paths
            )
            if any(relative in paths for paths in config["required_artifacts"].values())
            else "supporting"
        )
        artifacts.append(Artifact(relative, category, len(data), sha256_bytes(data)))
    return tuple(sorted(artifacts, key=lambda item: item.path))


def _verify_refs(refs: list[dict[str, str]], artifacts: tuple[Artifact, ...]) -> bool:
    inventory = {item.path: item.sha256 for item in artifacts}
    return bool(refs) and all(
        ref.get("path") in inventory and inventory[ref["path"]] == ref.get("sha256") for ref in refs
    )


def _validate_evidence_content(
    root: Path, refs: list[dict[str, str]], expected_type: str, expected_status: str
) -> bool:
    for ref in refs:
        try:
            payload = _strict_load_json(
                (root / ref["path"]).read_text(encoding="utf-8"), source=ref["path"]
            )
        except (OSError, UnicodeDecodeError, SubmissionBuildError):
            return False
        if not isinstance(payload, dict):
            return False
        if (
            payload.get("evidence_type") != expected_type
            or payload.get("status") != expected_status
        ):
            return False
        if not isinstance(payload.get("schema_version"), str):
            return False
    return True


def _gate(
    root: Path, config: dict[str, Any], artifacts: tuple[Artifact, ...], mode: str
) -> GateReport:
    if mode not in {"candidate", "submit-ready"}:
        raise SubmissionBuildError("mode must be candidate or submit-ready")
    reasons: list[str] = []
    warnings: list[str] = []
    if not config.get("demo_url"):
        reasons.append("demo_url_missing")
    eligibility_refs = config["gate_evidence"]["eligibility"]["evidence_refs"]
    eligibility_valid = _verify_refs(eligibility_refs, artifacts) and _validate_evidence_content(
        root, eligibility_refs, "eligibility", "UNLOCKED"
    )
    if config.get("eligibility_unlocked") is not True or not eligibility_valid:
        reasons.append("eligibility_not_unlocked")
    collaboration = config["gate_evidence"]["real_agent_collaboration"]
    counts = collaboration.get("counts")
    required_counts = (
        "worker_execution",
        "task_event",
        "matrix_event",
        "mcp_receipt",
        "skill_receipt",
        "trace",
        "human_gate_receipt",
    )
    counts_valid = isinstance(counts, dict) and all(
        isinstance(counts.get(key), int) and counts[key] >= 1 for key in required_counts
    )
    collaboration_refs = collaboration["evidence_refs"]
    collaboration_valid = _verify_refs(
        collaboration_refs, artifacts
    ) and _validate_evidence_content(root, collaboration_refs, "agent_collaboration_v2", "VERIFIED")
    if (
        config.get("real_agent_collaboration_evidence") is not True
        or not counts_valid
        or not collaboration_valid
    ):
        reasons.append("real_agent_collaboration_evidence_missing")
    recheck = config["gate_evidence"]["official_config_recheck"]
    observed_at = recheck.get("observed_at")
    recheck_valid = False
    if isinstance(observed_at, str):
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        recheck_valid = (
            parsed.tzinfo is not None
            and parsed <= datetime.now(UTC)
            and (datetime.now(UTC) - parsed).total_seconds() <= recheck["max_age_hours"] * 3600
        )
    if config.get("official_config_rechecked") is not True or not recheck_valid:
        reasons.append("official_dynamic_config_not_rechecked")
    artifact_paths = {item.path for item in artifacts}
    if not any(item.category == "agent_collaboration_evidence" for item in artifacts):
        reasons.append("agent_collaboration_evidence_artifact_missing")
    context_digests = config["context_mapping"]["evidence_digests"]
    context_refs = [{"path": path, "sha256": digest} for path, digest in context_digests.items()]
    if not _verify_refs(context_refs, artifacts):
        reasons.append("context_evidence_digest_mismatch")
    for category, paths in config["required_artifacts"].items():
        missing = [path for path in paths if path not in artifact_paths]
        if missing:
            reasons.append(f"required_{category}_missing")
    if mode == "candidate":
        warnings.append("candidate mode never authorizes portal submission")
    status: Status = STATUS_CANDIDATE
    if mode == "submit-ready" and not reasons:
        status = STATUS_READY
    return GateReport(status=status, reasons=tuple(sorted(set(reasons))), warnings=tuple(warnings))


def build_manifest(
    *,
    root: Path,
    config: dict[str, Any],
    artifacts: tuple[Artifact, ...],
    gate: GateReport,
    source_commit: str,
) -> dict[str, Any]:
    inventory = [
        {
            "path": item.path,
            "category": item.category,
            "size_bytes": item.size_bytes,
            "sha256": item.sha256,
        }
        for item in artifacts
    ]
    return {
        "schema_version": "proofflow.goai.semifinal.manifest/v1",
        "manifest_type": "single_semifinal_zip",
        "artifact_status": gate.status,
        "project": config["project"],
        "track": config["track"],
        "source_commit": source_commit,
        "repository_url": config["repository_url"],
        "demo_url": config.get("demo_url"),
        "official": config["official"],
        "submission_fields": ["作品名", "代码仓库URL", "Demo URL", "ZIP"],
        "limits": {
            "zip_max_bytes": MAX_ZIP_BYTES,
            "cumulative_max_bytes": MAX_CUMULATIVE_BYTES,
            "max_attempts_per_stage": 3,
        },
        "required_components": config["required_artifacts"],
        "context_mapping": config["context_mapping"],
        "gate_evidence": config["gate_evidence"],
        "gate": gate.as_dict(),
        "artifact_inventory": inventory,
        "portal_receipt": None,
        "selection_claim": False,
        "integrity": {
            "algorithm": "SHA-256",
            "subject_binding_sha256": sha256_bytes(
                _canonical_json({"artifact_inventory": inventory, "gate": gate.as_dict()})
            ),
            "attestation": "NOT_PROVIDED",
            "signature": "NOT_PROVIDED",
        },
        "build": {
            "tool": "scripts.semifinal_submission",
            "reproducible": True,
            "timestamp": None,
            "source_root": ".",
        },
    }


def _write_deterministic_zip(
    root: Path, output: Path, artifacts: tuple[Artifact, ...], manifest: dict[str, Any]
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_bytes = _canonical_json(manifest)
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True
    ) as archive:
        entries = [(item.path, (root / item.path).read_bytes()) for item in artifacts]
        entries.append((MANIFEST_NAME, manifest_bytes))
        for path, data in sorted(entries, key=lambda pair: pair[0]):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 & 0xFFFF) << 16
            info.flag_bits = 0x800
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def build_package(
    *, config_path: Path, output: Path, mode: str = "candidate", report_path: Path | None = None
) -> dict[str, Any]:
    root = config_path.resolve().parents[2]
    if not (root / ".git").exists():
        raise SubmissionBuildError(f"config must be inside a git worktree: {config_path}")
    config = _normalize_config(load_config(config_path))
    source_commit = _assert_clean_git(root)
    artifacts = _collect_artifacts(root, config)
    gate = _gate(root, config, artifacts, mode)
    manifest = build_manifest(
        root=root, config=config, artifacts=artifacts, gate=gate, source_commit=source_commit
    )
    _write_deterministic_zip(root, output, artifacts, manifest)
    zip_size = output.stat().st_size
    if zip_size > MAX_ZIP_BYTES:
        output.unlink(missing_ok=True)
        raise SubmissionBuildError(f"ZIP exceeds 1200 MiB limit: {zip_size} bytes")
    report = {
        "schema_version": "proofflow.goai.semifinal.build-report/v1",
        "artifact_status": gate.status,
        "zip_path": output.name,
        "zip_size_bytes": zip_size,
        "zip_sha256": sha256_file(output),
        "manifest_sha256": sha256_bytes(_canonical_json(manifest)),
        "source_commit": source_commit,
        "gate": gate.as_dict(),
        "portal_receipt": None,
        "selection_claim": False,
    }
    if report_path is None:
        report_path = output.with_name(output.name + REPORT_SUFFIX)
    report_path.write_bytes(_canonical_json(report))
    return report


def validate_manifest(path: Path) -> list[str]:
    """Validate a generated manifest using the checked-in JSON Schema."""
    try:
        from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - development dependency is pinned
        raise SubmissionBuildError(
            "jsonschema is required to validate a submission manifest"
        ) from exc
    schema_path = (
        Path(__file__).resolve().parents[1] / "schemas/semifinal-submission-manifest.schema.json"
    )
    schema = _strict_load_json(schema_path.read_text(encoding="utf-8"), source=str(schema_path))
    manifest = _strict_load_json(path.read_text(encoding="utf-8"), source=str(path))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(manifest),
        key=lambda error: list(error.path),
    )
    messages = [
        f"{'.'.join(str(part) for part in error.path)}: {error.message}" for error in errors
    ]
    if isinstance(manifest, dict):
        inventory = manifest.get("artifact_inventory")
        if isinstance(inventory, list):
            paths = [item.get("path") for item in inventory if isinstance(item, dict)]
            if len(paths) != len(set(paths)):
                messages.append("artifact_inventory: duplicate paths")
            inventory_by_path = {
                item.get("path"): item for item in inventory if isinstance(item, dict)
            }
            for item in inventory:
                if not isinstance(item, dict) or not isinstance(item.get("size_bytes"), int):
                    messages.append("artifact_inventory: invalid size")
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("sha256"), str)
                    or not _SHA256_RE.fullmatch(item.get("sha256", ""))
                ):
                    messages.append("artifact_inventory: invalid sha256")
            required = manifest.get("required_components")
            if isinstance(required, dict):
                for category, required_paths in required.items():
                    if not isinstance(required_paths, list):
                        messages.append(f"required_components.{category}: must be an array")
                    elif any(path not in inventory_by_path for path in required_paths):
                        messages.append(f"required_components.{category}: inventory path missing")
            integrity = manifest.get("integrity")
            gate = manifest.get("gate")
            if isinstance(integrity, dict) and isinstance(gate, dict):
                expected_binding = sha256_bytes(
                    _canonical_json({"artifact_inventory": inventory, "gate": gate})
                )
                if integrity.get("subject_binding_sha256") != expected_binding:
                    messages.append("integrity: subject binding digest mismatch")
        status = manifest.get("artifact_status")
        receipt = manifest.get("portal_receipt")
        if status == "SUBMITTED_RECEIPT_VERIFIED" and receipt is None:
            messages.append("portal_receipt: required for SUBMITTED_RECEIPT_VERIFIED")
        if status != "SUBMITTED_RECEIPT_VERIFIED" and receipt is not None:
            messages.append("portal_receipt: must be null before submission")
    return messages


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Build a deterministic ProofFlow semifinal ZIP")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("candidate", "submit-ready"), default="candidate")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_package(
            config_path=args.config, output=args.output, mode=args.mode, report_path=args.report
        )
    except SubmissionBuildError as exc:
        print(f"error: {exc}")
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["artifact_status"] == STATUS_READY else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
