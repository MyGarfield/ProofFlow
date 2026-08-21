"""Reproducible GOAI semifinal package builder and submission gate.

This module deliberately treats the portal as an external, mutable system.  It
only builds and verifies a local candidate artifact; it never submits anything,
creates a portal receipt, or makes an eligibility/selection claim.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit
from xml.etree import ElementTree

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

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
CONFIG_SCHEMA_PATH = SCHEMA_DIR / "semifinal-submission-config.schema.json"
MANIFEST_SCHEMA_PATH = SCHEMA_DIR / "semifinal-submission-manifest.schema.json"
ELIGIBILITY_SCHEMA_PATH = SCHEMA_DIR / "semifinal-eligibility-evidence.schema.json"
OFFICIAL_RECHECK_SCHEMA_PATH = SCHEMA_DIR / "semifinal-official-recheck-evidence.schema.json"
DEMO_ACCESS_SCHEMA_PATH = SCHEMA_DIR / "semifinal-demo-access-evidence.schema.json"
EVALUATION_LEDGER_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "benchmarks/evaluation/run-ledger.schema.json"
)
CONFIG_ARCHIVE_PATH = "submission/semifinal/submission-config.json"
_BASE_TRUST_PATHS = frozenset(
    {
        CONFIG_ARCHIVE_PATH,
        "schemas/semifinal-demo-access-evidence.schema.json",
        "schemas/semifinal-eligibility-evidence.schema.json",
        "schemas/semifinal-official-recheck-evidence.schema.json",
        "schemas/semifinal-submission-config.schema.json",
        "schemas/semifinal-submission-manifest.schema.json",
        "scripts/semifinal_submission.py",
    }
)
_EVALUATION_TRUST_PATHS = frozenset(
    {
        "benchmarks/__init__.py",
        "benchmarks/evaluation/__init__.py",
        "benchmarks/evaluation/fixture.py",
        "benchmarks/evaluation/fixtures/fixture-manifest.schema.json",
        "benchmarks/evaluation/fixtures/manifest.json",
        "benchmarks/evaluation/ledger_verifier.py",
        "benchmarks/evaluation/run-ledger.schema.json",
        "benchmarks/evaluation/scenarios.json",
        "benchmarks/evaluation/scenarios.schema.json",
        "benchmarks/evaluation/worker-run-evidence.schema.json",
    }
)
_EVALUATION_TRUST_ANCHOR = "benchmarks/evaluation/ledger_verifier.py"

_RUNTIME_SOURCE_PATHS = frozenset(
    {
        "src/proofflow/__init__.py",
        "src/proofflow/canonical.py",
        "src/proofflow/cli.py",
        "src/proofflow/contracts.py",
        "src/proofflow/factories.py",
        "src/proofflow/models.py",
        "src/proofflow/py.typed",
        "src/proofflow/reference_runtime.py",
        "src/proofflow/state_machine.py",
        "src/proofflow/strategy.py",
        "src/proofflow/tool_server.py",
        "src/proofflow/trusted_store.py",
        "src/proofflow/skills/__init__.py",
        "src/proofflow/skills/approval.py",
        "src/proofflow/skills/audit.py",
        "src/proofflow/skills/calculation.py",
        "src/proofflow/skills/common.py",
        "src/proofflow/skills/evidence.py",
        "src/proofflow/skills/packaging.py",
        "src/proofflow/skills/rules.py",
    }
)
_FIXED_REQUIRED_PATHS: dict[str, frozenset[str]] = {
    "identity": frozenset({"specs/06_AGENT_IDENTITY.yaml"}),
    "skill_spec": frozenset({"specs/07_SKILL_SPEC.yaml"}),
    "runtime_source": _RUNTIME_SOURCE_PATHS,
    "runtime_entry": frozenset({"pyproject.toml", "src/proofflow/cli.py", "demo/server.py"}),
    "dependencies": frozenset({"pyproject.toml", "uv.lock"}),
    "demo_assets": frozenset(
        {
            "demo/__init__.py",
            "demo/app.js",
            "demo/index.html",
            "demo/server.py",
            "demo/styles.css",
            "scripts/semifinal_extracted_smoke.py",
        }
    ),
    "demo_benchmarks": frozenset(
        {"benchmarks/__init__.py", "benchmarks/scenarios.json", "benchmarks/suite.py"}
    ),
    "examples": frozenset(
        {
            "examples/cases/happy_path/contract.json",
            "examples/cases/happy_path/manifest.json",
            "examples/cases/happy_path/payroll.json",
            "examples/cases/happy_path/termination_notice.json",
        }
    ),
    "agentteams_workers": frozenset({"deploy/agentteams/01-workers-stopped.yaml"}),
    "agentteams_team": frozenset({"deploy/agentteams/02-team.yaml"}),
    "agentteams_humans": frozenset({"deploy/agentteams/03-humans.yaml"}),
    "agentteams_mcp": frozenset(
        {
            "deploy/agentteams/mcp/mcp-proof-calc.yaml",
            "deploy/agentteams/mcp/mcp-proof-evidence.yaml",
            "deploy/agentteams/mcp/mcp-proof-rules.yaml",
        }
    ),
    "agentteams_skills": frozenset(
        {
            "deploy/agentteams/skills/conflict_detect/SKILL.md",
            "deploy/agentteams/skills/decision_audit/SKILL.md",
            "deploy/agentteams/skills/deterministic_calculate/SKILL.md",
            "deploy/agentteams/skills/document_package/SKILL.md",
            "deploy/agentteams/skills/evidence_ingest/SKILL.md",
            "deploy/agentteams/skills/human_approval/SKILL.md",
            "deploy/agentteams/skills/rule_retrieve/SKILL.md",
            "deploy/agentteams/skills/timeline_build/SKILL.md",
        }
    ),
    "tool_service": frozenset(
        {
            "deploy/tool-service/Dockerfile",
            "deploy/tool-service/README.md",
            "deploy/tool-service/requirements.lock",
            "deploy/tool-service/THIRD_PARTY_NOTICES.md",
        }
    ),
    "reproduction_tests": frozenset(
        {
            "tests/benchmark/conftest.py",
            "tests/benchmark/test_public_contract_suite.py",
            "tests/e2e/test_demo_server.py",
        }
    ),
    "rebuild_inputs": frozenset(
        {
            CONFIG_ARCHIVE_PATH,
            "schemas/semifinal-demo-access-evidence.schema.json",
            "schemas/semifinal-eligibility-evidence.schema.json",
            "schemas/semifinal-official-recheck-evidence.schema.json",
            "schemas/semifinal-submission-config.schema.json",
            "schemas/semifinal-submission-manifest.schema.json",
            "scripts/build_semifinal_zip.py",
            "scripts/semifinal_submission.py",
        }
    ),
    "license": frozenset({"LICENSE", "NOTICE"}),
}
_EVIDENCE_CATEGORY_BY_GATE = {
    "eligibility": "eligibility_evidence",
    "official_config_recheck": "official_recheck_evidence",
    "real_agent_collaboration": "agent_collaboration_evidence",
    "demo_access": "demo_access_evidence",
}


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


def _schema_validator_from_bytes(schema_bytes: bytes, *, source: str) -> Any:
    try:
        from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - development dependency is pinned
        raise SubmissionBuildError("jsonschema is required for semifinal validation") from exc
    try:
        schema = _strict_load_json(schema_bytes.decode("utf-8"), source=source)
        Draft202012Validator.check_schema(schema)
    except UnicodeDecodeError as exc:
        raise SubmissionBuildError(f"schema is not UTF-8: {source}") from exc
    except Exception as exc:
        if isinstance(exc, SubmissionBuildError):
            raise
        raise SubmissionBuildError(f"invalid trusted schema {source}: {exc}") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _schema_validator(schema_path: Path) -> Any:
    try:
        schema_bytes = schema_path.read_bytes()
    except OSError as exc:
        raise SubmissionBuildError(f"required schema is unavailable: {schema_path}") from exc
    return _schema_validator_from_bytes(schema_bytes, source=str(schema_path))


def _schema_messages_from_bytes(instance: Any, schema_bytes: bytes, *, source: str) -> list[str]:
    validator = _schema_validator_from_bytes(schema_bytes, source=source)
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    return [
        f"{'.'.join(str(part) for part in error.absolute_path) or '$'}: {error.message}"
        for error in errors
    ]


def _schema_messages(instance: Any, schema_path: Path) -> list[str]:
    try:
        schema_bytes = schema_path.read_bytes()
    except OSError as exc:
        raise SubmissionBuildError(f"required schema is unavailable: {schema_path}") from exc
    return _schema_messages_from_bytes(instance, schema_bytes, source=str(schema_path))


def _validate_schema(instance: Any, schema_path: Path, *, source: str) -> None:
    messages = _schema_messages(instance, schema_path)
    if messages:
        raise SubmissionBuildError(
            f"{source} failed Draft 2020-12 schema validation: " + "; ".join(messages)
        )


def _validate_schema_bytes(
    instance: Any, schema_bytes: bytes, *, schema_source: str, source: str
) -> None:
    messages = _schema_messages_from_bytes(instance, schema_bytes, source=schema_source)
    if messages:
        raise SubmissionBuildError(
            f"{source} failed Draft 2020-12 schema validation: " + "; ".join(messages)
        )


def _load_strict_json_file(path: Path) -> Any:
    try:
        return _strict_load_json(path.read_text(encoding="utf-8"), source=str(path))
    except OSError as exc:
        raise SubmissionBuildError(f"cannot read JSON file {path}: {exc}") from exc


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
    _validate_schema(config, CONFIG_SCHEMA_PATH, source=str(path))
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
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").casefold().rstrip(".")
    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None
    forbidden_hostname = (
        not hostname
        or hostname == "localhost"
        or hostname == "127.0.0.1"
        or hostname.endswith((".localhost", ".local", ".internal", ".invalid", ".test", ".example"))
        or (parsed_ip is not None and not (parsed_ip.is_global and not parsed_ip.is_reserved))
    )
    if (
        not _PUBLIC_URL_RE.fullmatch(value)
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or forbidden_hostname
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


def _git_blob(root: Path, commit: str, relative: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SubmissionBuildError("trusted repository commit must be a full SHA-1")
    _safe_relative_path(relative, field="trusted file")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{relative}"],
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SubmissionBuildError(
            f"trusted Git blob is unavailable at {commit}:{relative}"
        ) from exc
    return result.stdout


def _git_path_exists(root: Path, commit: str, relative: str) -> bool:
    try:
        subprocess.run(
            ["git", "-C", str(root), "cat-file", "-e", f"{commit}:{relative}"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return True


@lru_cache(maxsize=4)
def _git_commit_regular_blobs(
    root_text: str, commit: str, paths: tuple[str, ...]
) -> dict[str, bytes]:
    """Read a commit's exact regular-file payload in one bounded Git operation."""
    root = Path(root_text)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SubmissionBuildError("trusted repository commit must be a full SHA-1")
    for relative in paths:
        _safe_relative_path(relative, field="source-commit artifact")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "archive", "--format=tar", commit, "--", *paths],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SubmissionBuildError("cannot read commit-pinned artifact payloads") from exc
    blobs: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=BytesIO(result.stdout), mode="r:") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                if member.name not in paths or not member.isfile():
                    raise SubmissionBuildError(
                        f"source commit artifact is not a regular file: {member.name}"
                    )
                stream = archive.extractfile(member)
                if stream is None:  # pragma: no cover - guarded by isfile()
                    raise SubmissionBuildError(f"cannot read source commit artifact: {member.name}")
                blobs[member.name] = stream.read()
    except (tarfile.TarError, OSError) as exc:
        raise SubmissionBuildError("invalid Git archive for expected source commit") from exc
    if set(blobs) != set(paths):
        missing = sorted(set(paths) - set(blobs))
        raise SubmissionBuildError(
            "expected source commit does not contain every packaged artifact: " + ", ".join(missing)
        )
    return blobs


def commit_pinned_trust_digests(root: Path, expected_repository_commit: str) -> dict[str, str]:
    """Derive the exact trusted schema/verifier digests from an external Git commit."""
    if not re.fullmatch(r"[0-9a-f]{40}", expected_repository_commit):
        raise SubmissionBuildError("expected_repository_commit must be a full commit id")
    try:
        resolved = _git(root, "rev-parse", "--verify", f"{expected_repository_commit}^{{commit}}")
    except SubmissionBuildError as exc:
        raise SubmissionBuildError(
            "expected repository commit is not present in trusted root"
        ) from exc
    if resolved.strip() != expected_repository_commit:
        raise SubmissionBuildError("trusted root resolved a different repository commit")
    paths = set(_BASE_TRUST_PATHS)
    evaluation_available = _git_path_exists(
        root, expected_repository_commit, _EVALUATION_TRUST_ANCHOR
    )
    if evaluation_available:
        missing = sorted(
            path
            for path in _EVALUATION_TRUST_PATHS
            if not _git_path_exists(root, expected_repository_commit, path)
        )
        if missing:
            raise SubmissionBuildError(
                "trusted evaluation verifier closure is incomplete: " + ", ".join(missing)
            )
        paths.update(_EVALUATION_TRUST_PATHS)
    return {
        path: sha256_bytes(_git_blob(root, expected_repository_commit, path))
        for path in sorted(paths)
    }


def _load_trusted_blobs(
    *,
    trusted_root: Path,
    expected_repository_commit: str,
    trusted_file_digests: Mapping[str, str],
) -> dict[str, bytes]:
    expected_digests = commit_pinned_trust_digests(trusted_root, expected_repository_commit)
    supplied = dict(trusted_file_digests)
    if supplied != expected_digests:
        raise SubmissionBuildError(
            "caller-supplied trusted schema/verifier digests do not match the pinned Git commit"
        )
    return {
        path: _git_blob(trusted_root, expected_repository_commit, path)
        for path in sorted(expected_digests)
    }


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


def _run_bounded_parser(command: list[str], data: bytes, *, relative: str) -> bytes:
    clean_env = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    try:
        result = subprocess.run(
            command,
            input=data,
            check=False,
            capture_output=True,
            timeout=15,
            env=clean_env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SubmissionBuildError(f"required parser failed for {relative}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:300]
        raise SubmissionBuildError(f"invalid {Path(relative).suffix} document {relative}: {detail}")
    if len(result.stdout) > 16 * 1024 * 1024:
        raise SubmissionBuildError(f"parser output limit exceeded in {relative}")
    return result.stdout


def _scan_pdf(relative: str, data: bytes) -> None:
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-4096:]:
        raise SubmissionBuildError(f"invalid PDF magic or trailer: {relative}")
    _run_bounded_parser(["pdfinfo", "-"], data, relative=relative)
    extracted_text = _run_bounded_parser(["pdftotext", "-", "-"], data, relative=relative)
    if _SECRET_RE.search(extracted_text) or _PII_RE.search(extracted_text):
        raise SubmissionBuildError(f"secret/PII-like material detected in {relative}")


@lru_cache(maxsize=8)
def _render_pptx_with_soffice(data: bytes) -> int:
    clean_env = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "127.0.0.1,localhost",
    }
    with tempfile.TemporaryDirectory(prefix="proofflow-pptx-parse-") as temporary:
        root = Path(temporary)
        source = root / "presentation.pptx"
        output_dir = root / "converted"
        profile_dir = root / "soffice-profile"
        source.write_bytes(data)
        output_dir.mkdir()
        profile_dir.mkdir()
        command = [
            "soffice",
            f"-env:UserInstallation={profile_dir.as_uri()}",
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            str(output_dir),
            str(source),
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=90,
                env=clean_env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SubmissionBuildError(
                "soffice is required to prove PPTX renderability; conversion could not run"
            ) from exc
        converted = output_dir / "presentation.pdf"
        if result.returncode != 0 or not converted.is_file() or converted.stat().st_size == 0:
            detail = (result.stderr or result.stdout).strip()[-500:]
            raise SubmissionBuildError(f"PPTX failed soffice headless conversion: {detail}")
        converted_bytes = converted.read_bytes()
        info = _run_bounded_parser(
            ["pdfinfo", "-"], converted_bytes, relative="soffice-converted.pdf"
        ).decode("utf-8", errors="replace")
        match = re.search(r"(?m)^Pages:\s+([0-9]+)\s*$", info)
        if match is None or int(match.group(1)) < 1:
            raise SubmissionBuildError("soffice-converted PPTX has no verifiable pages")
        _scan_pdf("soffice-converted.pdf", converted_bytes)
        return int(match.group(1))


def _scan_pptx(relative: str, data: bytes) -> None:
    try:
        with zipfile.ZipFile(BytesIO(data)) as office:
            names = office.namelist()
            if len(names) != len(set(names)):
                raise SubmissionBuildError(f"duplicate office member in {relative}")
            required_members = {"[Content_Types].xml", "_rels/.rels", "ppt/presentation.xml"}
            if not required_members.issubset(names):
                raise SubmissionBuildError(f"invalid PowerPoint structure: {relative}")
            total = 0
            for member in office.infolist():
                if member.is_dir():
                    continue
                total += member.file_size
                if total > 64 * 1024 * 1024 or len(member.filename) > 512:
                    raise SubmissionBuildError(f"office scan limit exceeded in {relative}")
                member_data = office.read(member)
                if member.filename.endswith((".xml", ".rels")):
                    try:
                        ElementTree.fromstring(member_data)
                    except ElementTree.ParseError as exc:
                        raise SubmissionBuildError(
                            f"invalid XML member {member.filename} in {relative}"
                        ) from exc
                if _SECRET_RE.search(member_data) or _PII_RE.search(member_data):
                    raise SubmissionBuildError(f"secret/PII-like material detected in {relative}")
    except zipfile.BadZipFile as exc:
        raise SubmissionBuildError(f"invalid office container: {relative}") from exc
    _render_pptx_with_soffice(data)


def _scan_bytes(relative: str, data: bytes) -> None:
    if _SECRET_RE.search(data):
        raise SubmissionBuildError(f"secret-like material detected in {relative}")
    suffix = Path(relative).suffix.lower()
    if suffix == ".pptx":
        _scan_pptx(relative, data)
    elif suffix == ".pdf":
        _scan_pdf(relative, data)
    elif suffix not in {".zip", ".png", ".jpg", ".jpeg", ".mp4"} and _PII_RE.search(data):
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
            "official_recheck_evidence",
            "demo_access_evidence",
            "demo_offline_fallback",
        }:
            raise SubmissionBuildError(f"required_artifacts.{category!r} must be a non-empty list")
        normalized[category] = [
            _safe_relative_path(value, field=f"required_artifacts.{category}") for value in values
        ]
    if len(normalized["deck_pptx"]) != 1 or not normalized["deck_pptx"][0].endswith(".pptx"):
        raise SubmissionBuildError("required_artifacts.deck_pptx must contain exactly one .pptx")
    if len(normalized["deck_pdf"]) != 1 or not normalized["deck_pdf"][0].endswith(".pdf"):
        raise SubmissionBuildError("required_artifacts.deck_pdf must contain exactly one .pdf")
    for category, expected in _FIXED_REQUIRED_PATHS.items():
        actual = set(normalized[category])
        if actual != expected:
            missing = sorted(expected - actual)
            extras = sorted(actual - expected)
            raise SubmissionBuildError(
                f"required_artifacts.{category} must match the fixed release contract; "
                f"missing={missing}, extras={extras}"
            )
    if len(normalized["agentteams_skills"]) != 8:
        raise SubmissionBuildError("exactly eight AgentTeams SKILL.md files are required")
    if any(not path.endswith("/SKILL.md") for path in normalized["agentteams_skills"]):
        raise SubmissionBuildError("every AgentTeams Skill artifact must be named SKILL.md")
    if len(normalized["agentteams_mcp"]) != 3:
        raise SubmissionBuildError("exactly three AgentTeams MCP resources are required")
    return normalized


def _validate_gate_evidence(config: dict[str, Any]) -> dict[str, Any]:
    evidence = config.get("gate_evidence")
    if not isinstance(evidence, dict):
        raise SubmissionBuildError("config.gate_evidence is required")
    for key, ref_key in (
        ("eligibility", "evidence_ref"),
        ("official_config_recheck", "evidence_ref"),
        ("real_agent_collaboration", "evaluation_ledger_ref"),
        ("demo_access", "evidence_ref"),
    ):
        item = evidence.get(key)
        if not isinstance(item, dict):
            raise SubmissionBuildError(f"config.gate_evidence.{key} is required")
        ref = item.get(ref_key)
        if ref is not None:
            if not isinstance(ref, dict):
                raise SubmissionBuildError(f"invalid {key} evidence ref")
            _safe_relative_path(ref.get("path"), field=f"gate_evidence.{key}.path")
            digest = ref.get("sha256")
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                raise SubmissionBuildError(f"invalid {key} evidence digest")
    for key in ("official_config_recheck", "demo_access"):
        max_age = evidence[key].get("max_age_hours")
        if not isinstance(max_age, int) or not 0 < max_age <= 24:
            raise SubmissionBuildError(f"{key} max_age_hours must be between 1 and 24")
    return evidence


def _normalize_config(
    config: dict[str, Any], *, trusted_schema_bytes: bytes | None = None
) -> dict[str, Any]:
    if trusted_schema_bytes is None:
        _validate_schema(config, CONFIG_SCHEMA_PATH, source="submission config")
    else:
        _validate_schema_bytes(
            config,
            trusted_schema_bytes,
            schema_source="trusted semifinal submission config schema",
            source="submission config",
        )
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
    snapshot = official["snapshot"]
    opens_at = datetime.fromisoformat(snapshot["opens_at"].replace("Z", "+00:00"))
    closes_at = datetime.fromisoformat(snapshot["closes_at"].replace("Z", "+00:00"))
    if opens_at >= closes_at:
        raise SubmissionBuildError("official.snapshot opens_at must precede closes_at")
    context = _validate_context_mapping(config)
    gate_evidence = _validate_gate_evidence(config)
    for gate_key, category in _EVIDENCE_CATEGORY_BY_GATE.items():
        ref_key = (
            "evaluation_ledger_ref" if gate_key == "real_agent_collaboration" else "evidence_ref"
        )
        ref = gate_evidence[gate_key][ref_key]
        category_paths = required[category]
        if ref is None:
            if category_paths:
                raise SubmissionBuildError(
                    f"required_artifacts.{category} must be empty while its gate ref is null"
                )
            continue
        if category_paths != [ref["path"]]:
            raise SubmissionBuildError(
                f"required_artifacts.{category} must contain exactly its bound evidence path"
            )
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


def _artifact_category(relative: str, required_artifacts: Mapping[str, list[str]]) -> str:
    return next(
        (category for category, paths in required_artifacts.items() if relative in paths),
        "supporting",
    )


def _collect_artifacts(root: Path, config: dict[str, Any]) -> tuple[Artifact, ...]:
    artifacts: list[Artifact] = []
    for relative in config["allowlist"]:
        source = _assert_safe_file(root, relative)
        _assert_tracked(root, relative)
        data = source.read_bytes()
        _scan_bytes(relative, data)
        category = _artifact_category(relative, config["required_artifacts"])
        artifacts.append(Artifact(relative, category, len(data), sha256_bytes(data)))
    return tuple(sorted(artifacts, key=lambda item: item.path))


def _yaml_documents(path: Path) -> list[dict[str, Any]]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - development dependency is pinned
        raise SubmissionBuildError("PyYAML is required to validate AgentTeams resources") from exc
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SubmissionBuildError(f"invalid YAML resource {path}: {exc}") from exc
    if not documents or any(not isinstance(item, dict) for item in documents):
        raise SubmissionBuildError(f"YAML resource must contain object documents: {path}")
    return documents


def _validate_artifact_contract(
    root: Path, config: dict[str, Any], artifacts: tuple[Artifact, ...]
) -> None:
    artifact_paths = {item.path for item in artifacts}
    if artifact_paths != set(config["allowlist"]):
        raise SubmissionBuildError("artifact inventory must equal the normalized allowlist")

    required = config["required_artifacts"]
    workers = _yaml_documents(root / required["agentteams_workers"][0])
    if len(workers) != 6 or any(item.get("kind") != "Worker" for item in workers):
        raise SubmissionBuildError("AgentTeams worker resource must contain exactly six Workers")
    worker_names = [item.get("metadata", {}).get("name") for item in workers]
    if len(worker_names) != len(set(worker_names)) or any(
        item.get("spec", {}).get("state") != "Stopped" for item in workers
    ):
        raise SubmissionBuildError(
            "the six packaged Worker resources must be unique and fail-safe Stopped"
        )

    teams = _yaml_documents(root / required["agentteams_team"][0])
    if len(teams) != 1 or teams[0].get("kind") != "Team":
        raise SubmissionBuildError("AgentTeams team resource must contain exactly one Team")
    members = teams[0].get("spec", {}).get("workerMembers")
    member_names = [item.get("name") for item in members] if isinstance(members, list) else []
    if len(member_names) != 6 or set(member_names) != set(worker_names):
        raise SubmissionBuildError("AgentTeams Team must bind the exact six packaged Workers")

    humans = _yaml_documents(root / required["agentteams_humans"][0])
    if len(humans) != 2 or any(item.get("kind") != "Human" for item in humans):
        raise SubmissionBuildError("AgentTeams human resource must contain exactly two Humans")

    mcp_names: set[str] = set()
    for relative in required["agentteams_mcp"]:
        documents = _yaml_documents(root / relative)
        if len(documents) != 1:
            raise SubmissionBuildError(f"MCP resource must contain one document: {relative}")
        server_name = documents[0].get("server", {}).get("name")
        tools = documents[0].get("tools")
        if (
            not isinstance(server_name, str)
            or not server_name
            or not isinstance(tools, list)
            or not tools
        ):
            raise SubmissionBuildError(f"invalid MCP resource structure: {relative}")
        mcp_names.add(server_name)
    if len(mcp_names) != 3:
        raise SubmissionBuildError("the three packaged MCP resources must have unique server names")

    for relative in required["agentteams_skills"]:
        skill_text = (root / relative).read_text(encoding="utf-8")
        if not skill_text.startswith("---\n") or "name:" not in skill_text[:1024]:
            raise SubmissionBuildError(f"invalid SKILL.md frontmatter: {relative}")

    deck_pptx = required["deck_pptx"][0]
    deck_pdf = required["deck_pdf"][0]
    if not deck_pptx.startswith("submission/public/") or not deck_pdf.startswith(
        "submission/public/"
    ):
        raise SubmissionBuildError("deck PPTX/PDF must come from submission/public")

    fallback = required["demo_offline_fallback"]
    if fallback and not any(Path(path).suffix.casefold() in {".mp4", ".webm"} for path in fallback):
        raise SubmissionBuildError("demo_offline_fallback must contain a playable video")


def _verify_refs(refs: list[dict[str, str]], artifacts: tuple[Artifact, ...]) -> bool:
    inventory = {item.path: item.sha256 for item in artifacts}
    return bool(refs) and all(
        ref.get("path") in inventory and inventory[ref["path"]] == ref.get("sha256") for ref in refs
    )


def _load_bound_evidence(
    root: Path,
    ref: dict[str, str] | None,
    *,
    category: str,
    artifacts: tuple[Artifact, ...],
    schema_path: Path | None = None,
    trusted_schema_bytes: bytes | None = None,
) -> dict[str, Any] | None:
    if ref is None:
        return None
    if not _verify_refs([ref], artifacts):
        raise SubmissionBuildError(f"{category} evidence digest is not bound to the ZIP inventory")
    categories = {item.path: item.category for item in artifacts}
    if categories.get(ref["path"]) != category:
        raise SubmissionBuildError(f"{category} evidence ref has the wrong artifact category")
    payload = _load_strict_json_file(root / ref["path"])
    if not isinstance(payload, dict):
        raise SubmissionBuildError(f"{category} evidence must be a JSON object")
    if trusted_schema_bytes is not None:
        _validate_schema_bytes(
            payload,
            trusted_schema_bytes,
            schema_source=f"trusted {category} schema",
            source=ref["path"],
        )
    elif schema_path is not None:
        _validate_schema(payload, schema_path, source=ref["path"])
    else:  # pragma: no cover - internal programming contract
        raise SubmissionBuildError(f"no trusted schema supplied for {category}")
    return payload


def _is_fresh(observed_at: str, max_age_hours: int, *, now: datetime | None = None) -> bool:
    current = now or datetime.now(UTC)
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    return (
        parsed.tzinfo is not None
        and parsed <= current
        and (current - parsed).total_seconds() <= max_age_hours * 3600
    )


def _verify_evaluation_v2(
    evidence_root: Path,
    ref: dict[str, str] | None,
    artifacts: tuple[Artifact, ...],
    *,
    expected_repository_commit: str,
    trusted_blobs: Mapping[str, bytes],
) -> tuple[bool, str]:
    if _EVALUATION_TRUST_ANCHOR not in trusted_blobs:
        return False, "evaluation_v2_verifier_missing"
    if ref is None:
        return False, "evaluation_v2_ledger_missing"
    ledger = _load_bound_evidence(
        evidence_root,
        ref,
        category="agent_collaboration_evidence",
        artifacts=artifacts,
        trusted_schema_bytes=trusted_blobs["benchmarks/evaluation/run-ledger.schema.json"],
    )
    if ledger is None:  # pragma: no cover - guarded above
        return False, "evaluation_v2_ledger_missing"
    if ledger.get("provenance", {}).get("repository_commit") != expected_repository_commit:
        return False, "evaluation_v2_source_commit_mismatch"
    with tempfile.TemporaryDirectory(prefix="proofflow-trusted-evaluation-") as temporary:
        verifier_root = Path(temporary)
        for relative in sorted(_EVALUATION_TRUST_PATHS):
            destination = verifier_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(trusted_blobs[relative])
        verifier_program = """
import json
import pathlib
import sys
from benchmarks.evaluation.ledger_verifier import verify_run_ledger

module = pathlib.Path(sys.modules["benchmarks.evaluation.ledger_verifier"].__file__).resolve()
root = pathlib.Path.cwd().resolve()
if not module.is_relative_to(root):
    raise RuntimeError("evaluation verifier escaped the trusted root")
raw = sys.stdin.read()
result = verify_run_ledger(raw, expected_repository_commit=sys.argv[1])
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"""
        clean_env = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONPATH": str(verifier_root),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost",
        }
        try:
            completed = subprocess.run(
                [sys.executable, "-c", verifier_program, expected_repository_commit],
                input=_canonical_json(ledger).decode("utf-8"),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=verifier_root,
                env=clean_env,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SubmissionBuildError("trusted evaluation v2 verifier could not run") from exc
        if completed.returncode != 0:
            raise SubmissionBuildError(
                "trusted evaluation v2 verifier failed: " + completed.stderr.strip()[-500:]
            )
        verification = _strict_load_json(
            completed.stdout, source="trusted evaluation v2 verifier output"
        )
    if not isinstance(verification, dict) or verification.get("status") != "VERIFIED":
        return False, "evaluation_v2_ledger_not_verified"
    if verification.get("entries_verified") != len(ledger["entries"]):
        return False, "evaluation_v2_entry_count_mismatch"
    worker_entries = [
        entry for entry in ledger["entries"] if entry["arm_id"] in {"single_agent", "six_agent"}
    ]
    arms = {entry["arm_id"] for entry in worker_entries}
    if arms != {"single_agent", "six_agent"}:
        return False, "evaluation_v2_worker_arms_incomplete"
    if any(
        entry["execution_status"] != "EXECUTED"
        or entry["status"] in {"UNKNOWN", "UNSAFE_SUCCESS"}
        or entry["result"] is None
        for entry in worker_entries
    ):
        return False, "evaluation_v2_worker_runs_incomplete_or_unsafe"
    return True, "evaluation_v2_verified"


def _gate(
    root: Path,
    config: dict[str, Any],
    artifacts: tuple[Artifact, ...],
    mode: str,
    *,
    expected_repository_commit: str,
    trusted_blobs: Mapping[str, bytes],
) -> GateReport:
    if mode not in {"candidate", "submit-ready"}:
        raise SubmissionBuildError("mode must be candidate or submit-ready")
    reasons: list[str] = []
    warnings: list[str] = []
    if not config.get("demo_url"):
        reasons.append("demo_url_missing")
    eligibility = _load_bound_evidence(
        root,
        config["gate_evidence"]["eligibility"]["evidence_ref"],
        category="eligibility_evidence",
        artifacts=artifacts,
        trusted_schema_bytes=trusted_blobs["schemas/semifinal-eligibility-evidence.schema.json"],
    )
    if eligibility is None or not _is_fresh(eligibility["observed_at"], 24):
        reasons.append("eligibility_evidence_missing_or_stale")

    recheck_config = config["gate_evidence"]["official_config_recheck"]
    recheck = _load_bound_evidence(
        root,
        recheck_config["evidence_ref"],
        category="official_recheck_evidence",
        artifacts=artifacts,
        trusted_schema_bytes=trusted_blobs[
            "schemas/semifinal-official-recheck-evidence.schema.json"
        ],
    )
    snapshot_fields = (
        "opens_at",
        "closes_at",
        "zip_max_mib",
        "cumulative_max_mib",
        "max_attempts_per_stage",
        "required_fields",
    )
    if (
        recheck is None
        or not _is_fresh(recheck["observed_at"], recheck_config["max_age_hours"])
        or any(recheck[field] != config["official"]["snapshot"][field] for field in snapshot_fields)
    ):
        reasons.append("official_dynamic_config_evidence_missing_stale_or_mismatched")

    demo_gate = config["gate_evidence"]["demo_access"]
    demo_evidence = _load_bound_evidence(
        root,
        demo_gate["evidence_ref"],
        category="demo_access_evidence",
        artifacts=artifacts,
        trusted_schema_bytes=trusted_blobs["schemas/semifinal-demo-access-evidence.schema.json"],
    )
    if (
        demo_evidence is None
        or demo_evidence.get("url") != config.get("demo_url")
        or not _is_fresh(demo_evidence["observed_at"], demo_gate["max_age_hours"])
    ):
        reasons.append("public_demo_access_evidence_missing_stale_or_mismatched")

    collaboration_ref = config["gate_evidence"]["real_agent_collaboration"]["evaluation_ledger_ref"]
    collaboration_valid, collaboration_reason = _verify_evaluation_v2(
        root,
        collaboration_ref,
        artifacts,
        expected_repository_commit=expected_repository_commit,
        trusted_blobs=trusted_blobs,
    )
    if not collaboration_valid:
        reasons.extend(("real_agent_collaboration_evidence_missing", collaboration_reason))
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
    warnings.append(
        "PDF text was extracted with pdftotext and scanned; rasterized text needs review"
    )
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
    mode: str,
    trusted_file_digests: Mapping[str, str],
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
    manifest = {
        "schema_version": "proofflow.goai.semifinal.manifest/v3",
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
        "trust": {
            "expected_repository_commit": source_commit,
            "root_kind": "EXTERNAL_GIT_COMMIT",
            "trusted_file_digests": dict(sorted(trusted_file_digests.items())),
            "evaluation_verifier_status": (
                "AVAILABLE" if _EVALUATION_TRUST_ANCHOR in trusted_file_digests else "MISSING"
            ),
        },
        "integrity": {
            "algorithm": "SHA-256",
            "subject_binding_sha256": "sha256:" + "0" * 64,
            "attestation": "NOT_PROVIDED",
            "signature": "NOT_PROVIDED",
        },
        "build": {
            "tool": "scripts.semifinal_submission",
            "mode": mode,
            "reproducible": True,
            "timestamp": None,
            "source_root": ".",
            "config_path": CONFIG_ARCHIVE_PATH,
            "command": [
                "uv",
                "run",
                "python",
                "scripts/build_semifinal_zip.py",
                "--config",
                CONFIG_ARCHIVE_PATH,
                "--output",
                "<OUTPUT_OUTSIDE_REPOSITORY>.zip",
                "--mode",
                mode,
            ],
        },
    }
    manifest["integrity"]["subject_binding_sha256"] = sha256_bytes(
        _canonical_json(_subject_binding_payload(manifest))
    )
    return manifest


def _subject_binding_payload(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": manifest.get("schema_version"),
        "source_commit": manifest.get("source_commit"),
        "repository_url": manifest.get("repository_url"),
        "official_snapshot": (
            manifest.get("official", {}).get("snapshot")
            if isinstance(manifest.get("official"), Mapping)
            else None
        ),
        "demo_url": manifest.get("demo_url"),
        "required_components": manifest.get("required_components"),
        "context_mapping": manifest.get("context_mapping"),
        "gate_evidence": manifest.get("gate_evidence"),
        "trust": manifest.get("trust"),
        "artifact_inventory": manifest.get("artifact_inventory"),
        "gate": manifest.get("gate"),
        "build": manifest.get("build"),
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


def _run_extracted_command(
    command: list[str], *, cwd: Path, timeout: int, label: str
) -> str | None:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "UV_OFFLINE": "1",
        "UV_NO_PROGRESS": "1",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "127.0.0.1,localhost",
        "http_proxy": "http://127.0.0.1:9",
        "https_proxy": "http://127.0.0.1:9",
        "all_proxy": "http://127.0.0.1:9",
        "no_proxy": "127.0.0.1,localhost",
    }
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"{label} could not run: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-1000:]
        return f"{label} failed with exit {result.returncode}: {detail}"
    return None


def _validate_extracted_runtime_root(extracted: Path) -> list[str]:
    messages: list[str] = []
    error = _run_extracted_command(
        ["uv", "sync", "--frozen", "--no-dev", "--offline"],
        cwd=extracted,
        timeout=180,
        label="offline uv sync",
    )
    if error:
        return [error]
    python = extracted / ".venv/bin/python"
    for command, label in (
        ([str(python), "-m", "demo.server", "--help"], "extracted demo --help"),
        (
            [str(python), "-m", "scripts.semifinal_extracted_smoke"],
            "extracted loopback smoke",
        ),
    ):
        error = _run_extracted_command(command, cwd=extracted, timeout=60, label=label)
        if error:
            messages.append(error)
            break
    return messages


def validate_zip(
    path: Path,
    *,
    expected_repository_commit: str,
    trusted_root: Path,
    trusted_file_digests: Mapping[str, str],
    run_extracted_smoke: bool = False,
) -> list[str]:
    """Validate ZIP bytes against an external commit-pinned schema/verifier root."""
    messages: list[str] = []
    if not path.is_file():
        return ["ZIP does not exist"]
    try:
        trusted_blobs = _load_trusted_blobs(
            trusted_root=trusted_root,
            expected_repository_commit=expected_repository_commit,
            trusted_file_digests=trusted_file_digests,
        )
    except SubmissionBuildError as exc:
        return [f"external trust anchor invalid: {exc}"]
    if path.stat().st_size > MAX_ZIP_BYTES:
        messages.append("ZIP exceeds 1200 MiB limit")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if names != sorted(names):
                messages.append("ZIP entries are not deterministically sorted")
            if len(names) != len(set(names)):
                messages.append("ZIP contains duplicate entry names")
            portable_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
            if len(portable_names) != len(set(portable_names)):
                messages.append("ZIP contains portable-path collisions")
            total_uncompressed = 0
            for info in infos:
                try:
                    normalized = _safe_relative_path(info.filename, field="ZIP entry")
                except SubmissionBuildError as exc:
                    messages.append(str(exc))
                    continue
                if normalized != info.filename or info.is_dir():
                    messages.append(f"ZIP entry is not a canonical file path: {info.filename}")
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) != stat.S_IFREG or stat.S_IMODE(mode) != 0o644:
                    messages.append(f"ZIP entry is not a regular 0644 file: {info.filename}")
                if info.flag_bits & 0x1:
                    messages.append(f"ZIP entry is encrypted: {info.filename}")
                if info.compress_type != zipfile.ZIP_DEFLATED:
                    messages.append(
                        f"ZIP entry uses an unexpected compression method: {info.filename}"
                    )
                if info.date_time != (1980, 1, 1, 0, 0, 0):
                    messages.append(f"ZIP entry has a non-reproducible timestamp: {info.filename}")
                total_uncompressed += info.file_size
                if total_uncompressed > 2 * 1024 * 1024 * 1024:
                    messages.append("ZIP uncompressed size exceeds the validation ceiling")
                    break
            if names.count(MANIFEST_NAME) != 1:
                messages.append("ZIP must contain exactly one semifinal manifest")
                return sorted(set(messages))
            if messages:
                return sorted(set(messages))
            archive_bytes: dict[str, bytes] = {}
            for name in names:
                try:
                    archive_bytes[name] = archive.read(name)
                except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
                    messages.append(f"cannot read ZIP entry {name}: {exc}")
            if messages:
                return sorted(set(messages))
            for relative, trusted_bytes in trusted_blobs.items():
                if archive_bytes.get(relative) != trusted_bytes:
                    messages.append(
                        f"commit-pinned trusted file bytes mismatch or missing: {relative}"
                    )
            if messages:
                return sorted(set(messages))
            try:
                config_value = _strict_load_json(
                    archive_bytes[CONFIG_ARCHIVE_PATH].decode("utf-8"),
                    source=CONFIG_ARCHIVE_PATH,
                )
                if not isinstance(config_value, dict):
                    raise SubmissionBuildError("packaged submission config must be an object")
                config = _normalize_config(
                    config_value,
                    trusted_schema_bytes=trusted_blobs[
                        "schemas/semifinal-submission-config.schema.json"
                    ],
                )
            except (KeyError, UnicodeDecodeError, SubmissionBuildError) as exc:
                return [f"commit-pinned packaged config is invalid: {exc}"]
            expected_names = set(config["allowlist"]) | {MANIFEST_NAME}
            if set(names) != expected_names:
                missing = sorted(expected_names - set(names))
                extras = sorted(set(names) - expected_names)
                messages.append(
                    "ZIP exact config-derived inventory mismatch: "
                    f"missing={missing}, extras={extras}"
                )
                return sorted(set(messages))
            try:
                source_blobs = _git_commit_regular_blobs(
                    str(trusted_root.resolve()),
                    expected_repository_commit,
                    tuple(sorted(config["allowlist"])),
                )
            except SubmissionBuildError as exc:
                return [f"external source commit payload is unavailable: {exc}"]
            for relative, expected_bytes in source_blobs.items():
                if archive_bytes[relative] != expected_bytes:
                    messages.append(
                        f"ZIP artifact bytes disagree with expected source commit: {relative}"
                    )
            artifacts = tuple(
                Artifact(
                    path=relative,
                    category=_artifact_category(relative, config["required_artifacts"]),
                    size_bytes=len(archive_bytes[relative]),
                    sha256=sha256_bytes(archive_bytes[relative]),
                )
                for relative in sorted(config["allowlist"])
            )
            for artifact in artifacts:
                try:
                    _scan_bytes(artifact.path, archive_bytes[artifact.path])
                except SubmissionBuildError as exc:
                    messages.append(str(exc))
            if messages:
                return sorted(set(messages))
            try:
                manifest = _strict_load_json(
                    archive_bytes[MANIFEST_NAME].decode("utf-8"), source=MANIFEST_NAME
                )
            except (KeyError, UnicodeDecodeError, SubmissionBuildError) as exc:
                messages.append(f"ZIP manifest is invalid strict JSON: {exc}")
                return sorted(set(messages))
            if not isinstance(manifest, dict):
                messages.append("ZIP manifest must be an object")
                return sorted(set(messages))
            messages.extend(
                _validate_manifest_data(
                    manifest,
                    trusted_manifest_schema_bytes=trusted_blobs[
                        "schemas/semifinal-submission-manifest.schema.json"
                    ],
                    expected_repository_commit=expected_repository_commit,
                    trusted_file_digests=trusted_file_digests,
                )
            )
            expected_inventory = [
                {
                    "path": item.path,
                    "category": item.category,
                    "size_bytes": item.size_bytes,
                    "sha256": item.sha256,
                }
                for item in artifacts
            ]
            for key, expected in (
                ("source_commit", expected_repository_commit),
                ("repository_url", config["repository_url"]),
                ("demo_url", config.get("demo_url")),
                ("official", config["official"]),
                ("required_components", config["required_artifacts"]),
                ("context_mapping", config["context_mapping"]),
                ("gate_evidence", config["gate_evidence"]),
                ("artifact_inventory", expected_inventory),
            ):
                if manifest.get(key) != expected:
                    messages.append(f"manifest.{key} disagrees with trusted ZIP bytes/config")
            if manifest.get("trust") != {
                "expected_repository_commit": expected_repository_commit,
                "root_kind": "EXTERNAL_GIT_COMMIT",
                "trusted_file_digests": dict(sorted(trusted_file_digests.items())),
                "evaluation_verifier_status": (
                    "AVAILABLE" if _EVALUATION_TRUST_ANCHOR in trusted_file_digests else "MISSING"
                ),
            }:
                messages.append("manifest.trust disagrees with the external trust anchor")
            with tempfile.TemporaryDirectory(prefix="proofflow-semifinal-extracted-") as temporary:
                extracted = Path(temporary)
                for relative in sorted(expected_names - {MANIFEST_NAME}):
                    destination = extracted / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive_bytes[relative])
                try:
                    _validate_artifact_contract(extracted, config, artifacts)
                    mode = manifest["build"]["mode"]
                    recomputed_gate = _gate(
                        extracted,
                        config,
                        artifacts,
                        mode,
                        expected_repository_commit=expected_repository_commit,
                        trusted_blobs=trusted_blobs,
                    )
                except (KeyError, TypeError, SubmissionBuildError) as exc:
                    messages.append(f"independent gate reconstruction failed: {exc}")
                    return sorted(set(messages))
                if manifest.get("gate") != recomputed_gate.as_dict():
                    messages.append("manifest.gate disagrees with independently reconstructed gate")
                if manifest.get("artifact_status") != recomputed_gate.status:
                    messages.append(
                        "manifest.artifact_status disagrees with independently reconstructed gate"
                    )
                if not messages and run_extracted_smoke:
                    messages.extend(_validate_extracted_runtime_root(extracted))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        return [f"invalid ZIP archive: {exc}"]
    return sorted(set(messages))


def build_package(
    *, config_path: Path, output: Path, mode: str = "candidate", report_path: Path | None = None
) -> dict[str, Any]:
    root = config_path.resolve().parents[2]
    if not (root / ".git").exists():
        raise SubmissionBuildError(f"config must be inside a git worktree: {config_path}")
    config = _normalize_config(load_config(config_path))
    source_commit = _assert_clean_git(root)
    trusted_file_digests = commit_pinned_trust_digests(root, source_commit)
    trusted_blobs = _load_trusted_blobs(
        trusted_root=root,
        expected_repository_commit=source_commit,
        trusted_file_digests=trusted_file_digests,
    )
    artifacts = _collect_artifacts(root, config)
    _validate_artifact_contract(root, config, artifacts)
    gate = _gate(
        root,
        config,
        artifacts,
        mode,
        expected_repository_commit=source_commit,
        trusted_blobs=trusted_blobs,
    )
    manifest = build_manifest(
        root=root,
        config=config,
        artifacts=artifacts,
        gate=gate,
        source_commit=source_commit,
        mode=mode,
        trusted_file_digests=trusted_file_digests,
    )
    manifest_errors = _validate_manifest_data(
        manifest,
        trusted_manifest_schema_bytes=trusted_blobs[
            "schemas/semifinal-submission-manifest.schema.json"
        ],
        expected_repository_commit=source_commit,
        trusted_file_digests=trusted_file_digests,
    )
    if manifest_errors:
        raise SubmissionBuildError(
            "generated manifest failed validation: " + "; ".join(manifest_errors)
        )
    _write_deterministic_zip(root, output, artifacts, manifest)
    zip_size = output.stat().st_size
    if zip_size > MAX_ZIP_BYTES:
        output.unlink(missing_ok=True)
        raise SubmissionBuildError(f"ZIP exceeds 1200 MiB limit: {zip_size} bytes")
    zip_errors = validate_zip(
        output,
        expected_repository_commit=source_commit,
        trusted_root=root,
        trusted_file_digests=trusted_file_digests,
        run_extracted_smoke=True,
    )
    if zip_errors:
        output.unlink(missing_ok=True)
        raise SubmissionBuildError("final ZIP validation failed: " + "; ".join(zip_errors))
    report = {
        "schema_version": "proofflow.goai.semifinal.build-report/v1",
        "artifact_status": gate.status,
        "zip_path": output.name,
        "zip_size_bytes": zip_size,
        "zip_sha256": sha256_file(output),
        "manifest_sha256": sha256_bytes(_canonical_json(manifest)),
        "source_commit": source_commit,
        "trusted_file_digests": trusted_file_digests,
        "gate": gate.as_dict(),
        "portal_receipt": None,
        "selection_claim": False,
    }
    if report_path is None:
        report_path = output.with_name(output.name + REPORT_SUFFIX)
    report_path.write_bytes(_canonical_json(report))
    return report


def _validate_manifest_data(
    manifest: dict[str, Any],
    *,
    trusted_manifest_schema_bytes: bytes | None = None,
    expected_repository_commit: str | None = None,
    trusted_file_digests: Mapping[str, str] | None = None,
) -> list[str]:
    if trusted_manifest_schema_bytes is None:
        messages = _schema_messages(manifest, MANIFEST_SCHEMA_PATH)
    else:
        messages = _schema_messages_from_bytes(
            manifest,
            trusted_manifest_schema_bytes,
            source="externally trusted semifinal manifest schema",
        )
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
                for category, expected in _FIXED_REQUIRED_PATHS.items():
                    actual = required.get(category)
                    if isinstance(actual, list) and set(actual) != expected:
                        messages.append(
                            f"required_components.{category}: fixed release contract mismatch"
                        )
                deck_pptx = required.get("deck_pptx")
                deck_pdf = required.get("deck_pdf")
                if not (
                    isinstance(deck_pptx, list)
                    and len(deck_pptx) == 1
                    and deck_pptx[0].endswith(".pptx")
                ):
                    messages.append("required_components.deck_pptx: exactly one .pptx required")
                if not (
                    isinstance(deck_pdf, list)
                    and len(deck_pdf) == 1
                    and deck_pdf[0].endswith(".pdf")
                ):
                    messages.append("required_components.deck_pdf: exactly one .pdf required")
            integrity = manifest.get("integrity")
            if isinstance(integrity, dict):
                expected_binding = sha256_bytes(_canonical_json(_subject_binding_payload(manifest)))
                if integrity.get("subject_binding_sha256") != expected_binding:
                    messages.append("integrity: subject binding digest mismatch")
        status = manifest.get("artifact_status")
        gate = manifest.get("gate")
        receipt = manifest.get("portal_receipt")
        if status == "SUBMITTED_RECEIPT_VERIFIED" and receipt is None:
            messages.append("portal_receipt: required for SUBMITTED_RECEIPT_VERIFIED")
        if status != "SUBMITTED_RECEIPT_VERIFIED" and receipt is not None:
            messages.append("portal_receipt: must be null before submission")
        if isinstance(gate, dict) and status != gate.get("status"):
            messages.append("artifact_status: must equal gate.status")
        build = manifest.get("build")
        if isinstance(build, dict):
            command = build.get("command")
            if isinstance(command, list) and command and command[-1] != build.get("mode"):
                messages.append("build.command: --mode value must equal build.mode")
        if expected_repository_commit is not None:
            if manifest.get("source_commit") != expected_repository_commit:
                messages.append("source_commit: external expected commit mismatch")
            trust = manifest.get("trust")
            expected_trust = {
                "expected_repository_commit": expected_repository_commit,
                "root_kind": "EXTERNAL_GIT_COMMIT",
                "trusted_file_digests": dict(sorted((trusted_file_digests or {}).items())),
                "evaluation_verifier_status": (
                    "AVAILABLE"
                    if trusted_file_digests and _EVALUATION_TRUST_ANCHOR in trusted_file_digests
                    else "MISSING"
                ),
            }
            if trust != expected_trust:
                messages.append("trust: external commit/schema/verifier anchor mismatch")
        gate_evidence = manifest.get("gate_evidence")
        if status == STATUS_READY:
            if not isinstance(gate, dict) or gate.get("reasons"):
                messages.append("gate: PRE_SUBMIT_READY requires zero reasons")
            if manifest.get("demo_url") is None:
                messages.append("demo_url: PRE_SUBMIT_READY requires a public Demo URL")
            if isinstance(gate_evidence, dict):
                refs = (
                    gate_evidence.get("eligibility", {}).get("evidence_ref"),
                    gate_evidence.get("official_config_recheck", {}).get("evidence_ref"),
                    gate_evidence.get("real_agent_collaboration", {}).get("evaluation_ledger_ref"),
                    gate_evidence.get("demo_access", {}).get("evidence_ref"),
                )
                if any(ref is None for ref in refs):
                    messages.append("gate_evidence: PRE_SUBMIT_READY requires every evidence ref")
            else:
                messages.append("gate_evidence: missing")
        official = manifest.get("official")
        if isinstance(official, dict) and isinstance(official.get("snapshot"), dict):
            snapshot = official["snapshot"]
            try:
                opens_at = datetime.fromisoformat(snapshot["opens_at"].replace("Z", "+00:00"))
                closes_at = datetime.fromisoformat(snapshot["closes_at"].replace("Z", "+00:00"))
                if opens_at >= closes_at:
                    messages.append("official.snapshot: opens_at must precede closes_at")
            except (KeyError, TypeError, ValueError):
                pass
        try:
            _validate_public_url(
                manifest.get("repository_url"), key="repository_url", required=True
            )
            _validate_public_url(manifest.get("demo_url"), key="demo_url", required=False)
            if isinstance(official, dict):
                for key in ("track_url", "handbook_url", "site_config_url", "submission_url"):
                    _validate_public_url(
                        official.get(key), key=f"official.{key}", required=True, allow_query=True
                    )
        except SubmissionBuildError as exc:
            messages.append(str(exc))
    return sorted(set(messages))


def validate_manifest(path: Path) -> list[str]:
    """Validate a generated manifest using strict JSON, schema, and semantic checks."""
    manifest = _load_strict_json_file(path)
    if not isinstance(manifest, dict):
        return ["manifest must be an object"]
    return _validate_manifest_data(manifest)


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
