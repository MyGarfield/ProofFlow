"""Reproducible GOAI semifinal package builder and submission gate.

This module deliberately treats the portal as an external, mutable system.  It
only builds and verifies a local candidate artifact; it never submits anything,
creates a portal receipt, or makes an eligibility/selection claim.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
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


def _schema_validator(schema_path: Path) -> Any:
    try:
        from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - development dependency is pinned
        raise SubmissionBuildError("jsonschema is required for semifinal validation") from exc
    try:
        schema = _strict_load_json(schema_path.read_text(encoding="utf-8"), source=str(schema_path))
        Draft202012Validator.check_schema(schema)
    except OSError as exc:
        raise SubmissionBuildError(f"required schema is unavailable: {schema_path}") from exc
    except Exception as exc:
        if isinstance(exc, SubmissionBuildError):
            raise
        raise SubmissionBuildError(f"invalid checked-in schema {schema_path}: {exc}") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _schema_messages(instance: Any, schema_path: Path) -> list[str]:
    validator = _schema_validator(schema_path)
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    return [
        f"{'.'.join(str(part) for part in error.absolute_path) or '$'}: {error.message}"
        for error in errors
    ]


def _validate_schema(instance: Any, schema_path: Path, *, source: str) -> None:
    messages = _schema_messages(instance, schema_path)
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
    forbidden_hostname = (
        not hostname
        or hostname == "localhost"
        or hostname == "127.0.0.1"
        or hostname.endswith((".localhost", ".invalid", ".test", ".example"))
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


def _normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    _validate_schema(config, CONFIG_SCHEMA_PATH, source="submission config")
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
    schema_path: Path,
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
    _validate_schema(payload, schema_path, source=ref["path"])
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
    root: Path,
    ref: dict[str, str] | None,
    artifacts: tuple[Artifact, ...],
) -> tuple[bool, str]:
    if not EVALUATION_LEDGER_SCHEMA_PATH.is_file():
        return False, "evaluation_v2_verifier_missing"
    try:
        module = importlib.import_module("benchmarks.evaluation.ledger_verifier")
    except (ImportError, AttributeError):
        return False, "evaluation_v2_verifier_missing"
    if ref is None:
        return False, "evaluation_v2_ledger_missing"
    module_path = Path(module.__file__ or "").resolve()
    if not module_path.is_relative_to(root.resolve()):
        raise SubmissionBuildError("evaluation v2 verifier did not resolve from the source tree")
    ledger = _load_bound_evidence(
        root,
        ref,
        category="agent_collaboration_evidence",
        artifacts=artifacts,
        schema_path=EVALUATION_LEDGER_SCHEMA_PATH,
    )
    if ledger is None:  # pragma: no cover - guarded above
        return False, "evaluation_v2_ledger_missing"
    expected_commit = ledger.get("provenance", {}).get("repository_commit")
    if not isinstance(expected_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise SubmissionBuildError("evaluation ledger lacks a valid source commit binding")
    verification = module.verify_run_ledger(
        ledger,
        expected_repository_commit=expected_commit,
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
    root: Path, config: dict[str, Any], artifacts: tuple[Artifact, ...], mode: str
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
        schema_path=ELIGIBILITY_SCHEMA_PATH,
    )
    if eligibility is None or not _is_fresh(eligibility["observed_at"], 24):
        reasons.append("eligibility_evidence_missing_or_stale")

    recheck_config = config["gate_evidence"]["official_config_recheck"]
    recheck = _load_bound_evidence(
        root,
        recheck_config["evidence_ref"],
        category="official_recheck_evidence",
        artifacts=artifacts,
        schema_path=OFFICIAL_RECHECK_SCHEMA_PATH,
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
        schema_path=DEMO_ACCESS_SCHEMA_PATH,
    )
    if (
        demo_evidence is None
        or demo_evidence.get("url") != config.get("demo_url")
        or not _is_fresh(demo_evidence["observed_at"], demo_gate["max_age_hours"])
    ):
        reasons.append("public_demo_access_evidence_missing_stale_or_mismatched")

    collaboration_ref = config["gate_evidence"]["real_agent_collaboration"]["evaluation_ledger_ref"]
    collaboration_valid, collaboration_reason = _verify_evaluation_v2(
        root, collaboration_ref, artifacts
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
        "schema_version": "proofflow.goai.semifinal.manifest/v2",
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


def _validate_extracted_runtime(archive_path: Path) -> list[str]:
    messages: list[str] = []
    with tempfile.TemporaryDirectory(prefix="proofflow-semifinal-extracted-") as temporary:
        extracted = Path(temporary)
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(extracted)
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


def validate_zip(path: Path, *, run_extracted_smoke: bool = False) -> list[str]:
    """Reopen and independently validate the final ZIP bytes and optional offline runtime."""
    messages: list[str] = []
    if not path.is_file():
        return ["ZIP does not exist"]
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
            try:
                manifest = _strict_load_json(
                    archive.read(MANIFEST_NAME).decode("utf-8"), source=MANIFEST_NAME
                )
            except (KeyError, UnicodeDecodeError, SubmissionBuildError) as exc:
                messages.append(f"ZIP manifest is invalid strict JSON: {exc}")
                return sorted(set(messages))
            if not isinstance(manifest, dict):
                messages.append("ZIP manifest must be an object")
                return sorted(set(messages))
            messages.extend(_validate_manifest_data(manifest))
            inventory = manifest.get("artifact_inventory")
            if not isinstance(inventory, list):
                return sorted({*messages, "manifest artifact_inventory is not an array"})
            inventory_by_path: dict[str, dict[str, Any]] = {
                item["path"]: item
                for item in inventory
                if isinstance(item, dict) and isinstance(item.get("path"), str)
            }
            expected_names = set(inventory_by_path) | {MANIFEST_NAME}
            if set(names) != expected_names:
                missing = sorted(expected_names - set(names))
                extras = sorted(set(names) - expected_names)
                messages.append(f"ZIP exact inventory mismatch: missing={missing}, extras={extras}")
            for relative, item in inventory_by_path.items():
                if not isinstance(relative, str) or relative not in names:
                    continue
                try:
                    data = archive.read(relative)
                except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
                    messages.append(f"cannot read ZIP entry {relative}: {exc}")
                    continue
                if len(data) != item.get("size_bytes"):
                    messages.append(f"ZIP size mismatch for {relative}")
                if sha256_bytes(data) != item.get("sha256"):
                    messages.append(f"ZIP SHA-256 mismatch for {relative}")
                try:
                    _scan_bytes(relative, data)
                except SubmissionBuildError as exc:
                    messages.append(str(exc))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        return [f"invalid ZIP archive: {exc}"]
    if not messages and run_extracted_smoke:
        messages.extend(_validate_extracted_runtime(path))
    return sorted(set(messages))


def build_package(
    *, config_path: Path, output: Path, mode: str = "candidate", report_path: Path | None = None
) -> dict[str, Any]:
    root = config_path.resolve().parents[2]
    if not (root / ".git").exists():
        raise SubmissionBuildError(f"config must be inside a git worktree: {config_path}")
    config = _normalize_config(load_config(config_path))
    source_commit = _assert_clean_git(root)
    artifacts = _collect_artifacts(root, config)
    _validate_artifact_contract(root, config, artifacts)
    gate = _gate(root, config, artifacts, mode)
    manifest = build_manifest(
        root=root, config=config, artifacts=artifacts, gate=gate, source_commit=source_commit
    )
    manifest_errors = _validate_manifest_data(manifest)
    if manifest_errors:
        raise SubmissionBuildError(
            "generated manifest failed validation: " + "; ".join(manifest_errors)
        )
    _write_deterministic_zip(root, output, artifacts, manifest)
    zip_size = output.stat().st_size
    if zip_size > MAX_ZIP_BYTES:
        output.unlink(missing_ok=True)
        raise SubmissionBuildError(f"ZIP exceeds 1200 MiB limit: {zip_size} bytes")
    zip_errors = validate_zip(output, run_extracted_smoke=True)
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
        "gate": gate.as_dict(),
        "portal_receipt": None,
        "selection_claim": False,
    }
    if report_path is None:
        report_path = output.with_name(output.name + REPORT_SUFFIX)
    report_path.write_bytes(_canonical_json(report))
    return report


def _validate_manifest_data(manifest: dict[str, Any]) -> list[str]:
    messages = _schema_messages(manifest, MANIFEST_SCHEMA_PATH)
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
            gate = manifest.get("gate")
            if isinstance(integrity, dict) and isinstance(gate, dict):
                expected_binding = sha256_bytes(
                    _canonical_json({"artifact_inventory": inventory, "gate": gate})
                )
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
