"""Deterministic public quality and safety contract suite.

The suite deliberately measures structural contracts over synthetic fixtures. It
does not estimate legal accuracy, production security, or runtime performance.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable, Mapping
from datetime import UTC, date, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import Any

from proofflow import __version__ as proofflow_version
from proofflow.canonical import sha256_bytes, sha256_digest, sha256_file
from proofflow.contracts import (
    CalculateRequest,
    CaseManifest,
    EvidenceIngestRequest,
    RuleCatalog,
    RuleRetrieveOutput,
    RuleRetrieveRequest,
)
from proofflow.models import (
    ApprovalDecision,
    EvidenceObject,
    FactStatus,
    SkillContext,
    SkillStatus,
)
from proofflow.reference_runtime import (
    ReferenceRunBlocked,
    approve_reference_run,
    package_reference_run,
    prepare_reference_run,
    verify_reference_run,
)
from proofflow.skills import deterministic_calculate, evidence_ingest, rule_retrieve
from proofflow.trusted_store import TrustedArtifactStore

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "examples/cases/happy_path"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
RULE_CATALOG_PATH = ROOT / "data/rules/cn_labor_contract_law.catalog.json"
SCENARIO_MANIFEST_PATH = Path(__file__).with_name("scenarios.json")
FIXED_NOW = datetime(2026, 8, 20, 4, 0, tzinfo=UTC)
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PROVENANCE_DISTRIBUTIONS = (
    "annotated-types",
    "pydantic",
    "pydantic-core",
    "typing-extensions",
    "typing-inspection",
)

ScenarioHandler = Callable[[Path], dict[str, Any]]


class BenchmarkSetupError(RuntimeError):
    """Raised when the frozen public fixture no longer satisfies suite preconditions."""


def load_suite_manifest() -> dict[str, Any]:
    """Load the declarative public scenario manifest."""
    value = json.loads(SCENARIO_MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("scenarios"), list):
        raise BenchmarkSetupError("scenario manifest must contain a scenarios list")
    return value


def _file_binding(relative_path: str, *, root: Path = ROOT) -> dict[str, Any]:
    path = root / relative_path
    return {
        "hash_kind": "UNSIGNED_CONTENT_DIGEST",
        "path": relative_path,
        "sha256": sha256_file(path),
        "signature_verified": False,
    }


def _directory_binding(
    relative_root: str,
    *,
    include_suffixes: frozenset[str] | None = None,
    root: Path = ROOT,
) -> dict[str, Any]:
    base = root / relative_root
    entries: list[dict[str, Any]] = []
    candidates = sorted(
        (path for path in base.rglob("*") if path.is_file() or path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    for path in candidates:
        if "__pycache__" in path.parts or path.name == ".DS_Store":
            continue
        if include_suffixes is not None and path.suffix not in include_suffixes:
            continue
        relative_path = path.relative_to(root).as_posix()
        if path.is_symlink():
            digest = sha256_bytes(os.fsencode(os.readlink(path)))
            kind = "SYMLINK_TARGET"
        else:
            digest = sha256_file(path)
            kind = "FILE"
        entries.append({"kind": kind, "path": relative_path, "sha256": digest})
    return {
        "bundle_sha256": sha256_digest(entries),
        "file_count": len(entries),
        "files": entries,
        "hash_kind": "UNSIGNED_CONTENT_DIGEST",
        "root": relative_root,
        "signature_verified": False,
    }


def _git_bytes(*arguments: str, root: Path = ROOT) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotepath=false", *arguments],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _git_text(*arguments: str, root: Path = ROOT) -> str | None:
    value = _git_bytes(*arguments, root=root)
    if value is None:
        return None
    try:
        return value.decode("ascii").strip()
    except UnicodeDecodeError:
        return None


def _working_tree_bundle(*, root: Path = ROOT) -> dict[str, Any]:
    raw_paths = _git_bytes(
        "ls-files", "-z", "--cached", "--others", "--exclude-standard", root=root
    )
    if raw_paths is None:
        return {"bundle_sha256": None, "captured": False, "file_count": None}

    entries: list[dict[str, Any]] = []
    for raw_path in sorted(set(raw_paths.split(b"\0")) - {b""}):
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            return {"bundle_sha256": None, "captured": False, "file_count": None}
        path = root / relative
        if path.is_symlink():
            digest = sha256_bytes(os.fsencode(os.readlink(path)))
            kind = "SYMLINK_TARGET"
            mode = path.lstat().st_mode & 0o7777
        elif path.is_file():
            digest = sha256_file(path)
            kind = "FILE"
            mode = path.stat().st_mode & 0o7777
        else:
            digest = None
            kind = "MISSING"
            mode = None
        entries.append(
            {
                "kind": kind,
                "mode": mode,
                "path_bytes_hex": raw_path.hex(),
                "sha256": digest,
            }
        )
    return {
        "bundle_sha256": sha256_digest(entries),
        "captured": True,
        "file_count": len(entries),
    }


def _git_provenance(*, root: Path = ROOT) -> dict[str, Any]:
    commit = _git_text("rev-parse", "--verify", "HEAD", root=root)
    tree = _git_text("rev-parse", "--verify", "HEAD^{tree}", root=root)
    object_format = _git_text("rev-parse", "--show-object-format", root=root)
    status = _git_bytes("status", "--porcelain=v1", "-z", "--untracked-files=all", root=root)
    return {
        "available": commit is not None and tree is not None and status is not None,
        "dirty": bool(status) if status is not None else None,
        "dirty_paths_disclosed": False,
        "dirty_status_digest": sha256_bytes(status) if status is not None else None,
        "head_commit": commit,
        "head_tree": tree,
        "object_format": object_format,
        "signature_verified": False,
        "working_tree": _working_tree_bundle(root=root),
    }


def _normalized_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _locked_distribution_versions(*, root: Path = ROOT) -> dict[str, tuple[str, ...]] | None:
    try:
        with (root / "uv.lock").open("rb") as lock_file:
            lock_data = tomllib.load(lock_file)
    except (OSError, tomllib.TOMLDecodeError):
        return None

    versions: dict[str, set[str]] = {}
    for package in lock_data.get("package", []):
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            versions.setdefault(_normalized_distribution_name(name), set()).add(version)
    return {name: tuple(sorted(values)) for name, values in sorted(versions.items())}


def _python_provenance() -> dict[str, Any]:
    version_info = sys.version_info
    return {
        "cache_tag": sys.implementation.cache_tag,
        "implementation": sys.implementation.name,
        "version": platform.python_version(),
        "version_info": {
            "major": version_info.major,
            "micro": version_info.micro,
            "minor": version_info.minor,
            "releaselevel": version_info.releaselevel,
            "serial": version_info.serial,
        },
    }


def _dependency_provenance(*, root: Path = ROOT) -> dict[str, Any]:
    locked_versions = _locked_distribution_versions(root=root)
    distributions: list[dict[str, Any]] = []
    for requested_name in PROVENANCE_DISTRIBUTIONS:
        normalized_name = _normalized_distribution_name(requested_name)
        try:
            installed_version = metadata.version(requested_name)
        except metadata.PackageNotFoundError:
            installed_version = None
        expected_versions = locked_versions.get(normalized_name, ()) if locked_versions else ()
        distributions.append(
            {
                "installed_version": installed_version,
                "locked_versions": list(expected_versions),
                "matches_uv_lock": (
                    installed_version is not None and installed_version in expected_versions
                ),
                "name": requested_name,
            }
        )
    return {
        "all_installed_versions_match_uv_lock": bool(distributions)
        and all(item["matches_uv_lock"] for item in distributions),
        "distributions": distributions,
        "installed_metadata_is_signed": False,
        "source": "LOCAL_INSTALLED_DISTRIBUTION_METADATA",
        "uv_lock_parsed": locked_versions is not None,
    }


def _runtime_image_provenance() -> dict[str, Any]:
    asserted_digest = os.environ.get("PROOFFLOW_RUNTIME_IMAGE_DIGEST")
    if asserted_digest is not None and IMAGE_DIGEST_PATTERN.fullmatch(asserted_digest):
        return {
            "digest": asserted_digest,
            "source": "UNVERIFIED_ENVIRONMENT_ASSERTION",
            "verified": False,
        }
    return {"digest": None, "source": None, "verified": False}


def _provenance(*, root: Path = ROOT) -> dict[str, Any]:
    return {
        "benchmark_sources": _directory_binding(
            "benchmarks",
            include_suffixes=frozenset({".json", ".md", ".py"}),
            root=root,
        ),
        "dependencies": _dependency_provenance(root=root),
        "fixtures": _directory_binding("examples/cases", root=root),
        "git": _git_provenance(root=root),
        "hashes_are_digital_signatures": False,
        "python": _python_provenance(),
        "rules": _directory_binding("data/rules", root=root),
        "runtime_image": _runtime_image_provenance(),
        "scenario_manifest": _file_binding("benchmarks/scenarios.json", root=root),
        "uv_lock": _file_binding("uv.lock", root=root),
    }


def _load_case_manifest() -> CaseManifest:
    return CaseManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))


def _load_rule_catalog() -> RuleCatalog:
    return RuleCatalog.model_validate_json(RULE_CATALOG_PATH.read_text(encoding="utf-8"))


def _context(identity: str, key: str) -> SkillContext:
    return SkillContext(
        tenant_id="tenant-public-demo",
        case_id="case-happy-001",
        caller_identity=identity,
        trace_id="trace-public-benchmark",
        idempotency_key=key,
        expected_state_version=0,
    )


def _issue_codes(result: Any) -> list[str]:
    return sorted({issue.code for issue in result.issues})


def _ingest_fixture_evidence() -> tuple[EvidenceObject, ...]:
    manifest = _load_case_manifest()
    evidence: list[EvidenceObject] = []
    for document in manifest.documents:
        document_path = FIXTURE_DIR / document.path
        result = evidence_ingest(
            _context("PF-A2", f"benchmark-evidence:{document.document_id}"),
            EvidenceIngestRequest(
                document_id=document.document_id,
                media_type=document.media_type,
                declared_sha256=document.sha256,
                raw_content=document_path.read_bytes(),
            ),
            now=FIXED_NOW,
        )
        if result.status != SkillStatus.SUCCESS or result.value is None:
            raise BenchmarkSetupError("frozen evidence fixture did not ingest successfully")
        evidence.extend(result.value.evidence_objects)
    return tuple(evidence)


def _retrieve_fixture_rules() -> RuleRetrieveOutput:
    manifest = _load_case_manifest()
    result = rule_retrieve(
        _context("PF-A3", "benchmark-rules"),
        RuleRetrieveRequest(
            issue_codes=manifest.issue_codes,
            jurisdiction=manifest.jurisdiction,
            as_of_date=manifest.as_of_date,
        ),
        catalog=_load_rule_catalog(),
        now=FIXED_NOW,
    )
    if result.status != SkillStatus.SUCCESS or result.value is None:
        raise BenchmarkSetupError("frozen rule fixture did not resolve successfully")
    return result.value


def _trusted_store(evidence: tuple[EvidenceObject, ...]) -> TrustedArtifactStore:
    store = TrustedArtifactStore()
    store.register_all(evidence)
    return store


def _prepare_run(run_dir: Path) -> None:
    prepare_reference_run(
        manifest_path=MANIFEST_PATH,
        rule_catalog_path=RULE_CATALOG_PATH,
        run_dir=run_dir,
        now=FIXED_NOW,
    )


def _approve_run(run_dir: Path) -> None:
    approve_reference_run(
        run_dir=run_dir,
        approver_id="synthetic-benchmark-reviewer",
        approver_role="legal-reviewer",
        decision=ApprovalDecision.APPROVE,
        reason="Reviewed the frozen synthetic benchmark artifacts.",
        now=FIXED_NOW + timedelta(minutes=1),
    )


def _happy_path(run_dir: Path) -> dict[str, Any]:
    _prepare_run(run_dir)
    _approve_run(run_dir)
    package_reference_run(run_dir=run_dir, now=FIXED_NOW + timedelta(minutes=2))
    verification = verify_reference_run(run_dir)
    state = json.loads((run_dir / "run-state.json").read_text(encoding="utf-8"))
    return {
        "approval_record_present": (run_dir / "artifacts/approval-record.json").is_file(),
        "external_side_effects_enabled": state["external_side_effects_enabled"],
        "stage": state["stage"],
        "verification_valid": verification.valid,
    }


def _missing_parameter(_workspace: Path) -> dict[str, Any]:
    evidence = tuple(
        item for item in _ingest_fixture_evidence() if item.field_name != "monthly_wage_average"
    )
    rules = _retrieve_fixture_rules()
    result = deterministic_calculate(
        _context("PF-A4", "benchmark-missing-parameter"),
        CalculateRequest(
            evidence=evidence,
            rule_citations=rules.citations,
            rule_scope=rules.rule_scope,
        ),
        catalog=_load_rule_catalog(),
        trusted_artifacts=_trusted_store(evidence),
        now=FIXED_NOW,
    )
    return {
        "issue_codes": _issue_codes(result),
        "skill_status": result.status.value,
        "value_emitted": result.value is not None,
    }


def _rule_scope_and_time(_workspace: Path) -> dict[str, Any]:
    catalog = _load_rule_catalog()
    issue_codes = ("economic_compensation_amount",)
    foreign = rule_retrieve(
        _context("PF-A3", "benchmark-foreign-rule"),
        RuleRetrieveRequest(
            issue_codes=issue_codes,
            jurisdiction="US-CA",
            as_of_date=date(2025, 8, 31),
        ),
        catalog=catalog,
        now=FIXED_NOW,
    )
    target_rule = next(record for record in catalog.rules if record.issue_code in issue_codes)
    expired_rule = target_rule.model_copy(update={"effective_to": date(2024, 12, 31)})
    expired_catalog = catalog.model_copy(
        update={
            "rules": tuple(
                expired_rule if record.rule_id == target_rule.rule_id else record
                for record in catalog.rules
            )
        }
    )
    expired = rule_retrieve(
        _context("PF-A3", "benchmark-expired-rule"),
        RuleRetrieveRequest(
            issue_codes=issue_codes,
            jurisdiction="CN-ZJ-HZ",
            as_of_date=date(2025, 8, 31),
        ),
        catalog=expired_catalog,
        now=FIXED_NOW,
    )
    return {
        "expired_citation_count": len(expired.value.citations) if expired.value else 0,
        "expired_issue_codes": _issue_codes(expired),
        "expired_status": expired.status.value,
        "foreign_citation_count": len(foreign.value.citations) if foreign.value else 0,
        "foreign_issue_codes": _issue_codes(foreign),
        "foreign_status": foreign.status.value,
    }


def _parser_field_allowlist(_workspace: Path) -> dict[str, Any]:
    manifest = _load_case_manifest()
    document = next(item for item in manifest.documents if item.path == "termination_notice.json")
    document_path = FIXTURE_DIR / document.path
    result = evidence_ingest(
        _context("PF-A2", "benchmark-prompt-injection"),
        EvidenceIngestRequest(
            document_id=document.document_id,
            media_type=document.media_type,
            declared_sha256=document.sha256,
            raw_content=document_path.read_bytes(),
        ),
        now=FIXED_NOW,
    )
    ignored_fields = result.value.ignored_fields if result.value else ()
    evidence_fields = (
        {item.field_name for item in result.value.evidence_objects} if result.value else set()
    )
    return {
        "instruction_like_field_extracted": "untrusted_document_text" in evidence_fields,
        "instruction_like_field_ignored": "untrusted_document_text" in ignored_fields,
        "skill_status": result.status.value,
    }


def _evidence_tamper(_workspace: Path) -> dict[str, Any]:
    document_path = FIXTURE_DIR / "contract.json"
    result = evidence_ingest(
        _context("PF-A2", "benchmark-evidence-tamper"),
        EvidenceIngestRequest(
            document_id="doc-contract-001",
            media_type="application/json",
            declared_sha256="sha256:" + "0" * 64,
            raw_content=document_path.read_bytes(),
        ),
        now=FIXED_NOW,
    )
    return {
        "evidence_emitted": result.value is not None,
        "issue_codes": _issue_codes(result),
        "skill_status": result.status.value,
    }


def _approval_toctou(run_dir: Path) -> dict[str, Any]:
    _prepare_run(run_dir)
    proposals_path = run_dir / "artifacts/proposals.json"
    proposals = json.loads(proposals_path.read_text(encoding="utf-8"))
    proposals[0]["summary"] += " [FAULT_INJECTION]"
    proposals_path.write_text(
        json.dumps(proposals, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    blocked_stage = ""
    blocked_issue_codes: list[str] = []
    try:
        _approve_run(run_dir)
    except ReferenceRunBlocked as exc:
        blocked_stage = exc.stage
        blocked_issue_codes = _issue_codes(exc.result)

    state = json.loads((run_dir / "run-state.json").read_text(encoding="utf-8"))
    return {
        "approval_record_present": (run_dir / "artifacts/approval-record.json").is_file(),
        "blocked_issue_codes": blocked_issue_codes,
        "blocked_stage": blocked_stage,
        "stage_after_attempt": state["stage"],
    }


def _package_tamper(run_dir: Path) -> dict[str, Any]:
    _prepare_run(run_dir)
    _approve_run(run_dir)
    package_reference_run(run_dir=run_dir, now=FIXED_NOW + timedelta(minutes=2))
    draft_path = run_dir / "package/review-draft.md"
    draft_path.write_text(
        draft_path.read_text(encoding="utf-8") + "\n[FAULT_INJECTION]\n",
        encoding="utf-8",
    )
    verification = verify_reference_run(run_dir)
    return {
        "package_hash_mismatch_detected": (
            "package file hash mismatch: review-draft.md" in verification.errors
        ),
        "verification_valid": verification.valid,
    }


def _replace_evidence(
    evidence: tuple[EvidenceObject, ...],
    original: EvidenceObject,
    replacement: EvidenceObject,
) -> tuple[EvidenceObject, ...]:
    return tuple(
        replacement if item.meta.artifact_id == original.meta.artifact_id else item
        for item in evidence
    )


def _calculation_guard_observation(
    evidence: tuple[EvidenceObject, ...],
    key: str,
    *,
    registered_evidence: tuple[EvidenceObject, ...],
) -> dict[str, Any]:
    rules = _retrieve_fixture_rules()
    result = deterministic_calculate(
        _context("PF-A4", key),
        CalculateRequest(
            evidence=evidence,
            rule_citations=rules.citations,
            rule_scope=rules.rule_scope,
        ),
        catalog=_load_rule_catalog(),
        trusted_artifacts=_trusted_store(registered_evidence),
        now=FIXED_NOW,
    )
    return {
        "blocked": result.status == SkillStatus.BLOCKED,
        "blocker_issue_present": any(issue.severity == "BLOCKER" for issue in result.issues),
        "issue_codes": _issue_codes(result),
        "value_emitted": result.value is not None,
    }


def _seal_tamper(_workspace: Path) -> dict[str, Any]:
    evidence = _ingest_fixture_evidence()
    original = next(item for item in evidence if item.field_name == "monthly_wage_average")
    tampered = original.model_copy(update={"normalized_value": "99999.00"})
    observed = _calculation_guard_observation(
        _replace_evidence(evidence, original, tampered),
        "benchmark-seal-tamper",
        registered_evidence=evidence,
    )
    return {**observed, "input_hash_valid": tampered.verify_hash()}


def _resealed_value_tamper(_workspace: Path) -> dict[str, Any]:
    evidence = _ingest_fixture_evidence()
    original = next(item for item in evidence if item.field_name == "monthly_wage_average")
    resealed = original.model_copy(
        update={
            "normalized_value": "99999.00",
            "meta": original.meta.model_copy(update={"content_hash": None}),
        }
    ).seal()
    observed = _calculation_guard_observation(
        _replace_evidence(evidence, original, resealed),
        "benchmark-resealed-value-tamper",
        registered_evidence=evidence,
    )
    return {
        **observed,
        "input_hash_valid": resealed.verify_hash(),
        "same_context": (
            resealed.meta.tenant_id,
            resealed.meta.case_id,
            resealed.meta.trace_id,
        )
        == ("tenant-public-demo", "case-happy-001", "trace-public-benchmark"),
    }


def _cross_tenant_calculation(_workspace: Path) -> dict[str, Any]:
    evidence = _ingest_fixture_evidence()
    original = next(item for item in evidence if item.field_name == "monthly_wage_average")
    cross_tenant = original.model_copy(
        update={
            "meta": original.meta.model_copy(
                update={"content_hash": None, "tenant_id": "tenant-other-synthetic"}
            )
        }
    ).seal()
    modified_evidence = _replace_evidence(evidence, original, cross_tenant)
    observed = _calculation_guard_observation(
        modified_evidence,
        "benchmark-cross-tenant-calculation",
        registered_evidence=evidence,
    )
    cross_tenant_count = sum(
        item.meta.tenant_id != "tenant-public-demo" for item in modified_evidence
    )
    return {**observed, "cross_tenant_input_count": cross_tenant_count}


def _unresolved_calculation_boundary(_workspace: Path) -> dict[str, Any]:
    evidence = _ingest_fixture_evidence()
    original = next(item for item in evidence if item.field_name == "monthly_wage_average")
    unresolved = original.model_copy(
        update={
            "fact_status": FactStatus.UNRESOLVED,
            "meta": original.meta.model_copy(update={"content_hash": None}),
        }
    ).seal()
    modified_evidence = _replace_evidence(evidence, original, unresolved)
    observed = _calculation_guard_observation(
        modified_evidence,
        "benchmark-unresolved-calculation",
        registered_evidence=evidence,
    )
    unresolved_count = sum(item.fact_status == FactStatus.UNRESOLVED for item in modified_evidence)
    return {**observed, "unresolved_input_count": unresolved_count}


SCENARIO_HANDLERS: dict[str, ScenarioHandler] = {
    "happy_path": _happy_path,
    "missing_parameter": _missing_parameter,
    "rule_scope_and_time": _rule_scope_and_time,
    "parser_field_allowlist": _parser_field_allowlist,
    "evidence_tamper": _evidence_tamper,
    "approval_toctou": _approval_toctou,
    "package_tamper": _package_tamper,
    "resealed_value_tamper": _resealed_value_tamper,
    "seal_tamper": _seal_tamper,
    "cross_tenant_calculation": _cross_tenant_calculation,
    "unresolved_calculation_boundary": _unresolved_calculation_boundary,
}


def _mismatches(expected: Any, observed: Any, path: str = "$") -> list[str]:
    """Compare JSON values as a strict recursive closed set.

    No observed field is implicitly allowed. Missing, additional, type-changed,
    length-changed, or value-changed data all fail the contract.
    """
    if type(expected) is not type(observed):
        return [f"{path}:type_mismatch"]
    if isinstance(expected, dict):
        missing = [f"{path}.{key}:missing" for key in sorted(set(expected) - set(observed))]
        unexpected = [f"{path}.{key}:unexpected" for key in sorted(set(observed) - set(expected))]
        nested = [
            mismatch
            for key in sorted(set(expected).intersection(observed))
            for mismatch in _mismatches(expected[key], observed[key], f"{path}.{key}")
        ]
        return missing + unexpected + nested
    if isinstance(expected, list):
        if len(expected) != len(observed):
            return [f"{path}:length_mismatch"]
        return [
            mismatch
            for index, (expected_item, observed_item) in enumerate(
                zip(expected, observed, strict=True)
            )
            for mismatch in _mismatches(expected_item, observed_item, f"{path}[{index}]")
        ]
    return [] if expected == observed else [f"{path}:value_mismatch"]


def _category_summary(results: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    totals: dict[str, dict[str, int]] = {}
    for result in results:
        for contract_class in result["contract_classes"]:
            counts = totals.setdefault(contract_class, {"failed": 0, "passed": 0, "total": 0})
            counts["total"] += 1
            counts["passed" if result["passed"] else "failed"] += 1
    return {key: totals[key] for key in sorted(totals)}


def compute_report_hash(report: Mapping[str, Any]) -> str:
    """Hash the complete report payload except for its self-referential digest field."""
    payload = {key: value for key, value in report.items() if key != "report_hash"}
    return sha256_digest(payload)


def run_suite(workspace: Path) -> dict[str, Any]:
    """Run every frozen scenario in a caller-owned workspace and return a JSON value."""
    workspace.mkdir(parents=True, exist_ok=True)
    manifest = load_suite_manifest()
    results: list[dict[str, Any]] = []

    for index, raw_spec in enumerate(manifest["scenarios"], start=1):
        if not isinstance(raw_spec, dict):
            raise BenchmarkSetupError("each scenario specification must be an object")
        scenario_id = raw_spec.get("id")
        if not isinstance(scenario_id, str):
            raise BenchmarkSetupError("each scenario requires a string id")
        expected = raw_spec.get("expected")
        if not isinstance(expected, dict):
            raise BenchmarkSetupError(f"scenario {scenario_id} requires an expected object")
        handler = SCENARIO_HANDLERS.get(scenario_id)
        scenario_workspace = workspace / f"{index:02d}-{scenario_id}"

        if handler is None:
            observed: dict[str, Any] = {"error_type": "MISSING_SCENARIO_HANDLER"}
            mismatched_fields = ["handler"]
        else:
            try:
                observed = handler(scenario_workspace)
                mismatched_fields = _mismatches(expected, observed)
            except Exception as exc:  # The report must retain other scenario results.
                observed = {"error_type": type(exc).__name__}
                mismatched_fields = ["unexpected_exception"]

        results.append(
            {
                "coverage_boundary": raw_spec.get("coverage_boundary"),
                "contract_classes": raw_spec.get("contract_classes", []),
                "expected": expected,
                "fault": raw_spec.get("fault"),
                "id": scenario_id,
                "mismatched_fields": mismatched_fields,
                "observed": observed,
                "passed": not mismatched_fields,
                "title": raw_spec.get("title"),
            }
        )

    passed = sum(result["passed"] for result in results)
    total = len(results)
    summary = {
        "all_contracts_satisfied": passed == total,
        "by_contract_class": _category_summary(results),
        "contract_pass_fraction": f"{passed}/{total}",
        "failed": total - passed,
        "passed": passed,
        "total": total,
    }
    report = {
        "comparison_policy": manifest["comparison_policy"],
        "data_classification": manifest["data_classification"],
        "excluded_coverage": manifest["excluded_coverage"],
        "fixture_clock": manifest["fixture_clock"],
        "legal_accuracy_measured": manifest["legal_accuracy_measured"],
        "measurement_scope": manifest["measurement_scope"],
        "performance_measured": manifest["performance_measured"],
        "provenance": _provenance(),
        "proofflow_version": proofflow_version,
        "report_hash_semantics": {
            "algorithm": "SHA-256",
            "authenticity_verified": False,
            "digital_signature_present": False,
            "kind": "UNSIGNED_CONTENT_DIGEST",
        },
        "results": results,
        "scenario_manifest_hash": sha256_file(SCENARIO_MANIFEST_PATH),
        "schema_version": "proofflow.benchmark-report/v1",
        "suite_id": manifest["suite_id"],
        "suite_version": manifest["suite_version"],
        "summary": summary,
    }
    return {**report, "report_hash": compute_report_hash(report)}


def render_report(report: dict[str, Any]) -> str:
    """Render stable, machine-readable UTF-8 JSON."""
    return json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
