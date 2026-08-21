"""Synthetic-data-only local runtime for a three-step verifiable reference run."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

from pydantic import Field, model_validator

from proofflow.canonical import canonical_json, canonicalize, sha256_digest, sha256_file
from proofflow.contracts import (
    ApprovalExecuteOutput,
    ApprovalExecuteRequest,
    CalculateRequest,
    CaseManifest,
    ConflictDetectRequest,
    DecisionAuditRequest,
    DocumentPackageOutput,
    DocumentPackageRequest,
    EvidenceIngestRequest,
    ProposalGenerateRequest,
    RuleCatalog,
    RuleRetrieveRequest,
    TimelineBuildRequest,
)
from proofflow.factories import stable_id
from proofflow.models import (
    SCHEMA_VERSION,
    ActorKind,
    ApprovalDecision,
    ApprovalRecord,
    ApprovalRequest,
    AuditReport,
    AuditVerdict,
    CalculationSheet,
    CaseRecord,
    CaseState,
    ConflictReport,
    DataClassification,
    EvidenceObject,
    HumanDecision,
    PackageFile,
    PackageManifest,
    Proposal,
    RuleCitation,
    SkillContext,
    SkillResult,
    SkillStatus,
    StrictModel,
    TimelineEvent,
    TraceEvent,
    artifact_ref,
)
from proofflow.skills import (
    conflict_detect,
    decision_audit,
    deterministic_calculate,
    document_package,
    evidence_ingest,
    human_approval,
    rule_retrieve,
    timeline_build,
)
from proofflow.state_machine import TransitionContext, transition_case
from proofflow.strategy import create_candidate_proposals
from proofflow.trusted_store import TrustedArtifactStore, TrustedArtifactStoreError


class ReferenceRunError(RuntimeError):
    pass


class ReferenceRunBlocked(ReferenceRunError):
    def __init__(self, stage: str, result: SkillResult[Any]) -> None:
        codes = ", ".join(issue.code for issue in result.issues) or result.status.value
        super().__init__(f"reference run blocked at {stage}: {codes}")
        self.stage = stage
        self.result = result


class RunState(StrictModel):
    run_id: str
    trace_id: str
    status: str
    stage: CaseState
    case: CaseRecord
    approval_subject_hash: str
    approval_request_id: str
    agentteams_integrated: bool = False
    external_side_effects_enabled: bool = False
    created_at: datetime
    updated_at: datetime
    artifact_paths: dict[str, str]

    @model_validator(mode="after")
    def require_reference_runtime_invariants(self) -> RunState:
        if self.stage != self.case.state:
            raise ValueError("run stage must match the embedded case state")
        if self.agentteams_integrated:
            raise ValueError("reference runtime state cannot claim AgentTeams integration")
        if self.external_side_effects_enabled:
            raise ValueError("reference runtime state cannot enable external side effects")
        if self.status != "REFERENCE_RUNTIME_ONLY":
            raise ValueError("reference runtime state has an unsupported status")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("reference runtime creation time must be timezone-aware")
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() is None:
            raise ValueError("reference runtime update time must be timezone-aware")
        if self.updated_at < self.created_at:
            raise ValueError("reference runtime update time cannot precede creation")
        if self.stage not in {
            CaseState.AWAITING_APPROVAL,
            CaseState.APPROVED,
            CaseState.REJECTED,
            CaseState.REVISION_REQUIRED,
            CaseState.PACKAGED,
        }:
            raise ValueError("reference runtime state has an unsupported persisted stage")
        return self


class VerificationReport(StrictModel):
    valid: bool
    checked_artifacts: int = Field(ge=0)
    checked_package_files: int = Field(ge=0)
    errors: tuple[str, ...]


APPROVAL_POLICY_VERSION = "approval-policy-v0.1"
APPROVAL_REQUIRED_ROLE = "legal-reviewer"
APPROVAL_TTL = timedelta(hours=24)


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, value: Any) -> None:
    rendered = (
        json.dumps(canonicalize(value), ensure_ascii=False, sort_keys=True, indent=2).encode(
            "utf-8"
        )
        + b"\n"
    )
    _atomic_write(path, rendered)


def _write_trace(path: Path, events: list[TraceEvent]) -> None:
    payload = b"".join(canonical_json(event) + b"\n" for event in events)
    _atomic_write(path, payload)


def _safe_document_path(base: Path, relative_path: str) -> Path:
    candidate = (base / relative_path).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise ReferenceRunError(
            f"document path escapes the fixture directory: {relative_path}"
        ) from exc
    if not candidate.is_file():
        raise ReferenceRunError(f"document does not exist: {candidate}")
    return candidate


def _safe_run_path(
    run_dir: Path,
    relative_path: str,
    *,
    require_file: bool,
) -> Path:
    relative = Path(relative_path)
    if (
        not relative_path
        or relative.is_absolute()
        or relative == Path(".")
        or ".." in relative.parts
    ):
        raise ReferenceRunError(f"unsafe run artifact path: {relative_path}")
    root = run_dir.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ReferenceRunError(
            f"run artifact path escapes run directory: {relative_path}"
        ) from exc
    if require_file and not candidate.is_file():
        raise ReferenceRunError(f"run artifact does not exist: {relative_path}")
    return candidate


def _state_artifact_path(
    run_dir: Path,
    state: RunState,
    key: str,
    *,
    require_file: bool = True,
) -> Path:
    relative_path = state.artifact_paths.get(key)
    if relative_path is None:
        raise ReferenceRunError(f"run artifact path is missing: {key}")
    return _safe_run_path(run_dir, relative_path, require_file=require_file)


def _require_success[T](stage: str, result: SkillResult[T]) -> T:
    if result.status != SkillStatus.SUCCESS or result.value is None:
        raise ReferenceRunBlocked(stage, cast(SkillResult[Any], result))
    return result.value


def _skill_event(
    *,
    result: SkillResult[Any],
    sequence: int,
    trace_id: str,
    case: CaseRecord,
    actor_identity: str,
    event_type: str,
    now: datetime,
) -> TraceEvent:
    return TraceEvent(
        sequence=sequence,
        trace_id=trace_id,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        actor_identity=actor_identity,
        actor_kind=ActorKind.AGENT,
        event_type=event_type,
        input_hash=result.input_hash,
        output_hash=result.output_hash,
        status=result.status.value,
        occurred_at=now,
        error_code=result.issues[0].code if result.issues else None,
    )


def _subject_hash(
    *,
    manifest: CaseManifest,
    case: CaseRecord,
    evidence: tuple[EvidenceObject, ...],
    timeline: tuple[TimelineEvent, ...],
    rules: tuple[RuleCitation, ...],
    calculation: CalculationSheet,
    conflict_report: ConflictReport,
    proposals: tuple[Proposal, ...],
    audit_report: AuditReport,
    skill_results: Any,
    trace: tuple[TraceEvent, ...],
) -> str:
    return sha256_digest(
        {
            "manifest": manifest,
            "case": case,
            "evidence": evidence,
            "timeline": timeline,
            "rules": rules,
            "calculation": calculation,
            "conflict_report": conflict_report,
            "proposals": proposals,
            "audit_report": audit_report,
            "skill_results": skill_results,
            "trace": trace,
        }
    )


def _approval_trace_prefix(trace: list[TraceEvent]) -> tuple[TraceEvent, ...]:
    for index, event in enumerate(trace):
        if event.event_type == "skill.human_approval":
            return tuple(trace[:index])
    return tuple(trace)


def _expected_approval_request(
    *,
    audit_report: AuditReport,
    approval_subject_hash: str,
) -> ApprovalRequest:
    return ApprovalRequest(
        request_id=stable_id(
            "approval-request",
            {
                "policy_version": APPROVAL_POLICY_VERSION,
                "trace_id": audit_report.meta.trace_id,
                "subject": approval_subject_hash,
            },
        ),
        tenant_id=audit_report.meta.tenant_id,
        case_id=audit_report.meta.case_id,
        trace_id=audit_report.meta.trace_id,
        artifact_ref=f"ApprovalSubject:{audit_report.meta.trace_id}",
        artifact_hash=approval_subject_hash,
        audit_report_ref=artifact_ref(audit_report),
        required_role=APPROVAL_REQUIRED_ROLE,
        created_at=audit_report.meta.created_at,
        expires_at=audit_report.meta.created_at + APPROVAL_TTL,
    )


def _approval_request_binding_errors(
    *,
    state: RunState,
    approval_request: ApprovalRequest,
    expected: ApprovalRequest,
) -> list[str]:
    errors: list[str] = []
    if state.approval_subject_hash != expected.artifact_hash:
        errors.append("run state approval subject does not match deterministic policy")
    if state.approval_request_id != expected.request_id:
        errors.append("run state approval request id does not match deterministic policy")
    if state.trace_id != expected.trace_id:
        errors.append("run state trace id does not match deterministic policy")
    if state.case.tenant_id != expected.tenant_id or state.case.case_id != expected.case_id:
        errors.append("run state tenant or case does not match deterministic policy")
    if state.created_at != expected.created_at:
        errors.append("run state creation time does not match deterministic policy")
    if approval_request != expected:
        errors.append("approval request does not match deterministic policy")
    return errors


def _approval_record_binding_errors(
    *,
    approval_record: ApprovalRecord,
    expected: ApprovalRequest,
) -> list[str]:
    errors: list[str] = []
    expected_sources = (
        f"ApprovalRequest:{expected.request_id}",
        expected.artifact_ref,
        expected.audit_report_ref,
    )
    expected_artifact_id = stable_id(
        "approval",
        {
            "request_id": expected.request_id,
            "decision": approval_record.decision,
            "actor_id": approval_record.approver_id,
            "artifact_hash": expected.artifact_hash,
        },
    )
    if approval_record.meta.artifact_id != expected_artifact_id:
        errors.append("approval record artifact id mismatch")
    if approval_record.request_id != expected.request_id:
        errors.append("approval record request id mismatch")
    if approval_record.approver_role != expected.required_role:
        errors.append("approval record role mismatch")
    if approval_record.approved_artifact_hash != expected.artifact_hash:
        errors.append("approval record subject hash mismatch")
    if approval_record.expires_at != expected.expires_at:
        errors.append("approval record expiry mismatch")
    if approval_record.decided_at < expected.created_at:
        errors.append("approval record decision occurred before request creation")
    if approval_record.decided_at > expected.expires_at:
        errors.append("approval record decision occurred after expiry")
    if approval_record.meta.created_at != approval_record.decided_at:
        errors.append("approval record metadata time mismatch")
    if approval_record.meta.tenant_id != expected.tenant_id:
        errors.append("approval record tenant mismatch")
    if approval_record.meta.case_id != expected.case_id:
        errors.append("approval record case mismatch")
    if approval_record.meta.trace_id != expected.trace_id:
        errors.append("approval record trace mismatch")
    if approval_record.meta.source_refs != expected_sources:
        errors.append("approval record source binding mismatch")
    if approval_record.meta.producer_identity != f"HUMAN:{approval_record.approver_id}":
        errors.append("approval record producer identity mismatch")
    if approval_record.meta.classification != DataClassification.PUBLIC_SYNTHETIC:
        errors.append("approval record classification mismatch")
    if approval_record.meta.schema_version != SCHEMA_VERSION:
        errors.append("approval record schema version mismatch")
    if approval_record.approval_method != "LOCAL_DEMO":
        errors.append("approval record method mismatch")
    return errors


def _context(
    *,
    case: CaseRecord,
    trace_id: str,
    caller: str,
    idempotency_key: str,
) -> SkillContext:
    return SkillContext(
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        caller_identity=caller,
        trace_id=trace_id,
        idempotency_key=idempotency_key,
        expected_state_version=case.state_version,
    )


def prepare_reference_run(
    *,
    manifest_path: Path,
    rule_catalog_path: Path,
    run_dir: Path,
    now: datetime | None = None,
) -> RunState:
    """Prepare a synthetic run and stop at AWAITING_APPROVAL."""
    now = now or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ReferenceRunError("now must be timezone-aware")
    if run_dir.exists():
        raise ReferenceRunError(f"run directory already exists: {run_dir}")

    manifest = CaseManifest.model_validate(_load_json(manifest_path))
    if manifest.fixture_status != "SYNTHETIC":
        raise ReferenceRunError("the reference runtime accepts only SYNTHETIC fixtures")
    catalog = RuleCatalog.model_validate(_load_json(rule_catalog_path))
    manifest_hash = sha256_digest(manifest)
    run_id = stable_id(
        "run", {"manifest_hash": manifest_hash, "prepared_at": now, "case_id": manifest.case_id}
    )
    trace_id = stable_id("trace", {"run_id": run_id})
    case = CaseRecord(
        case_id=manifest.case_id,
        tenant_id=manifest.tenant_id,
        jurisdiction=manifest.jurisdiction,
        as_of_date=manifest.as_of_date,
        input_manifest_hash=manifest_hash,
    )
    trace: list[TraceEvent] = []
    skill_results: list[SkillResult[Any]] = []

    case, event = transition_case(
        case,
        target=CaseState.INGESTING,
        expected_state_version=case.state_version,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id=trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(manifest_valid=True, input_hashes_match=True),
    )
    trace.append(event)

    evidence_items: list[EvidenceObject] = []
    trusted_artifacts = TrustedArtifactStore()
    fixture_base = manifest_path.resolve().parent
    for index, document in enumerate(manifest.documents, start=1):
        document_path = _safe_document_path(fixture_base, document.path)
        raw = document_path.read_bytes()
        if sha256_file(document_path) != document.sha256:
            raise ReferenceRunError(f"manifest hash mismatch for {document.path}")
        request = EvidenceIngestRequest(
            document_id=document.document_id,
            media_type=document.media_type,
            declared_sha256=document.sha256,
            raw_content=raw,
        )
        result = evidence_ingest(
            _context(
                case=case,
                trace_id=trace_id,
                caller="PF-A2",
                idempotency_key=f"{run_id}:evidence:{index}",
            ),
            request,
            now=now,
        )
        skill_results.append(cast(SkillResult[Any], result))
        trace.append(
            _skill_event(
                result=cast(SkillResult[Any], result),
                sequence=len(trace) + 1,
                trace_id=trace_id,
                case=case,
                actor_identity="PF-A2",
                event_type="skill.evidence_ingest",
                now=now,
            )
        )
        evidence_output = _require_success("evidence_ingest", result)
        try:
            trusted_artifacts.register_all(evidence_output.evidence_objects)
        except TrustedArtifactStoreError as exc:
            raise ReferenceRunError("trusted Evidence registration failed") from exc
        evidence_items.extend(evidence_output.evidence_objects)
    evidence = tuple(evidence_items)

    timeline_result = timeline_build(
        _context(
            case=case,
            trace_id=trace_id,
            caller="PF-A2",
            idempotency_key=f"{run_id}:timeline",
        ),
        TimelineBuildRequest(evidence=evidence),
        now=now,
    )
    skill_results.append(cast(SkillResult[Any], timeline_result))
    trace.append(
        _skill_event(
            result=cast(SkillResult[Any], timeline_result),
            sequence=len(trace) + 1,
            trace_id=trace_id,
            case=case,
            actor_identity="PF-A2",
            event_type="skill.timeline_build",
            now=now,
        )
    )
    timeline = _require_success("timeline_build", timeline_result).events

    case, event = transition_case(
        case,
        target=CaseState.FACTS_READY,
        expected_state_version=case.state_version,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id=trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(evidence_complete=bool(evidence), has_blocking_issue=False),
    )
    trace.append(event)

    rule_result = rule_retrieve(
        _context(
            case=case,
            trace_id=trace_id,
            caller="PF-A3",
            idempotency_key=f"{run_id}:rules",
        ),
        RuleRetrieveRequest(
            issue_codes=manifest.issue_codes,
            jurisdiction=manifest.jurisdiction,
            as_of_date=manifest.as_of_date,
        ),
        catalog=catalog,
        now=now,
    )
    skill_results.append(cast(SkillResult[Any], rule_result))
    trace.append(
        _skill_event(
            result=cast(SkillResult[Any], rule_result),
            sequence=len(trace) + 1,
            trace_id=trace_id,
            case=case,
            actor_identity="PF-A3",
            event_type="skill.rule_retrieve",
            now=now,
        )
    )
    rule_output = _require_success("rule_retrieve", rule_result)
    rules = rule_output.citations

    case, event = transition_case(
        case,
        target=CaseState.RULES_READY,
        expected_state_version=case.state_version,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id=trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(rules_valid=bool(rules), has_blocking_issue=False),
    )
    trace.append(event)

    calculation_result = deterministic_calculate(
        _context(
            case=case,
            trace_id=trace_id,
            caller="PF-A4",
            idempotency_key=f"{run_id}:calculation",
        ),
        CalculateRequest(
            evidence=evidence,
            rule_citations=rules,
            rule_scope=rule_output.rule_scope,
        ),
        catalog=catalog,
        trusted_artifacts=trusted_artifacts,
        now=now,
    )
    skill_results.append(cast(SkillResult[Any], calculation_result))
    trace.append(
        _skill_event(
            result=cast(SkillResult[Any], calculation_result),
            sequence=len(trace) + 1,
            trace_id=trace_id,
            case=case,
            actor_identity="PF-A4",
            event_type="skill.deterministic_calculate",
            now=now,
        )
    )
    calculation = _require_success("deterministic_calculate", calculation_result).sheet

    case, event = transition_case(
        case,
        target=CaseState.CALC_READY,
        expected_state_version=case.state_version,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id=trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(
            calculation_complete=calculation.total is not None and calculation.verify_hash(),
            has_blocking_issue=False,
        ),
    )
    trace.append(event)

    proposal_result = create_candidate_proposals(
        _context(
            case=case,
            trace_id=trace_id,
            caller="PF-A5",
            idempotency_key=f"{run_id}:proposal",
        ),
        ProposalGenerateRequest(evidence=evidence, rules=rules, calculation=calculation),
        now=now,
    )
    skill_results.append(cast(SkillResult[Any], proposal_result))
    trace.append(
        _skill_event(
            result=cast(SkillResult[Any], proposal_result),
            sequence=len(trace) + 1,
            trace_id=trace_id,
            case=case,
            actor_identity="PF-A5",
            event_type="strategy.proposal_generate",
            now=now,
        )
    )
    proposals = _require_success("proposal_generate", proposal_result).proposals

    case, event = transition_case(
        case,
        target=CaseState.PROPOSAL_READY,
        expected_state_version=case.state_version,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id=trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(proposal_complete=bool(proposals)),
    )
    trace.append(event)

    conflict_result = conflict_detect(
        _context(
            case=case,
            trace_id=trace_id,
            caller="PF-A6",
            idempotency_key=f"{run_id}:conflict",
        ),
        ConflictDetectRequest(evidence=evidence, rules=rules, calculation=calculation),
        now=now,
    )
    skill_results.append(cast(SkillResult[Any], conflict_result))
    trace.append(
        _skill_event(
            result=cast(SkillResult[Any], conflict_result),
            sequence=len(trace) + 1,
            trace_id=trace_id,
            case=case,
            actor_identity="PF-A6",
            event_type="skill.conflict_detect",
            now=now,
        )
    )
    conflict_report = _require_success("conflict_detect", conflict_result).report

    audit_result = decision_audit(
        _context(
            case=case,
            trace_id=trace_id,
            caller="PF-A6",
            idempotency_key=f"{run_id}:audit",
        ),
        DecisionAuditRequest(
            proposals=proposals,
            evidence=evidence,
            rules=rules,
            calculation=calculation,
            conflict_report=conflict_report,
            observed_event_types=tuple(event.event_type for event in trace),
        ),
        now=now,
    )
    skill_results.append(cast(SkillResult[Any], audit_result))
    trace.append(
        _skill_event(
            result=cast(SkillResult[Any], audit_result),
            sequence=len(trace) + 1,
            trace_id=trace_id,
            case=case,
            actor_identity="PF-A6",
            event_type="skill.decision_audit",
            now=now,
        )
    )
    audit_report = _require_success("decision_audit", audit_result).report
    if audit_report.verdict != AuditVerdict.PASS:
        raise ReferenceRunError("the reference run did not pass structural audit")

    case, event = transition_case(
        case,
        target=CaseState.AWAITING_APPROVAL,
        expected_state_version=case.state_version,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id=trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(
            audit_verdict=audit_report.verdict,
            has_blocking_issue=False,
        ),
    )
    trace.append(event)

    subject_hash = _subject_hash(
        manifest=manifest,
        case=case,
        evidence=evidence,
        timeline=timeline,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
        skill_results=skill_results,
        trace=tuple(trace),
    )
    approval_request = _expected_approval_request(
        audit_report=audit_report,
        approval_subject_hash=subject_hash,
    )

    paths = {
        "manifest": "input/manifest.json",
        "evidence": "artifacts/evidence.json",
        "timeline": "artifacts/timeline.json",
        "rules": "artifacts/rules.json",
        "calculation": "artifacts/calculation.json",
        "proposals": "artifacts/proposals.json",
        "conflict_report": "artifacts/conflict-report.json",
        "audit_report": "artifacts/audit-report.json",
        "approval_request": "artifacts/approval-request.json",
        "trace": "trace.jsonl",
        "skill_results": "skill-results.json",
    }
    state = RunState(
        run_id=run_id,
        trace_id=trace_id,
        status="REFERENCE_RUNTIME_ONLY",
        stage=case.state,
        case=case,
        approval_subject_hash=subject_hash,
        approval_request_id=approval_request.request_id,
        created_at=now,
        updated_at=now,
        artifact_paths=paths,
    )

    run_dir.mkdir(parents=True)
    _write_json(run_dir / paths["manifest"], manifest)
    _write_json(run_dir / paths["evidence"], evidence)
    _write_json(run_dir / paths["timeline"], timeline)
    _write_json(run_dir / paths["rules"], rules)
    _write_json(run_dir / paths["calculation"], calculation)
    _write_json(run_dir / paths["proposals"], proposals)
    _write_json(run_dir / paths["conflict_report"], conflict_report)
    _write_json(run_dir / paths["audit_report"], audit_report)
    _write_json(run_dir / paths["approval_request"], approval_request)
    _write_json(run_dir / paths["skill_results"], skill_results)
    _write_trace(run_dir / paths["trace"], trace)
    _write_json(run_dir / "run-state.json", state)
    return state


def _read_artifacts(
    run_dir: Path, state: RunState
) -> tuple[
    tuple[EvidenceObject, ...],
    tuple[RuleCitation, ...],
    CalculationSheet,
    ConflictReport,
    tuple[Proposal, ...],
    AuditReport,
]:
    evidence = tuple(
        EvidenceObject.model_validate(item)
        for item in cast(list[Any], _load_json(_state_artifact_path(run_dir, state, "evidence")))
    )
    rules = tuple(
        RuleCitation.model_validate(item)
        for item in cast(list[Any], _load_json(_state_artifact_path(run_dir, state, "rules")))
    )
    calculation = CalculationSheet.model_validate(
        _load_json(_state_artifact_path(run_dir, state, "calculation"))
    )
    conflict_report = ConflictReport.model_validate(
        _load_json(_state_artifact_path(run_dir, state, "conflict_report"))
    )
    proposals = tuple(
        Proposal.model_validate(item)
        for item in cast(list[Any], _load_json(_state_artifact_path(run_dir, state, "proposals")))
    )
    audit_report = AuditReport.model_validate(
        _load_json(_state_artifact_path(run_dir, state, "audit_report"))
    )
    return evidence, rules, calculation, conflict_report, proposals, audit_report


def _load_state(run_dir: Path) -> RunState:
    if not run_dir.is_dir():
        raise ReferenceRunError(f"run directory does not exist: {run_dir}")
    try:
        return RunState.model_validate(_load_json(run_dir / "run-state.json"))
    except (OSError, ValueError) as exc:
        raise ReferenceRunError("run state is missing or invalid") from exc


def _read_trace(path: Path) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                events.append(TraceEvent.model_validate_json(line))
    return events


def _read_manifest(run_dir: Path, state: RunState) -> CaseManifest:
    return CaseManifest.model_validate(_load_json(_state_artifact_path(run_dir, state, "manifest")))


def _read_timeline(run_dir: Path, state: RunState) -> tuple[TimelineEvent, ...]:
    return tuple(
        TimelineEvent.model_validate(item)
        for item in cast(list[Any], _load_json(_state_artifact_path(run_dir, state, "timeline")))
    )


def _read_skill_results(run_dir: Path, state: RunState) -> list[Any]:
    loaded = _load_json(_state_artifact_path(run_dir, state, "skill_results"))
    if not isinstance(loaded, list):
        raise ReferenceRunError("stored skill results are not a list")
    return loaded


def _current_approval_subject_hash(
    *,
    run_dir: Path,
    state: RunState,
    evidence: tuple[EvidenceObject, ...],
    rules: tuple[RuleCitation, ...],
    calculation: CalculationSheet,
    conflict_report: ConflictReport,
    proposals: tuple[Proposal, ...],
    audit_report: AuditReport,
    trace: list[TraceEvent] | None = None,
) -> str:
    manifest = _read_manifest(run_dir, state)
    timeline = _read_timeline(run_dir, state)
    skill_results = _read_skill_results(run_dir, state)
    full_trace = (
        trace if trace is not None else _read_trace(_state_artifact_path(run_dir, state, "trace"))
    )
    approval_trace = _approval_trace_prefix(full_trace)
    approval_case = state.case.model_copy(
        update={
            "state": CaseState.AWAITING_APPROVAL,
            "state_version": sum(
                event.event_type == "case.state_transition" for event in approval_trace
            ),
        }
    )
    return _subject_hash(
        manifest=manifest,
        case=approval_case,
        evidence=evidence,
        timeline=timeline,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
        skill_results=skill_results,
        trace=approval_trace,
    )


def _load_approval_request(run_dir: Path, state: RunState) -> ApprovalRequest:
    try:
        return ApprovalRequest.model_validate(
            _load_json(_state_artifact_path(run_dir, state, "approval_request"))
        )
    except (OSError, ValueError) as exc:
        raise ReferenceRunError("approval request is missing or invalid") from exc


def _require_approval_request_binding(
    *,
    state: RunState,
    approval_request: ApprovalRequest,
    audit_report: AuditReport,
) -> ApprovalRequest:
    if not audit_report.verify_hash():
        raise ReferenceRunError("approval request binding mismatch: audit report is unsealed")
    expected = _expected_approval_request(
        audit_report=audit_report,
        approval_subject_hash=state.approval_subject_hash,
    )
    errors = _approval_request_binding_errors(
        state=state,
        approval_request=approval_request,
        expected=expected,
    )
    if errors:
        raise ReferenceRunError("approval request binding mismatch: " + "; ".join(errors))
    return expected


def _trace_integrity_errors(
    *,
    state: RunState,
    trace: list[TraceEvent],
    skill_results: list[Any],
    manifest_document_count: int,
    approval_request: ApprovalRequest,
    current_subject_hash: str,
    approval_record: ApprovalRecord | None,
    package_manifest: PackageManifest | None,
    package_input_hash: str | None,
    package_output_hash: str | None,
) -> list[str]:
    errors: list[str] = []
    expected_events: list[tuple[str, str, ActorKind]] = [
        ("case.state_transition", "PF-A1", ActorKind.AGENT),
        *[
            ("skill.evidence_ingest", "PF-A2", ActorKind.AGENT)
            for _ in range(manifest_document_count)
        ],
        ("skill.timeline_build", "PF-A2", ActorKind.AGENT),
        ("case.state_transition", "PF-A1", ActorKind.AGENT),
        ("skill.rule_retrieve", "PF-A3", ActorKind.AGENT),
        ("case.state_transition", "PF-A1", ActorKind.AGENT),
        ("skill.deterministic_calculate", "PF-A4", ActorKind.AGENT),
        ("case.state_transition", "PF-A1", ActorKind.AGENT),
        ("strategy.proposal_generate", "PF-A5", ActorKind.AGENT),
        ("case.state_transition", "PF-A1", ActorKind.AGENT),
        ("skill.conflict_detect", "PF-A6", ActorKind.AGENT),
        ("skill.decision_audit", "PF-A6", ActorKind.AGENT),
        ("case.state_transition", "PF-A1", ActorKind.AGENT),
    ]
    if approval_record is not None:
        expected_events.extend(
            [
                ("skill.human_approval", approval_record.approver_id, ActorKind.HUMAN),
                ("case.state_transition", approval_record.approver_id, ActorKind.HUMAN),
            ]
        )
    if package_manifest is not None:
        expected_events.extend(
            [
                ("skill.document_package", "PF-A1", ActorKind.AGENT),
                ("case.state_transition", "PF-A1", ActorKind.AGENT),
            ]
        )
    actual_events = [(event.event_type, event.actor_identity, event.actor_kind) for event in trace]
    if actual_events != expected_events:
        errors.append("trace event sequence or actor contract mismatch")
    expected_sequences = list(range(1, len(trace) + 1))
    if [event.sequence for event in trace] != expected_sequences:
        errors.append("trace sequence is not contiguous")
    if any(current.occurred_at < previous.occurred_at for previous, current in pairwise(trace)):
        errors.append("trace timestamps are not monotonic")
    if not trace or trace[0].occurred_at != state.created_at:
        errors.append("run creation time does not match the first trace event")
    if not trace or trace[-1].occurred_at != state.updated_at:
        errors.append("run update time does not match the final trace event")
    for event in trace:
        if event.status != "SUCCESS" or event.error_code is not None:
            errors.append("trace contains a non-success event")
        if event.trace_id != state.trace_id:
            errors.append("trace event trace id mismatch")
        if event.tenant_id != state.case.tenant_id:
            errors.append("trace event tenant mismatch")
        if event.case_id != state.case.case_id:
            errors.append("trace event case mismatch")
    state_events = [event for event in trace if event.event_type == "case.state_transition"]
    if len(state_events) != state.case.state_version:
        errors.append("trace state-transition count mismatch")
    initial_case = state.case.model_copy(update={"state": CaseState.RECEIVED, "state_version": 0})
    if not state_events or state_events[0].input_hash != sha256_digest(initial_case):
        errors.append("trace does not start at the deterministic initial case state")
    for previous, current in pairwise(state_events):
        if previous.output_hash != current.input_hash:
            errors.append("trace state-transition hash chain is broken")
    if not state_events or state_events[-1].output_hash != sha256_digest(state.case):
        errors.append("trace does not terminate at the stored case state")
    for event in state_events:
        if event.status != "SUCCESS" or event.error_code is not None:
            errors.append("trace contains a non-successful state transition")

    expected_state_targets = [
        CaseState.INGESTING,
        CaseState.FACTS_READY,
        CaseState.RULES_READY,
        CaseState.CALC_READY,
        CaseState.PROPOSAL_READY,
        CaseState.AWAITING_APPROVAL,
    ]
    if approval_record is not None:
        expected_state_targets.append(
            {
                ApprovalDecision.APPROVE: CaseState.APPROVED,
                ApprovalDecision.REJECT: CaseState.REJECTED,
                ApprovalDecision.REVISE: CaseState.REVISION_REQUIRED,
            }[approval_record.decision]
        )
    if package_manifest is not None:
        expected_state_targets.append(CaseState.PACKAGED)
    if len(state_events) != len(expected_state_targets):
        errors.append("trace state-transition plan mismatch")
    else:
        expected_case = initial_case
        for event, target in zip(state_events, expected_state_targets, strict=True):
            next_case = expected_case.model_copy(
                update={
                    "state": target,
                    "state_version": expected_case.state_version + 1,
                }
            )
            if event.input_hash != sha256_digest(expected_case):
                errors.append("trace transition input does not match the expected state plan")
            if event.output_hash != sha256_digest(next_case):
                errors.append("trace transition output does not match the expected state plan")
            expected_case = next_case
        if expected_case != state.case:
            errors.append("stored case does not match the replayed state plan")

    approval_events = [event for event in trace if event.event_type == "skill.human_approval"]
    if approval_record is None:
        if approval_events:
            errors.append("trace contains approval without an approval record")
    else:
        if len(approval_events) != 1:
            errors.append("trace must contain exactly one human approval event")
        else:
            approval_event = approval_events[0]
            if approval_event.actor_kind != ActorKind.HUMAN:
                errors.append("approval trace actor is not human")
            if approval_event.actor_identity != approval_record.approver_id:
                errors.append("approval trace actor does not match approval record")
            if approval_event.status != "SUCCESS" or approval_event.error_code is not None:
                errors.append("approval trace event is not a clean success")
            if approval_event.occurred_at != approval_record.decided_at:
                errors.append("approval trace time does not match approval record")
            expected_approval_input_hash = sha256_digest(
                ApprovalExecuteRequest(
                    approval_request=approval_request,
                    current_artifact_hash=current_subject_hash,
                )
            )
            if approval_event.input_hash != expected_approval_input_hash:
                errors.append("approval trace input does not match the active request")
            if approval_event.output_hash != sha256_digest(
                ApprovalExecuteOutput(record=approval_record)
            ):
                errors.append("approval trace output does not match approval record")

    package_events = [event for event in trace if event.event_type == "skill.document_package"]
    if package_manifest is None:
        if package_events:
            errors.append("trace contains package event without a package manifest")
    elif len(package_events) != 1:
        errors.append("trace must contain exactly one document package event")
    else:
        package_event = package_events[0]
        if package_event.actor_identity != "PF-A1" or package_event.actor_kind != ActorKind.AGENT:
            errors.append("package trace actor mismatch")
        if package_event.status != "SUCCESS" or package_event.error_code is not None:
            errors.append("package trace event is not a clean success")
        if package_event.occurred_at != package_manifest.meta.created_at:
            errors.append("package trace time does not match package manifest")
        if package_input_hash is None or package_event.input_hash != package_input_hash:
            errors.append("package trace input does not match packaged artifacts")
        if package_output_hash is None or package_event.output_hash != package_output_hash:
            errors.append("package trace output does not match package files")

    subject_result_events = [
        event
        for event in _approval_trace_prefix(trace)
        if event.event_type != "case.state_transition"
    ]
    if len(subject_result_events) != len(skill_results):
        errors.append("trace and stored skill-result counts differ")
    else:
        for index, (event, result) in enumerate(
            zip(subject_result_events, skill_results, strict=True),
            start=1,
        ):
            if not isinstance(result, dict):
                errors.append(f"stored skill result {index} is not an object")
                continue
            if event.input_hash != result.get("input_hash"):
                errors.append(f"trace input hash mismatch for stored skill result {index}")
            if event.output_hash != result.get("output_hash"):
                errors.append(f"trace output hash mismatch for stored skill result {index}")
            if event.status != result.get("status"):
                errors.append(f"trace status mismatch for stored skill result {index}")
            output_hash = result.get("output_hash")
            if output_hash is not None:
                try:
                    expected_output_hash = sha256_digest(result.get("value"))
                except (TypeError, ValueError):
                    errors.append(f"stored skill result {index} is not canonicalizable")
                else:
                    if output_hash != expected_output_hash:
                        errors.append(f"stored skill result {index} output hash mismatch")
    return errors


def approve_reference_run(
    *,
    run_dir: Path,
    approver_id: str,
    approver_role: str,
    decision: ApprovalDecision,
    reason: str,
    now: datetime | None = None,
) -> ApprovalRecord:
    now = now or datetime.now(UTC)
    state = _load_state(run_dir)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ReferenceRunError("approval time must be timezone-aware")
    if now < state.updated_at:
        raise ReferenceRunError("approval time cannot precede the current run state")
    if state.stage != CaseState.AWAITING_APPROVAL:
        raise ReferenceRunError(f"run is not awaiting approval: {state.stage.value}")
    evidence, rules, calculation, conflict_report, proposals, audit_report = _read_artifacts(
        run_dir, state
    )
    trace = _read_trace(_state_artifact_path(run_dir, state, "trace"))
    current_hash = _current_approval_subject_hash(
        run_dir=run_dir,
        state=state,
        evidence=evidence,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
        trace=trace,
    )
    approval_request = _load_approval_request(run_dir, state)
    expected_approval_request = _require_approval_request_binding(
        state=state,
        approval_request=approval_request,
        audit_report=audit_report,
    )
    human_decision = HumanDecision(
        actor_id=approver_id,
        actor_kind=ActorKind.HUMAN,
        actor_role=approver_role,
        decision=decision,
        reason=reason,
        decided_at=now,
    )
    result = human_approval(
        _context(
            case=state.case,
            trace_id=state.trace_id,
            caller="PF-A1",
            idempotency_key=f"{state.run_id}:approval:{approval_request.request_id}",
        ),
        ApprovalExecuteRequest(
            approval_request=approval_request,
            current_artifact_hash=current_hash,
        ),
        decision=human_decision,
        now=now,
    )
    output = _require_success("human_approval", result)
    record = output.record
    record_binding_errors = _approval_record_binding_errors(
        approval_record=record,
        expected=expected_approval_request,
    )
    if record_binding_errors:
        raise ReferenceRunError(
            "approval record binding mismatch: " + "; ".join(record_binding_errors)
        )
    target = {
        ApprovalDecision.APPROVE: CaseState.APPROVED,
        ApprovalDecision.REJECT: CaseState.REJECTED,
        ApprovalDecision.REVISE: CaseState.REVISION_REQUIRED,
    }[decision]
    trace.append(
        TraceEvent(
            sequence=len(trace) + 1,
            trace_id=state.trace_id,
            tenant_id=state.case.tenant_id,
            case_id=state.case.case_id,
            actor_identity=approver_id,
            actor_kind=ActorKind.HUMAN,
            event_type="skill.human_approval",
            input_hash=result.input_hash,
            output_hash=result.output_hash,
            status=result.status.value,
            occurred_at=now,
        )
    )
    case, event = transition_case(
        state.case,
        target=target,
        expected_state_version=state.case.state_version,
        actor_identity=approver_id,
        actor_kind=ActorKind.HUMAN,
        trace_id=state.trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(
            approval_decision=decision,
            approval_valid=current_hash == approval_request.artifact_hash,
            actor_role=approver_role,
            required_approval_role=approval_request.required_role,
        ),
    )
    trace.append(event)
    artifact_paths = {
        **state.artifact_paths,
        "approval_record": "artifacts/approval-record.json",
    }
    state = state.model_copy(
        update={
            "stage": case.state,
            "case": case,
            "updated_at": now,
            "artifact_paths": artifact_paths,
        }
    )
    _write_json(
        _state_artifact_path(
            run_dir,
            state,
            "approval_record",
            require_file=False,
        ),
        record,
    )
    _write_trace(_state_artifact_path(run_dir, state, "trace"), trace)
    _write_json(run_dir / "run-state.json", state)
    return record


def package_reference_run(
    *,
    run_dir: Path,
    now: datetime | None = None,
) -> PackageManifest:
    now = now or datetime.now(UTC)
    state = _load_state(run_dir)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ReferenceRunError("package time must be timezone-aware")
    if now < state.updated_at:
        raise ReferenceRunError("package time cannot precede the current run state")
    if state.stage != CaseState.APPROVED:
        raise ReferenceRunError(f"run is not approved: {state.stage.value}")
    evidence, rules, calculation, conflict_report, proposals, audit_report = _read_artifacts(
        run_dir, state
    )
    trace = _read_trace(_state_artifact_path(run_dir, state, "trace"))
    current_hash = _current_approval_subject_hash(
        run_dir=run_dir,
        state=state,
        evidence=evidence,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
        trace=trace,
    )
    approval_request = _load_approval_request(run_dir, state)
    expected_approval_request = _require_approval_request_binding(
        state=state,
        approval_request=approval_request,
        audit_report=audit_report,
    )
    approval_record = ApprovalRecord.model_validate(
        _load_json(_state_artifact_path(run_dir, state, "approval_record"))
    )
    record_binding_errors = _approval_record_binding_errors(
        approval_record=approval_record,
        expected=expected_approval_request,
    )
    if record_binding_errors:
        raise ReferenceRunError(
            "approval record binding mismatch: " + "; ".join(record_binding_errors)
        )
    manifest = _read_manifest(run_dir, state)
    skill_results = _read_skill_results(run_dir, state)
    trace_errors = _trace_integrity_errors(
        state=state,
        trace=trace,
        skill_results=skill_results,
        manifest_document_count=len(manifest.documents),
        approval_request=expected_approval_request,
        current_subject_hash=current_hash,
        approval_record=approval_record,
        package_manifest=None,
        package_input_hash=None,
        package_output_hash=None,
    )
    if trace_errors:
        raise ReferenceRunError("pre-package trace integrity failed: " + "; ".join(trace_errors))
    result = document_package(
        _context(
            case=state.case,
            trace_id=state.trace_id,
            caller="PF-A1",
            idempotency_key=f"{state.run_id}:package",
        ),
        DocumentPackageRequest(
            proposal=proposals[0],
            calculation=calculation,
            audit_report=audit_report,
            approval_request=approval_request,
            approval_record=approval_record,
            current_artifact_hash=current_hash,
        ),
        now=now,
    )
    output = _require_success("document_package", result)

    package_dir = run_dir / "package"
    if package_dir.exists():
        raise ReferenceRunError("package directory already exists; refusing to overwrite")
    package_dir.mkdir(parents=True)
    _atomic_write(package_dir / "review-draft.md", output.draft_markdown.encode("utf-8"))
    _atomic_write(package_dir / "artifacts.json", output.artifacts_json.encode("utf-8"))
    _write_json(package_dir / "package-manifest.json", output.manifest)

    trace.append(
        _skill_event(
            result=cast(SkillResult[Any], result),
            sequence=len(trace) + 1,
            trace_id=state.trace_id,
            case=state.case,
            actor_identity="PF-A1",
            event_type="skill.document_package",
            now=now,
        )
    )
    case, event = transition_case(
        state.case,
        target=CaseState.PACKAGED,
        expected_state_version=state.case.state_version,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id=state.trace_id,
        sequence=len(trace) + 1,
        occurred_at=now,
        context=TransitionContext(
            approval_valid=current_hash == approval_record.approved_artifact_hash,
            audit_verdict=audit_report.verdict,
            package_valid=output.manifest.verify_hash(),
        ),
    )
    trace.append(event)
    artifact_paths = {
        **state.artifact_paths,
        "package_manifest": "package/package-manifest.json",
    }
    state = state.model_copy(
        update={
            "stage": case.state,
            "case": case,
            "updated_at": now,
            "artifact_paths": artifact_paths,
        }
    )
    _write_trace(_state_artifact_path(run_dir, state, "trace"), trace)
    _write_json(run_dir / "run-state.json", state)
    return output.manifest


def verify_reference_run(run_dir: Path) -> VerificationReport:
    state = _load_state(run_dir)
    errors: list[str] = []
    checked_artifacts = 0
    evidence, rules, calculation, conflict_report, proposals, audit_report = _read_artifacts(
        run_dir, state
    )
    manifest = _read_manifest(run_dir, state)
    timeline = _read_timeline(run_dir, state)
    skill_results = _read_skill_results(run_dir, state)
    trace = _read_trace(_state_artifact_path(run_dir, state, "trace"))
    artifacts = (
        *evidence,
        *timeline,
        *rules,
        calculation,
        conflict_report,
        *proposals,
        audit_report,
    )
    for item in artifacts:
        checked_artifacts += 1
        if not item.verify_hash():
            errors.append(f"artifact hash mismatch: {artifact_ref(item)}")
        if item.meta.tenant_id != state.case.tenant_id:
            errors.append(f"artifact tenant mismatch: {artifact_ref(item)}")
        if item.meta.case_id != state.case.case_id:
            errors.append(f"artifact case mismatch: {artifact_ref(item)}")
        if item.meta.trace_id != state.trace_id:
            errors.append(f"artifact trace mismatch: {artifact_ref(item)}")

    if sha256_digest(manifest) != state.case.input_manifest_hash:
        errors.append("input manifest hash mismatch")
    if manifest.tenant_id != state.case.tenant_id or manifest.case_id != state.case.case_id:
        errors.append("input manifest tenant or case mismatch")
    if (
        manifest.jurisdiction != state.case.jurisdiction
        or manifest.as_of_date != state.case.as_of_date
    ):
        errors.append("input manifest scope mismatch")

    current_subject_hash = _current_approval_subject_hash(
        run_dir=run_dir,
        state=state,
        evidence=evidence,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
        trace=trace,
    )
    if current_subject_hash != state.approval_subject_hash:
        errors.append("approval subject hash mismatch")

    expected_approval_request = _expected_approval_request(
        audit_report=audit_report,
        approval_subject_hash=state.approval_subject_hash,
    )
    try:
        approval_request = _load_approval_request(run_dir, state)
    except ReferenceRunError:
        errors.append("approval request is missing or invalid")
    else:
        errors.extend(
            _approval_request_binding_errors(
                state=state,
                approval_request=approval_request,
                expected=expected_approval_request,
            )
        )

    approval_record: ApprovalRecord | None = None
    approval_record_path = state.artifact_paths.get("approval_record")
    if approval_record_path is not None:
        approval_record = ApprovalRecord.model_validate(
            _load_json(_state_artifact_path(run_dir, state, "approval_record"))
        )
        checked_artifacts += 1
        if not approval_record.verify_hash():
            errors.append(f"artifact hash mismatch: {artifact_ref(approval_record)}")
        errors.extend(
            _approval_record_binding_errors(
                approval_record=approval_record,
                expected=expected_approval_request,
            )
        )
        if approval_record.approved_artifact_hash != current_subject_hash:
            errors.append("approval record is bound to a stale subject hash")
    expected_decision_by_stage = {
        CaseState.APPROVED: ApprovalDecision.APPROVE,
        CaseState.PACKAGED: ApprovalDecision.APPROVE,
        CaseState.REJECTED: ApprovalDecision.REJECT,
        CaseState.REVISION_REQUIRED: ApprovalDecision.REVISE,
    }
    if state.stage == CaseState.AWAITING_APPROVAL:
        if approval_record is not None:
            errors.append("approval record must not exist while awaiting approval")
    else:
        expected_decision = expected_decision_by_stage[state.stage]
        if approval_record is None:
            errors.append("approval record is missing for the current stage")
        elif approval_record.decision != expected_decision:
            errors.append("approval decision does not match the current stage")

    checked_package_files = 0
    package_manifest: PackageManifest | None = None
    package_input_hash: str | None = None
    package_output_hash: str | None = None
    manifest_path = state.artifact_paths.get("package_manifest")
    if manifest_path is not None and state.stage != CaseState.PACKAGED:
        errors.append("package manifest is only valid for PACKAGED state")
    if manifest_path is not None:
        package_manifest = PackageManifest.model_validate(
            _load_json(_state_artifact_path(run_dir, state, "package_manifest"))
        )
        checked_artifacts += 1
        if not package_manifest.verify_hash():
            errors.append(f"artifact hash mismatch: {artifact_ref(package_manifest)}")
        if package_manifest.meta.tenant_id != state.case.tenant_id:
            errors.append("package manifest tenant mismatch")
        if package_manifest.meta.case_id != state.case.case_id:
            errors.append("package manifest case mismatch")
        if package_manifest.meta.trace_id != state.trace_id:
            errors.append("package manifest trace mismatch")
        if package_manifest.meta.producer_identity != "PF-A1":
            errors.append("package manifest producer mismatch")
        if package_manifest.meta.classification != DataClassification.PUBLIC_SYNTHETIC:
            errors.append("package manifest classification mismatch")
        if approval_record is None:
            errors.append("package manifest exists without an approval record")
        else:
            if approval_record.decision != ApprovalDecision.APPROVE:
                errors.append("package is not backed by an APPROVE decision")
            if package_manifest.approval_record_ref != artifact_ref(approval_record):
                errors.append("package manifest approval reference mismatch")
        if package_manifest.audit_report_ref != artifact_ref(audit_report):
            errors.append("package manifest audit reference mismatch")
        expected_included_refs = (
            artifact_ref(proposals[0]),
            artifact_ref(calculation),
            artifact_ref(audit_report),
            artifact_ref(approval_record)
            if approval_record is not None
            else "ApprovalRecord:MISSING",
        )
        if package_manifest.included_artifact_refs != expected_included_refs:
            errors.append("package manifest included references mismatch")
        if package_manifest.meta.source_refs != expected_included_refs:
            errors.append("package manifest source references mismatch")
        expected_manifest_hash = sha256_digest(
            {
                "files": package_manifest.files,
                "included_refs": expected_included_refs,
                "approval_hash": (
                    approval_record.meta.content_hash if approval_record is not None else None
                ),
                "template_id": "controlled-review-draft",
                "template_version": "0.1.0",
            }
        )
        if package_manifest.manifest_hash != expected_manifest_hash:
            errors.append("package manifest internal hash mismatch")
        if package_manifest.meta.artifact_id != stable_id(
            "package", {"manifest_hash": expected_manifest_hash}
        ):
            errors.append("package manifest artifact id mismatch")
        package_root = _safe_run_path(
            run_dir,
            "package",
            require_file=False,
        )
        for packaged_file in package_manifest.files:
            checked_package_files += 1
            candidate = (package_root / packaged_file.path).resolve()
            try:
                candidate.relative_to(package_root)
            except ValueError:
                errors.append(f"package file escapes package directory: {packaged_file.path}")
                continue
            if not candidate.is_file():
                errors.append(f"package file is missing: {packaged_file.path}")
                continue
            actual = sha256_file(candidate)
            if actual != packaged_file.sha256:
                errors.append(f"package file hash mismatch: {packaged_file.path}")
        expected_package_output: DocumentPackageOutput | None = None
        if approval_record is not None:
            package_request = DocumentPackageRequest(
                proposal=proposals[0],
                calculation=calculation,
                audit_report=audit_report,
                approval_request=expected_approval_request,
                approval_record=approval_record,
                current_artifact_hash=current_subject_hash,
            )
            package_input_hash = sha256_digest(package_request)
            expected_package_result = document_package(
                _context(
                    case=state.case,
                    trace_id=state.trace_id,
                    caller="PF-A1",
                    idempotency_key=f"{state.run_id}:package",
                ),
                package_request,
                now=package_manifest.meta.created_at,
            )
            if (
                expected_package_result.status != SkillStatus.SUCCESS
                or expected_package_result.value is None
            ):
                errors.append("package cannot be deterministically regenerated")
            else:
                expected_package_output = expected_package_result.value
                package_output_hash = expected_package_result.output_hash
                if expected_package_output.manifest != package_manifest:
                    errors.append("package manifest does not match deterministic regeneration")
        draft_path = package_root / "review-draft.md"
        artifacts_json_path = package_root / "artifacts.json"
        if draft_path.is_file() and artifacts_json_path.is_file():
            expected_files = (
                PackageFile(path="review-draft.md", sha256=sha256_file(draft_path)),
                PackageFile(path="artifacts.json", sha256=sha256_file(artifacts_json_path)),
            )
            if package_manifest.files != expected_files:
                errors.append("package manifest file contract mismatch")
            if expected_package_output is not None:
                if draft_path.read_text(encoding="utf-8") != expected_package_output.draft_markdown:
                    errors.append("package draft does not match deterministic regeneration")
                if (
                    artifacts_json_path.read_text(encoding="utf-8")
                    != expected_package_output.artifacts_json
                ):
                    errors.append(
                        "package artifact bundle does not match deterministic regeneration"
                    )
    elif state.stage == CaseState.PACKAGED:
        errors.append("package manifest is missing for PACKAGED state")

    errors.extend(
        _trace_integrity_errors(
            state=state,
            trace=trace,
            skill_results=skill_results,
            manifest_document_count=len(manifest.documents),
            approval_request=expected_approval_request,
            current_subject_hash=current_subject_hash,
            approval_record=approval_record,
            package_manifest=package_manifest,
            package_input_hash=package_input_hash,
            package_output_hash=package_output_hash,
        )
    )

    return VerificationReport(
        valid=not errors,
        checked_artifacts=checked_artifacts,
        checked_package_files=checked_package_files,
        errors=tuple(errors),
    )
