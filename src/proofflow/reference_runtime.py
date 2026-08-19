"""Synthetic-data-only local runtime for a three-step verifiable reference run."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from pydantic import Field

from proofflow.canonical import canonical_json, canonicalize, sha256_digest, sha256_file
from proofflow.contracts import (
    ApprovalExecuteRequest,
    CalculateRequest,
    CaseManifest,
    ConflictDetectRequest,
    DecisionAuditRequest,
    DocumentPackageRequest,
    EvidenceIngestRequest,
    ProposalGenerateRequest,
    RuleCatalog,
    RuleRetrieveRequest,
    TimelineBuildRequest,
)
from proofflow.factories import stable_id
from proofflow.models import (
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
    EvidenceObject,
    HumanDecision,
    PackageManifest,
    Proposal,
    RuleCitation,
    SkillContext,
    SkillResult,
    SkillStatus,
    StrictModel,
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


class VerificationReport(StrictModel):
    valid: bool
    checked_artifacts: int = Field(ge=0)
    checked_package_files: int = Field(ge=0)
    errors: tuple[str, ...]


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
    evidence: tuple[EvidenceObject, ...],
    rules: tuple[RuleCitation, ...],
    calculation: CalculationSheet,
    conflict_report: ConflictReport,
    proposals: tuple[Proposal, ...],
    audit_report: AuditReport,
) -> str:
    return sha256_digest(
        {
            "evidence": evidence,
            "rules": rules,
            "calculation": calculation,
            "conflict_report": conflict_report,
            "proposals": proposals,
            "audit_report": audit_report,
        }
    )


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
        evidence_items.extend(_require_success("evidence_ingest", result).evidence_objects)
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
    rules = _require_success("rule_retrieve", rule_result).citations

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
        CalculateRequest(evidence=evidence, rule_citations=rules),
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

    subject_hash = _subject_hash(
        evidence=evidence,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
    )
    approval_request = ApprovalRequest(
        request_id=stable_id("approval-request", {"run_id": run_id, "subject": subject_hash}),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        artifact_ref=f"ApprovalSubject:{run_id}",
        artifact_hash=subject_hash,
        audit_report_ref=artifact_ref(audit_report),
        required_role="legal-reviewer",
        expires_at=now + timedelta(hours=24),
    )
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
        for item in cast(list[Any], _load_json(run_dir / state.artifact_paths["evidence"]))
    )
    rules = tuple(
        RuleCitation.model_validate(item)
        for item in cast(list[Any], _load_json(run_dir / state.artifact_paths["rules"]))
    )
    calculation = CalculationSheet.model_validate(
        _load_json(run_dir / state.artifact_paths["calculation"])
    )
    conflict_report = ConflictReport.model_validate(
        _load_json(run_dir / state.artifact_paths["conflict_report"])
    )
    proposals = tuple(
        Proposal.model_validate(item)
        for item in cast(list[Any], _load_json(run_dir / state.artifact_paths["proposals"]))
    )
    audit_report = AuditReport.model_validate(
        _load_json(run_dir / state.artifact_paths["audit_report"])
    )
    return evidence, rules, calculation, conflict_report, proposals, audit_report


def _load_state(run_dir: Path) -> RunState:
    if not run_dir.is_dir():
        raise ReferenceRunError(f"run directory does not exist: {run_dir}")
    return RunState.model_validate(_load_json(run_dir / "run-state.json"))


def _read_trace(path: Path) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                events.append(TraceEvent.model_validate_json(line))
    return events


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
    if state.stage != CaseState.AWAITING_APPROVAL:
        raise ReferenceRunError(f"run is not awaiting approval: {state.stage.value}")
    evidence, rules, calculation, conflict_report, proposals, audit_report = _read_artifacts(
        run_dir, state
    )
    current_hash = _subject_hash(
        evidence=evidence,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
    )
    approval_request = ApprovalRequest.model_validate(
        _load_json(run_dir / state.artifact_paths["approval_request"])
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
    target = {
        ApprovalDecision.APPROVE: CaseState.APPROVED,
        ApprovalDecision.REJECT: CaseState.REJECTED,
        ApprovalDecision.REVISE: CaseState.REVISION_REQUIRED,
    }[decision]
    trace = _read_trace(run_dir / state.artifact_paths["trace"])
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
    _write_json(run_dir / state.artifact_paths["approval_record"], record)
    _write_trace(run_dir / state.artifact_paths["trace"], trace)
    _write_json(run_dir / "run-state.json", state)
    return record


def package_reference_run(
    *,
    run_dir: Path,
    now: datetime | None = None,
) -> PackageManifest:
    now = now or datetime.now(UTC)
    state = _load_state(run_dir)
    if state.stage != CaseState.APPROVED:
        raise ReferenceRunError(f"run is not approved: {state.stage.value}")
    evidence, rules, calculation, conflict_report, proposals, audit_report = _read_artifacts(
        run_dir, state
    )
    current_hash = _subject_hash(
        evidence=evidence,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
    )
    approval_record_path = state.artifact_paths.get("approval_record")
    if approval_record_path is None:
        raise ReferenceRunError("approval record path is missing")
    approval_record = ApprovalRecord.model_validate(_load_json(run_dir / approval_record_path))
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

    trace = _read_trace(run_dir / state.artifact_paths["trace"])
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
    _write_trace(run_dir / state.artifact_paths["trace"], trace)
    _write_json(run_dir / "run-state.json", state)
    return output.manifest


def verify_reference_run(run_dir: Path) -> VerificationReport:
    state = _load_state(run_dir)
    errors: list[str] = []
    checked_artifacts = 0
    evidence, rules, calculation, conflict_report, proposals, audit_report = _read_artifacts(
        run_dir, state
    )
    artifacts = (*evidence, *rules, calculation, conflict_report, *proposals, audit_report)
    for item in artifacts:
        checked_artifacts += 1
        if not item.verify_hash():
            errors.append(f"artifact hash mismatch: {artifact_ref(item)}")

    current_subject_hash = _subject_hash(
        evidence=evidence,
        rules=rules,
        calculation=calculation,
        conflict_report=conflict_report,
        proposals=proposals,
        audit_report=audit_report,
    )
    if current_subject_hash != state.approval_subject_hash:
        errors.append("approval subject hash mismatch")

    approval_record_path = state.artifact_paths.get("approval_record")
    if approval_record_path is not None:
        approval_record = ApprovalRecord.model_validate(_load_json(run_dir / approval_record_path))
        checked_artifacts += 1
        if not approval_record.verify_hash():
            errors.append(f"artifact hash mismatch: {artifact_ref(approval_record)}")
        if approval_record.approved_artifact_hash != current_subject_hash:
            errors.append("approval record is bound to a stale subject hash")

    checked_package_files = 0
    manifest_path = state.artifact_paths.get("package_manifest")
    if manifest_path is not None:
        manifest = PackageManifest.model_validate(_load_json(run_dir / manifest_path))
        checked_artifacts += 1
        if not manifest.verify_hash():
            errors.append(f"artifact hash mismatch: {artifact_ref(manifest)}")
        for packaged_file in manifest.files:
            checked_package_files += 1
            package_root = (run_dir / "package").resolve()
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

    return VerificationReport(
        valid=not errors,
        checked_artifacts=checked_artifacts,
        checked_package_files=checked_package_files,
        errors=tuple(errors),
    )
