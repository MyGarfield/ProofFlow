"""Explicit case-state transitions with optimistic concurrency and guard checks."""

from __future__ import annotations

from datetime import datetime

from proofflow.canonical import sha256_digest
from proofflow.models import (
    ActorKind,
    ApprovalDecision,
    AuditVerdict,
    CaseRecord,
    CaseState,
    StrictModel,
    TraceEvent,
)


class TransitionRejected(ValueError):
    """Raised when a requested case transition violates a deterministic guard."""


class TransitionContext(StrictModel):
    manifest_valid: bool = False
    input_hashes_match: bool = False
    evidence_complete: bool = False
    has_blocking_issue: bool = False
    rules_valid: bool = False
    calculation_complete: bool = False
    proposal_complete: bool = False
    audit_verdict: AuditVerdict | None = None
    approval_decision: ApprovalDecision | None = None
    approval_valid: bool = False
    package_valid: bool = False
    close_confirmed: bool = False
    actor_role: str | None = None
    required_approval_role: str | None = None


ALLOWED_TRANSITIONS: dict[CaseState, frozenset[CaseState]] = {
    CaseState.RECEIVED: frozenset({CaseState.INGESTING}),
    CaseState.INGESTING: frozenset({CaseState.NEEDS_EVIDENCE, CaseState.FACTS_READY}),
    CaseState.NEEDS_EVIDENCE: frozenset({CaseState.INGESTING, CaseState.REJECTED}),
    CaseState.FACTS_READY: frozenset({CaseState.RULES_READY, CaseState.NEEDS_EVIDENCE}),
    CaseState.RULES_READY: frozenset({CaseState.CALC_READY, CaseState.NEEDS_EVIDENCE}),
    CaseState.CALC_READY: frozenset({CaseState.PROPOSAL_READY, CaseState.NEEDS_EVIDENCE}),
    CaseState.PROPOSAL_READY: frozenset({CaseState.AUDIT_BLOCKED, CaseState.AWAITING_APPROVAL}),
    CaseState.AUDIT_BLOCKED: frozenset({CaseState.REVISION_REQUIRED}),
    CaseState.AWAITING_APPROVAL: frozenset(
        {CaseState.APPROVED, CaseState.REJECTED, CaseState.REVISION_REQUIRED}
    ),
    CaseState.APPROVED: frozenset({CaseState.PACKAGED, CaseState.REVISION_REQUIRED}),
    CaseState.REJECTED: frozenset({CaseState.CLOSED}),
    CaseState.REVISION_REQUIRED: frozenset({CaseState.INGESTING, CaseState.CLOSED}),
    CaseState.PACKAGED: frozenset({CaseState.CLOSED, CaseState.REVISION_REQUIRED}),
    CaseState.CLOSED: frozenset(),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TransitionRejected(message)


def _validate_guard(
    current: CaseState,
    target: CaseState,
    actor_kind: ActorKind,
    context: TransitionContext,
) -> None:
    if target == CaseState.INGESTING and current == CaseState.RECEIVED:
        _require(context.manifest_valid, "input manifest is not valid")
        _require(context.input_hashes_match, "one or more declared input hashes do not match")
    elif target == CaseState.FACTS_READY:
        _require(context.evidence_complete, "evidence processing is incomplete")
        _require(not context.has_blocking_issue, "blocking evidence issue remains")
    elif target == CaseState.NEEDS_EVIDENCE:
        _require(context.has_blocking_issue, "NEEDS_EVIDENCE requires a recorded blocking issue")
    elif target == CaseState.RULES_READY:
        _require(context.rules_valid, "authoritative rules are incomplete or invalid")
        _require(not context.has_blocking_issue, "blocking rule issue remains")
    elif target == CaseState.CALC_READY:
        _require(context.calculation_complete, "deterministic calculation is incomplete")
        _require(not context.has_blocking_issue, "blocking calculation issue remains")
    elif target == CaseState.PROPOSAL_READY:
        _require(context.proposal_complete, "no fully referenced proposal is available")
    elif target == CaseState.AUDIT_BLOCKED:
        _require(
            context.audit_verdict in {AuditVerdict.BLOCK, AuditVerdict.REVISE},
            "AUDIT_BLOCKED requires a BLOCK or REVISE audit verdict",
        )
    elif target == CaseState.AWAITING_APPROVAL:
        _require(context.audit_verdict == AuditVerdict.PASS, "audit must PASS before approval")
        _require(not context.has_blocking_issue, "blocking issue remains before approval")
    elif current == CaseState.AWAITING_APPROVAL:
        _require(actor_kind == ActorKind.HUMAN, "approval transitions require a human actor")
        _require(
            bool(context.actor_role) and context.actor_role == context.required_approval_role,
            "human actor does not hold the required approval role",
        )
        if target == CaseState.APPROVED:
            _require(context.approval_decision == ApprovalDecision.APPROVE, "approval is absent")
            _require(context.approval_valid, "approval is expired or bound to stale artifacts")
        elif target == CaseState.REJECTED:
            _require(context.approval_decision == ApprovalDecision.REJECT, "rejection is absent")
        elif target == CaseState.REVISION_REQUIRED:
            _require(
                context.approval_decision == ApprovalDecision.REVISE or not context.approval_valid,
                "revision requires REVISE or an invalidated approval",
            )
    elif target == CaseState.PACKAGED:
        _require(context.approval_valid, "current approval is invalid")
        _require(context.audit_verdict == AuditVerdict.PASS, "current audit is not PASS")
        _require(context.package_valid, "package manifest is incomplete or inconsistent")
    elif target == CaseState.CLOSED:
        _require(context.close_confirmed, "closing a case requires explicit confirmation")


def transition_case(
    case: CaseRecord,
    *,
    target: CaseState,
    expected_state_version: int,
    actor_identity: str,
    actor_kind: ActorKind,
    trace_id: str,
    sequence: int = 1,
    occurred_at: datetime,
    context: TransitionContext,
) -> tuple[CaseRecord, TraceEvent]:
    if sequence < 1:
        raise TransitionRejected("trace sequence must be positive")
    if expected_state_version != case.state_version:
        raise TransitionRejected(
            f"stale state version: expected {expected_state_version}, current {case.state_version}"
        )
    if target not in ALLOWED_TRANSITIONS[case.state]:
        raise TransitionRejected(f"illegal transition: {case.state.value} -> {target.value}")
    _validate_guard(case.state, target, actor_kind, context)

    new_case = case.model_copy(update={"state": target, "state_version": case.state_version + 1})
    event = TraceEvent(
        sequence=sequence,
        trace_id=trace_id,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        actor_identity=actor_identity,
        actor_kind=actor_kind,
        event_type="case.state_transition",
        input_hash=sha256_digest(case),
        output_hash=sha256_digest(new_case),
        status="SUCCESS",
        occurred_at=occurred_at,
    )
    return new_case, event
