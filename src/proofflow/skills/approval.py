"""Local-demo Human Gate bound to an immutable approval subject hash."""

from __future__ import annotations

from datetime import datetime

from proofflow.canonical import sha256_digest
from proofflow.contracts import ApprovalExecuteOutput, ApprovalExecuteRequest
from proofflow.factories import artifact_meta
from proofflow.models import (
    ApprovalRecord,
    HumanDecision,
    Issue,
    SkillContext,
    SkillResult,
    SkillStatus,
    artifact_ref,
)
from proofflow.skills.common import denied, success


def human_approval(
    context: SkillContext,
    request: ApprovalExecuteRequest,
    *,
    decision: HumanDecision,
    now: datetime,
) -> SkillResult[ApprovalExecuteOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A1",
        result_type=ApprovalExecuteOutput,
    ):
        return result
    approval_request = request.approval_request
    issues: list[Issue] = []
    if (
        approval_request.tenant_id != context.tenant_id
        or approval_request.case_id != context.case_id
        or approval_request.trace_id != context.trace_id
    ):
        issues.append(
            Issue(
                code="CROSS_TENANT_OR_CASE_APPROVAL",
                severity="BLOCKER",
                message="approval request does not belong to the active tenant and case",
            )
        )
    if decision.actor_role != approval_request.required_role:
        issues.append(
            Issue(
                code="UNAUTHORIZED_APPROVER",
                severity="BLOCKER",
                message="human actor does not hold the required approval role",
            )
        )
    if now.tzinfo is None or now.utcoffset() is None:
        issues.append(
            Issue(
                code="INVALID_APPROVAL_TIME",
                severity="BLOCKER",
                message="approval execution time must be timezone-aware",
            )
        )
    elif decision.decided_at != now:
        issues.append(
            Issue(
                code="APPROVAL_TIME_MISMATCH",
                severity="BLOCKER",
                message="the recorded human decision time must match execution time",
            )
        )
    elif now < approval_request.created_at:
        issues.append(
            Issue(
                code="APPROVAL_NOT_YET_ACTIVE",
                severity="BLOCKER",
                message="approval cannot occur before the request was created",
            )
        )
    if decision.decided_at > approval_request.expires_at or (
        now.tzinfo is not None and now.utcoffset() is not None and now > approval_request.expires_at
    ):
        issues.append(
            Issue(
                code="APPROVAL_EXPIRED",
                severity="BLOCKER",
                message="approval request is expired",
            )
        )
    if request.current_artifact_hash != approval_request.artifact_hash:
        issues.append(
            Issue(
                code="ARTIFACT_CHANGED",
                severity="BLOCKER",
                message="approval subject changed after the request was created",
            )
        )
    if issues:
        return SkillResult[ApprovalExecuteOutput](
            status=SkillStatus.BLOCKED,
            issues=tuple(issues),
            input_hash=sha256_digest(request),
        )

    record = ApprovalRecord(
        meta=artifact_meta(
            prefix="approval",
            identity=f"HUMAN:{decision.actor_id}",
            context=context,
            now=now,
            payload_for_id={
                "request_id": approval_request.request_id,
                "decision": decision.decision,
                "actor_id": decision.actor_id,
                "artifact_hash": approval_request.artifact_hash,
            },
            source_refs=(
                f"ApprovalRequest:{approval_request.request_id}",
                approval_request.artifact_ref,
                approval_request.audit_report_ref,
            ),
        ),
        request_id=approval_request.request_id,
        decision=decision.decision,
        approver_id=decision.actor_id,
        approver_role=decision.actor_role,
        reason=decision.reason,
        approved_artifact_hash=approval_request.artifact_hash,
        decided_at=decision.decided_at,
        expires_at=approval_request.expires_at,
    ).seal()
    output = ApprovalExecuteOutput(record=record)
    return success(request, output, (artifact_ref(record),))
