"""Read-only structural conflict detection and decision audit."""

from __future__ import annotations

from datetime import datetime

from proofflow.canonical import sha256_digest
from proofflow.contracts import (
    ConflictDetectOutput,
    ConflictDetectRequest,
    DecisionAuditOutput,
    DecisionAuditRequest,
)
from proofflow.factories import artifact_meta, stable_id
from proofflow.models import (
    AuditFinding,
    AuditReport,
    AuditVerdict,
    Conflict,
    ConflictReport,
    Issue,
    SkillContext,
    SkillResult,
    SkillStatus,
    artifact_ref,
)
from proofflow.skills.common import denied, success

REQUIRED_PRE_AUDIT_EVENTS = frozenset(
    {
        "skill.evidence_ingest",
        "skill.timeline_build",
        "skill.rule_retrieve",
        "skill.deterministic_calculate",
        "strategy.proposal_generate",
        "skill.conflict_detect",
    }
)


def conflict_detect(
    context: SkillContext,
    request: ConflictDetectRequest,
    *,
    now: datetime,
) -> SkillResult[ConflictDetectOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A6",
        result_type=ConflictDetectOutput,
    ):
        return result

    grouped: dict[str, dict[str, list[str]]] = {}
    for item in request.evidence:
        grouped.setdefault(item.field_name, {}).setdefault(item.normalized_value, []).append(
            artifact_ref(item)
        )
    conflicts: list[Conflict] = []
    for field_name, values in sorted(grouped.items()):
        if len(values) < 2:
            continue
        refs = tuple(ref for value_refs in values.values() for ref in value_refs)
        conflicts.append(
            Conflict(
                conflict_id=stable_id("conflict", {"field": field_name, "values": values}),
                severity="BLOCKER",
                object_refs=refs,
                description=f"conflicting verified values for {field_name}",
                required_action="A human reviewer must resolve the source conflict.",
            )
        )

    input_complete = bool(request.evidence and request.rules and request.calculation)
    report = ConflictReport(
        meta=artifact_meta(
            prefix="conflict-report",
            identity="PF-A6",
            context=context,
            now=now,
            payload_for_id={
                "policy_version": request.policy_version,
                "conflicts": conflicts,
                "input_complete": input_complete,
            },
            source_refs=tuple(
                [artifact_ref(item) for item in request.evidence]
                + [artifact_ref(item) for item in request.rules]
                + ([artifact_ref(request.calculation)] if request.calculation else [])
            ),
        ),
        conflicts=tuple(conflicts),
        blocker_ids=tuple(item.conflict_id for item in conflicts if item.severity == "BLOCKER"),
        input_complete=input_complete,
    ).seal()
    output = ConflictDetectOutput(report=report)
    return SkillResult[ConflictDetectOutput](
        status=SkillStatus.SUCCESS if input_complete else SkillStatus.BLOCKED,
        value=output,
        issues=(
            ()
            if input_complete
            else (
                Issue(
                    code="INCOMPLETE_INPUT",
                    severity="BLOCKER",
                    message="conflict detection input is incomplete",
                ),
            )
        ),
        input_hash=sha256_digest(request),
        output_hash=sha256_digest(output),
        emitted_refs=(artifact_ref(report),),
    )


def decision_audit(
    context: SkillContext,
    request: DecisionAuditRequest,
    *,
    now: datetime,
) -> SkillResult[DecisionAuditOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A6",
        result_type=DecisionAuditOutput,
    ):
        return result

    findings: list[AuditFinding] = []
    missing_events = sorted(REQUIRED_PRE_AUDIT_EVENTS.difference(request.observed_event_types))
    if missing_events:
        findings.append(
            AuditFinding(
                finding_id=stable_id("finding", {"missing_events": missing_events}),
                severity="BLOCKER",
                object_refs=(),
                message="required trace events are missing: " + ", ".join(missing_events),
                required_action="Restore the missing trace evidence and rerun the audit.",
            )
        )
    if not request.conflict_report.input_complete:
        findings.append(
            AuditFinding(
                finding_id=stable_id("finding", "conflict-input-incomplete"),
                severity="BLOCKER",
                object_refs=(artifact_ref(request.conflict_report),),
                message="conflict report was produced from incomplete inputs",
                required_action="Complete all upstream evidence before audit.",
            )
        )
    for conflict_id in request.conflict_report.blocker_ids:
        findings.append(
            AuditFinding(
                finding_id=stable_id("finding", {"blocker": conflict_id}),
                severity="BLOCKER",
                object_refs=(conflict_id,),
                message="an unresolved blocker conflict remains",
                required_action="Resolve the conflict through the Human Gate.",
            )
        )
    if request.calculation.total is None or not request.calculation.verify_hash():
        findings.append(
            AuditFinding(
                finding_id=stable_id("finding", "calculation-invalid"),
                severity="BLOCKER",
                object_refs=(artifact_ref(request.calculation),),
                message="calculation is missing, unsealed, or inconsistent",
                required_action="Rerun the versioned deterministic calculation.",
            )
        )

    unsupported: list[str] = []
    available_evidence = {artifact_ref(item) for item in request.evidence}
    available_rules = {artifact_ref(item) for item in request.rules}
    calculation_ref = artifact_ref(request.calculation)
    for proposal in request.proposals:
        if not proposal.verify_hash():
            unsupported.append(f"{artifact_ref(proposal)} is not sealed")
        if not proposal.evidence_refs or not set(proposal.evidence_refs).issubset(
            available_evidence
        ):
            unsupported.append(f"{artifact_ref(proposal)} has invalid evidence references")
        if not proposal.rule_refs or not set(proposal.rule_refs).issubset(available_rules):
            unsupported.append(f"{artifact_ref(proposal)} has invalid rule references")
        if proposal.calculation_ref != calculation_ref:
            unsupported.append(f"{artifact_ref(proposal)} has an invalid calculation reference")
    if unsupported:
        findings.append(
            AuditFinding(
                finding_id=stable_id("finding", {"unsupported": unsupported}),
                severity="BLOCKER",
                object_refs=tuple(artifact_ref(item) for item in request.proposals),
                message="one or more proposal claims are not structurally supported",
                required_action="Regenerate proposals with valid immutable references.",
            )
        )

    verdict = (
        AuditVerdict.BLOCK
        if any(item.severity == "BLOCKER" for item in findings)
        else AuditVerdict.PASS
    )
    audited = tuple(
        item.meta.content_hash
        for item in (
            *request.evidence,
            *request.rules,
            request.calculation,
            request.conflict_report,
            *request.proposals,
        )
        if item.meta.content_hash is not None
    )
    report = AuditReport(
        meta=artifact_meta(
            prefix="audit-report",
            identity="PF-A6",
            context=context,
            now=now,
            payload_for_id={
                "policy_version": request.policy_version,
                "audited_hashes": audited,
                "findings": findings,
            },
            source_refs=tuple(
                artifact_ref(item)
                for item in (
                    *request.evidence,
                    *request.rules,
                    request.calculation,
                    request.conflict_report,
                    *request.proposals,
                )
            ),
        ),
        verdict=verdict,
        findings=tuple(findings),
        unsupported_claims=tuple(unsupported),
        audited_artifact_hashes=audited,
        policy_version=request.policy_version,
    ).seal()
    output = DecisionAuditOutput(report=report)
    return success(request, output, (artifact_ref(report),))
