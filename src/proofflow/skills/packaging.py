"""Controlled local draft rendering with a hash-verifiable manifest."""

from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal

from proofflow.canonical import canonicalize, sha256_bytes, sha256_digest
from proofflow.contracts import DocumentPackageOutput, DocumentPackageRequest
from proofflow.factories import artifact_meta
from proofflow.models import (
    ApprovalDecision,
    AuditVerdict,
    Issue,
    PackageFile,
    PackageManifest,
    SkillContext,
    SkillResult,
    SkillStatus,
    artifact_ref,
)
from proofflow.skills.common import denied, success


def _money(value: Decimal) -> str:
    return format(value, ".2f")


def _render_draft(request: DocumentPackageRequest) -> str:
    total = request.calculation.total
    assert total is not None
    risks = "\n".join(f"- {item}" for item in request.proposal.risks)
    uncertainties = "\n".join(f"- {item}" for item in request.proposal.uncertainties)
    return f"""# ProofFlow controlled review draft

Status: **SYNTHETIC / HUMAN-REVIEWED DRAFT / NOT LEGAL ADVICE**

This file does not authorize sending, signing, submitting, termination, payment,
or an HR-system write.

## Candidate option

{request.proposal.summary}

## Deterministic reference calculation

- Amount: CNY {_money(total)}
- Formula: {request.calculation.line_items[0].formula_version}
- Reproducibility hash: `{request.calculation.reproducibility_hash}`

The amount is a deterministic reference only. It does not establish eligibility
or a final legal outcome.

## Risks

{risks}

## Uncertainties

{uncertainties}

## Immutable references

- Proposal: `{artifact_ref(request.proposal)}`
- Calculation: `{artifact_ref(request.calculation)}`
- Audit: `{artifact_ref(request.audit_report)}`
- Approval: `{artifact_ref(request.approval_record)}`
""".rstrip()


def document_package(
    context: SkillContext,
    request: DocumentPackageRequest,
    *,
    now: datetime,
) -> SkillResult[DocumentPackageOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A1",
        result_type=DocumentPackageOutput,
    ):
        return result

    issues: list[Issue] = []
    if request.audit_report.verdict != AuditVerdict.PASS or not request.audit_report.verify_hash():
        issues.append(
            Issue(
                code="AUDIT_NOT_PASSABLE",
                severity="BLOCKER",
                message="a sealed PASS audit is required",
            )
        )
    if (
        request.approval_record.decision != ApprovalDecision.APPROVE
        or not request.approval_record.verify_hash()
    ):
        issues.append(
            Issue(
                code="APPROVAL_INVALID",
                severity="BLOCKER",
                message="a sealed APPROVE record is required",
            )
        )
    if request.current_artifact_hash != request.approval_record.approved_artifact_hash:
        issues.append(
            Issue(
                code="ARTIFACT_HASH_MISMATCH",
                severity="BLOCKER",
                message="the approved subject hash no longer matches",
            )
        )
    if now > request.approval_record.expires_at:
        issues.append(
            Issue(
                code="APPROVAL_EXPIRED",
                severity="BLOCKER",
                message="the approval expired before package generation",
            )
        )
    if request.calculation.total is None or not request.calculation.verify_hash():
        issues.append(
            Issue(
                code="CALCULATION_INVALID",
                severity="BLOCKER",
                message="a sealed deterministic calculation is required",
            )
        )
    if issues:
        return SkillResult[DocumentPackageOutput](
            status=SkillStatus.BLOCKED,
            issues=tuple(issues),
            input_hash=sha256_digest(request),
        )

    draft = _render_draft(request)
    artifact_payload = {
        "proposal": request.proposal,
        "calculation": request.calculation,
        "audit_report": request.audit_report,
        "approval_record": request.approval_record,
        "template": {
            "id": request.template_id,
            "version": request.template_version,
        },
    }
    artifacts_json = json.dumps(
        canonicalize(artifact_payload), ensure_ascii=False, sort_keys=True, indent=2
    )
    files = (
        PackageFile(path="review-draft.md", sha256=sha256_bytes(draft.encode("utf-8"))),
        PackageFile(path="artifacts.json", sha256=sha256_bytes(artifacts_json.encode("utf-8"))),
    )
    included_refs = (
        artifact_ref(request.proposal),
        artifact_ref(request.calculation),
        artifact_ref(request.audit_report),
        artifact_ref(request.approval_record),
    )
    manifest_hash = sha256_digest(
        {
            "files": files,
            "included_refs": included_refs,
            "approval_hash": request.approval_record.meta.content_hash,
            "template_id": request.template_id,
            "template_version": request.template_version,
        }
    )
    manifest = PackageManifest(
        meta=artifact_meta(
            prefix="package",
            identity="PF-A1",
            context=context,
            now=now,
            payload_for_id={"manifest_hash": manifest_hash},
            source_refs=included_refs,
        ),
        approval_record_ref=artifact_ref(request.approval_record),
        audit_report_ref=artifact_ref(request.audit_report),
        files=files,
        included_artifact_refs=included_refs,
        manifest_hash=manifest_hash,
    ).seal()
    output = DocumentPackageOutput(
        manifest=manifest,
        draft_markdown=draft,
        artifacts_json=artifacts_json,
    )
    return success(request, output, (artifact_ref(manifest),))
