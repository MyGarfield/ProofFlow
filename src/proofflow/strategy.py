"""Bounded deterministic proposal templates owned by PF-A5.

This is intentionally not a ninth Skill and not an autonomous legal judgment.
"""

from __future__ import annotations

from datetime import datetime

from proofflow.canonical import sha256_digest
from proofflow.contracts import ProposalGenerateOutput, ProposalGenerateRequest
from proofflow.factories import artifact_meta
from proofflow.models import Issue, Proposal, SkillContext, SkillResult, SkillStatus, artifact_ref
from proofflow.skills.common import denied, success


def create_candidate_proposals(
    context: SkillContext,
    request: ProposalGenerateRequest,
    *,
    now: datetime,
) -> SkillResult[ProposalGenerateOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A5",
        result_type=ProposalGenerateOutput,
    ):
        return result
    if request.calculation.total is None or not request.calculation.verify_hash():
        return SkillResult[ProposalGenerateOutput](
            status=SkillStatus.BLOCKED,
            issues=(
                Issue(
                    code="CALCULATION_NOT_VERIFIED",
                    severity="BLOCKER",
                    message="proposal generation requires a sealed deterministic calculation",
                ),
            ),
            input_hash=sha256_digest(request),
        )

    evidence_refs = tuple(artifact_ref(item) for item in request.evidence)
    rule_refs = tuple(artifact_ref(item) for item in request.rules)
    calculation_ref = artifact_ref(request.calculation)
    proposal = Proposal(
        meta=artifact_meta(
            prefix="proposal",
            identity="PF-A5",
            context=context,
            now=now,
            payload_for_id={
                "option": "controlled-human-review",
                "evidence_refs": evidence_refs,
                "rule_refs": rule_refs,
                "calculation_ref": calculation_ref,
            },
            source_refs=evidence_refs + rule_refs + (calculation_ref,),
        ),
        option_code="CONTROLLED_HUMAN_REVIEW",
        summary=(
            "Prepare a controlled review draft that exposes the deterministic compensation "
            "reference, while requiring a qualified human to verify termination eligibility "
            "and all unresolved legal or factual preconditions."
        ),
        actions=(
            "Verify the candidate termination basis against the complete factual record.",
            "Review the cited official provisions at their authoritative source.",
            "Review the calculation inputs, formula version, and reproducibility hash.",
            "Do not send, sign, submit, or write to an HR system from this workflow.",
        ),
        evidence_refs=evidence_refs,
        rule_refs=rule_refs,
        calculation_ref=calculation_ref,
        risks=(
            "A deterministic amount does not establish legal eligibility.",
            "The local-average wage in this fixture is synthetic, not an official Hangzhou value.",
        ),
        uncertainties=(
            "Article 40 eligibility is deliberately unverified in the synthetic notice.",
            "No domain expert has reviewed this reference run.",
        ),
    ).seal()
    output = ProposalGenerateOutput(proposals=(proposal,))
    return success(request, output, (artifact_ref(proposal),))
