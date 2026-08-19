"""Controlled, date-aware rule catalog filtering (not vector RAG)."""

from __future__ import annotations

from datetime import datetime

from proofflow.canonical import sha256_digest
from proofflow.contracts import RuleCatalog, RuleRetrieveOutput, RuleRetrieveRequest
from proofflow.factories import artifact_meta
from proofflow.models import (
    Issue,
    RuleCitation,
    SkillContext,
    SkillResult,
    SkillStatus,
    artifact_ref,
)
from proofflow.skills.common import denied


def _jurisdiction_applies(rule_jurisdiction: str, case_jurisdiction: str) -> bool:
    return case_jurisdiction == rule_jurisdiction or case_jurisdiction.startswith(
        rule_jurisdiction + "-"
    )


def rule_retrieve(
    context: SkillContext,
    request: RuleRetrieveRequest,
    *,
    catalog: RuleCatalog,
    now: datetime,
) -> SkillResult[RuleRetrieveOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A3",
        result_type=RuleRetrieveOutput,
    ):
        return result

    citations: list[RuleCitation] = []
    missing: list[str] = []
    for issue_code in request.issue_codes:
        matches = [
            record
            for record in catalog.rules
            if record.issue_code == issue_code
            and _jurisdiction_applies(record.jurisdiction, request.jurisdiction)
            and record.effective_from <= request.as_of_date
            and (record.effective_to is None or request.as_of_date <= record.effective_to)
        ]
        if not matches:
            missing.append(issue_code)
            continue
        for record in matches:
            citation = RuleCitation(
                meta=artifact_meta(
                    prefix="rule",
                    identity="PF-A3",
                    context=context,
                    now=now,
                    payload_for_id={
                        "rule_id": record.rule_id,
                        "version": record.version,
                        "issue_code": issue_code,
                        "as_of_date": request.as_of_date,
                    },
                    source_refs=(record.authoritative_source,),
                ),
                rule_id=record.rule_id,
                version=record.version,
                issue_code=record.issue_code,
                title=record.title,
                jurisdiction=record.jurisdiction,
                effective_from=record.effective_from,
                effective_to=record.effective_to,
                authoritative_source=record.authoritative_source,
                locator=record.locator,
                excerpt=record.statement,
                source_hash=sha256_digest(record),
            ).seal()
            citations.append(citation)

    output = RuleRetrieveOutput(
        citations=tuple(citations),
        missing_issue_codes=tuple(missing),
        catalog_version=catalog.catalog_version,
    )
    return SkillResult[RuleRetrieveOutput](
        status=SkillStatus.NEEDS_HUMAN if missing else SkillStatus.SUCCESS,
        value=output,
        issues=tuple(
            Issue(
                code="INSUFFICIENT_AUTHORITY",
                severity="BLOCKER",
                message=f"no active authoritative record for issue code {issue_code}",
                needs_human=True,
            )
            for issue_code in missing
        ),
        input_hash=sha256_digest(request),
        output_hash=sha256_digest(output),
        emitted_refs=tuple(artifact_ref(citation) for citation in citations),
    )
