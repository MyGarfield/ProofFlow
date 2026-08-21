"""Evidence ingestion and source-linked timeline construction."""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from proofflow.canonical import sha256_bytes, sha256_digest
from proofflow.contracts import (
    EvidenceIngestOutput,
    EvidenceIngestRequest,
    TimelineBuildOutput,
    TimelineBuildRequest,
)
from proofflow.factories import artifact_meta
from proofflow.models import (
    EvidenceObject,
    FactStatus,
    Issue,
    SkillContext,
    SkillResult,
    SkillStatus,
    TimelineEvent,
    artifact_ref,
)
from proofflow.skills.common import denied, success

ALLOWED_MEDIA_TYPES = frozenset({"application/json", "text/plain"})
EXTRACTABLE_FIELDS = frozenset(
    {
        "employee_ref",
        "employer_ref",
        "employment_start_date",
        "work_location",
        "contract_type",
        "currency",
        "monthly_wage_average",
        "local_previous_year_monthly_average_wage",
        "wage_months_observed",
        "planned_termination_date",
        "candidate_basis",
        "advance_notice_days",
        "article_40_eligibility_verified",
    }
)


def _normalized(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def evidence_ingest(
    context: SkillContext,
    request: EvidenceIngestRequest,
    *,
    now: datetime,
) -> SkillResult[EvidenceIngestOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A2",
        result_type=EvidenceIngestOutput,
    ):
        return result
    if request.media_type not in ALLOWED_MEDIA_TYPES:
        return SkillResult[EvidenceIngestOutput](
            status=SkillStatus.BLOCKED,
            issues=(
                Issue(
                    code="UNSUPPORTED_FILE",
                    severity="BLOCKER",
                    message=f"unsupported media type: {request.media_type}",
                    needs_human=True,
                ),
            ),
            input_hash=sha256_digest(request),
        )

    actual_hash = sha256_bytes(request.raw_content)
    if actual_hash != request.declared_sha256:
        return SkillResult[EvidenceIngestOutput](
            status=SkillStatus.BLOCKED,
            issues=(
                Issue(
                    code="SOURCE_HASH_MISMATCH",
                    severity="BLOCKER",
                    message="declared source hash does not match the received bytes",
                ),
            ),
            input_hash=sha256_digest(request),
        )

    try:
        if request.media_type == "application/json":
            parsed = json.loads(request.raw_content)
            if not isinstance(parsed, dict):
                raise ValueError("top-level JSON must be an object")
        else:
            parsed = {"text_content": request.raw_content.decode("utf-8")}
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return SkillResult[EvidenceIngestOutput](
            status=SkillStatus.BLOCKED,
            issues=(
                Issue(
                    code="PARSE_FAILED",
                    severity="BLOCKER",
                    message=str(exc),
                    needs_human=True,
                ),
            ),
            input_hash=sha256_digest(request),
        )

    evidence: list[EvidenceObject] = []
    for field_name in sorted(EXTRACTABLE_FIELDS.intersection(parsed)):
        normalized = _normalized(parsed[field_name])
        item = EvidenceObject(
            meta=artifact_meta(
                prefix="evidence",
                identity="PF-A2",
                context=context,
                now=now,
                payload_for_id={
                    "document_id": request.document_id,
                    "field_name": field_name,
                    "value": normalized,
                },
                source_refs=(f"SourceDocument:{request.document_id}",),
            ),
            evidence_type="structured_field",
            field_name=field_name,
            normalized_value=normalized,
            verbatim_excerpt=f"{field_name}={normalized}",
            source_document_id=request.document_id,
            fact_status=FactStatus.VERIFIED,
            confidence=Decimal("1"),
        ).seal()
        evidence.append(item)

    ignored = tuple(sorted(set(parsed).difference(EXTRACTABLE_FIELDS)))
    output = EvidenceIngestOutput(
        evidence_objects=tuple(evidence),
        source_hash=actual_hash,
        ignored_fields=ignored,
    )
    return success(request, output, tuple(artifact_ref(item) for item in evidence))


def timeline_build(
    context: SkillContext,
    request: TimelineBuildRequest,
    *,
    now: datetime,
) -> SkillResult[TimelineBuildOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A2",
        result_type=TimelineBuildOutput,
    ):
        return result

    timeline_fields = {
        "employment_start_date": "Synthetic employment start",
        "planned_termination_date": "Synthetic planned termination",
    }
    events: list[TimelineEvent] = []
    unresolved: list[str] = []
    for item in request.evidence:
        if item.field_name not in timeline_fields:
            continue
        try:
            occurred = date.fromisoformat(item.normalized_value)
        except ValueError:
            unresolved.append(f"invalid date in {artifact_ref(item)}")
            continue
        event = TimelineEvent(
            meta=artifact_meta(
                prefix="timeline",
                identity="PF-A2",
                context=context,
                now=now,
                payload_for_id={
                    "field": item.field_name,
                    "date": item.normalized_value,
                    "source": artifact_ref(item),
                },
                source_refs=(artifact_ref(item),),
            ),
            occurred_from=occurred,
            occurred_to=occurred,
            description=timeline_fields[item.field_name],
            fact_status=item.fact_status,
        ).seal()
        events.append(event)

    output = TimelineBuildOutput(events=tuple(events), unresolved_items=tuple(unresolved))
    status = SkillStatus.NEEDS_HUMAN if unresolved else SkillStatus.SUCCESS
    return SkillResult[TimelineBuildOutput](
        status=status,
        value=output,
        issues=tuple(
            Issue(
                code="AMBIGUOUS_DATE",
                severity="WARNING",
                message=item,
                needs_human=True,
            )
            for item in unresolved
        ),
        input_hash=sha256_digest(request),
        output_hash=sha256_digest(output),
        emitted_refs=tuple(artifact_ref(event) for event in events),
    )
