from datetime import UTC, date, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from proofflow.models import (
    ArtifactMeta,
    CalculationSheet,
    DataClassification,
    EvidenceObject,
    FactStatus,
    TimelineEvent,
)


def meta(artifact_id: str) -> ArtifactMeta:
    return ArtifactMeta(
        artifact_id=artifact_id,
        tenant_id="tenant-synthetic",
        case_id="case-001",
        producer_identity="PF-A2",
        trace_id="trace-001",
        created_at=datetime(2026, 8, 20, 1, 2, 3, tzinfo=UTC),
        classification=DataClassification.PUBLIC_SYNTHETIC,
    )


def test_artifact_can_be_sealed_and_verified() -> None:
    evidence = EvidenceObject(
        meta=meta("evidence-001"),
        evidence_type="structured_field",
        field_name="monthly_wage",
        normalized_value="12000",
        verbatim_excerpt="synthetic monthly wage: 12000",
        source_document_id="doc-001",
        fact_status=FactStatus.VERIFIED,
        confidence=Decimal("1"),
    )

    sealed = evidence.seal()

    assert sealed.meta.content_hash is not None
    assert sealed.verify_hash()
    assert not evidence.verify_hash()


def test_timeline_requires_source_or_explicit_unresolved_status() -> None:
    with pytest.raises(ValidationError, match="source_refs or an unresolved reason"):
        TimelineEvent(
            meta=meta("timeline-001"),
            occurred_from=date(2026, 1, 1),
            occurred_to=None,
            description="unsupported event",
            fact_status=FactStatus.PROPOSED,
        )


def test_missing_parameters_forbid_a_total() -> None:
    with pytest.raises(ValidationError, match="total must be absent"):
        CalculationSheet(
            meta=meta("calc-001"),
            line_items=(),
            total=Decimal("1"),
            missing_parameters=("monthly_wage",),
        )
