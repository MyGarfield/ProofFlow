import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from proofflow.canonical import sha256_bytes
from proofflow.contracts import EvidenceIngestRequest
from proofflow.models import EvidenceObject, SkillContext
from proofflow.skills import evidence_ingest
from proofflow.trusted_store import (
    TrustedArtifactStore,
    TrustedArtifactStoreCapacityError,
)

NOW = datetime(2026, 8, 20, 3, 0, tzinfo=UTC)


def context(*, case_id: str = "case-happy-001") -> SkillContext:
    return SkillContext(
        tenant_id="tenant-public-demo",
        case_id=case_id,
        caller_identity="PF-A2",
        trace_id="trace-store-test",
        idempotency_key="store-test",
        expected_state_version=0,
    )


def ingested_evidence() -> tuple[EvidenceObject, ...]:
    raw = json.dumps(
        {
            "employment_start_date": "2021-01-01",
            "monthly_wage_average": "12000.00",
        }
    ).encode()
    result = evidence_ingest(
        context(),
        EvidenceIngestRequest(
            document_id="doc-store-test",
            media_type="application/json",
            declared_sha256=sha256_bytes(raw),
            raw_content=raw,
        ),
        now=NOW,
    )
    assert result.value is not None
    return result.value.evidence_objects


def test_store_requires_exact_registered_canonical_evidence_and_scope() -> None:
    evidence = ingested_evidence()
    store = TrustedArtifactStore(capacity=4)
    store.register_all(evidence)

    modified_and_resealed = (
        evidence[0]
        .model_copy(
            update={
                "meta": evidence[0].meta.model_copy(update={"content_hash": None}),
                "normalized_value": "99999.00",
            }
        )
        .seal()
    )

    assert store.contains(context(), evidence[0])
    assert not store.contains(context(), modified_and_resealed)
    assert not store.contains(context(case_id="case-other"), evidence[0])


def test_store_capacity_is_atomic_and_identical_retries_are_idempotent() -> None:
    evidence = ingested_evidence()
    too_small = TrustedArtifactStore(capacity=1)
    with pytest.raises(TrustedArtifactStoreCapacityError):
        too_small.register_all(evidence)
    assert len(too_small) == 0

    store = TrustedArtifactStore(capacity=2)
    store.register_all(evidence)
    store.register_all(evidence)
    assert len(store) == 2


def test_store_registration_and_lookup_are_thread_safe() -> None:
    evidence = ingested_evidence()
    store = TrustedArtifactStore(capacity=2)

    with ThreadPoolExecutor(max_workers=8) as executor:
        registrations = [executor.submit(store.register_all, evidence) for _ in range(32)]
        for registration in registrations:
            registration.result()

    assert len(store) == 2
    assert all(store.contains(context(), item) for item in evidence)
