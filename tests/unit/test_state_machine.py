from datetime import UTC, date, datetime

import pytest

from proofflow.models import ActorKind, AuditVerdict, CaseRecord, CaseState
from proofflow.state_machine import TransitionContext, TransitionRejected, transition_case

NOW = datetime(2026, 8, 20, 2, 0, tzinfo=UTC)


def new_case() -> CaseRecord:
    return CaseRecord(
        case_id="case-001",
        tenant_id="tenant-synthetic",
        jurisdiction="CN-ZJ-HZ",
        as_of_date=date(2026, 8, 20),
        input_manifest_hash="sha256:" + "0" * 64,
    )


def test_valid_transition_increments_version_and_emits_trace() -> None:
    case, event = transition_case(
        new_case(),
        target=CaseState.INGESTING,
        expected_state_version=0,
        actor_identity="PF-A1",
        actor_kind=ActorKind.AGENT,
        trace_id="trace-001",
        sequence=1,
        occurred_at=NOW,
        context=TransitionContext(manifest_valid=True, input_hashes_match=True),
    )

    assert case.state == CaseState.INGESTING
    assert case.state_version == 1
    assert event.input_hash != event.output_hash
    assert event.status == "SUCCESS"


def test_stale_version_and_illegal_jump_are_rejected_without_mutation() -> None:
    case = new_case()

    with pytest.raises(TransitionRejected, match="stale state version"):
        transition_case(
            case,
            target=CaseState.INGESTING,
            expected_state_version=1,
            actor_identity="PF-A1",
            actor_kind=ActorKind.AGENT,
            trace_id="trace-001",
            occurred_at=NOW,
            context=TransitionContext(manifest_valid=True, input_hashes_match=True),
        )

    with pytest.raises(TransitionRejected, match="illegal transition"):
        transition_case(
            case,
            target=CaseState.APPROVED,
            expected_state_version=0,
            actor_identity="PF-A1",
            actor_kind=ActorKind.AGENT,
            trace_id="trace-001",
            occurred_at=NOW,
            context=TransitionContext(),
        )

    assert case.state == CaseState.RECEIVED
    assert case.state_version == 0


def test_audit_pass_is_required_before_approval_queue() -> None:
    case = new_case().model_copy(update={"state": CaseState.PROPOSAL_READY, "state_version": 5})

    with pytest.raises(TransitionRejected, match="audit must PASS"):
        transition_case(
            case,
            target=CaseState.AWAITING_APPROVAL,
            expected_state_version=5,
            actor_identity="PF-A1",
            actor_kind=ActorKind.AGENT,
            trace_id="trace-001",
            occurred_at=NOW,
            context=TransitionContext(audit_verdict=AuditVerdict.REVISE),
        )
