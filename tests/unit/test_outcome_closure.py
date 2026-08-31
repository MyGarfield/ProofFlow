from __future__ import annotations

import base64
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, ValidationError
from test_execution_receipt import (
    NOW,
    ONE_HASH,
    ROOT,
    THREE_HASH,
    TWO_HASH,
    ZERO_HASH,
    envelope_bytes,
    public_key_b64,
    sha256_bytes,
    wire_payload,
)
from test_execution_receipt import (
    receipt_fixture as receipt_fixture_factory,
)

from proofflow.action_certificate import (
    OutcomeEvidenceSourceKind,
    OutcomeObserverScope,
    TrustPurpose,
    TrustRoot,
    VerificationReason,
    VerificationStatus,
)
from proofflow.execution_receipt import InMemoryReceiptIndex, verify_execution_receipt
from proofflow.outcome_closure import (
    OUTCOME_CLOSURE_AUDIENCE,
    OUTCOME_CLOSURE_PREDICATE_TYPE,
    ClaimedOutcome,
    EffectAttemptObservation,
    EffectAttemptStatus,
    EffectReconciliation,
    EffectTerminalResult,
    ExecutionReceiptReference,
    ExpectedOutcomeBinding,
    InMemoryOutcomeClosureIndex,
    InMemoryOutcomeEvidenceResolver,
    OutcomeClosurePredicate,
    OutcomeClosureStatement,
    OutcomeClosureVerificationReason,
    OutcomeClosureVerificationResult,
    OutcomeEvidenceSource,
    OutcomeProducerDeclaration,
    OutcomeVerdict,
    UnresolvedEffectObservation,
    UnresolvedEffectReason,
    execution_receipt_verification_sha256,
    expected_outcome_binding_for,
    verify_outcome_closure,
)


def _outcome_fixture(receipt: dict[str, Any]) -> dict[str, Any]:
    outcome_key = Ed25519PrivateKey.generate()
    outcome_root = TrustRoot(
        root_id="outcome-root",
        keyid_hints=("outcome-root",),
        algorithm="Ed25519",
        purpose=TrustPurpose.OUTCOME_OBSERVER,
        public_key_b64=public_key_b64(outcome_key),
        tenant_id="tenant-synthetic",
        principal_id="outcome-observer-001",
        audiences=(OUTCOME_CLOSURE_AUDIENCE,),
        predicate_types=(OUTCOME_CLOSURE_PREDICATE_TYPE,),
        outcome_observer_scopes=tuple(sorted(OutcomeObserverScope, key=lambda item: item.value)),
        outcome_evidence_source_kinds=(OutcomeEvidenceSourceKind.LOCAL_BYTES,),
        outcome_evidence_source_principals=("outcome-source-001",),
        not_before=NOW - timedelta(days=1),
        not_after=NOW + timedelta(days=1),
    )
    policy = receipt["policy"].model_copy(
        update={
            "allowed_audiences": (*receipt["policy"].allowed_audiences, OUTCOME_CLOSURE_AUDIENCE),
            "allowed_predicate_types": (
                *receipt["policy"].allowed_predicate_types,
                OUTCOME_CLOSURE_PREDICATE_TYPE,
            ),
            "allowed_outcome_observer_principals": ("outcome-observer-001",),
            "allowed_outcome_evidence_source_kinds": (OutcomeEvidenceSourceKind.LOCAL_BYTES,),
            "allowed_outcome_evidence_source_principals": ("outcome-source-001",),
            "roots": (*receipt["policy"].roots, outcome_root),
        }
    )
    receipt_result = verify_execution_receipt(
        receipt["envelope"],
        trust_policy=receipt["policy"],
        expected_binding=receipt["expected"],
        action_certificate_envelope_bytes=receipt["action_envelope"],
        action_certificate_verification=receipt["action_result"],
        receipt_index=InMemoryReceiptIndex(),
        now=NOW,
    )
    assert receipt_result.status == VerificationStatus.ACCEPT
    receipt_ref = ExecutionReceiptReference(
        receipt_id=receipt["statement"].predicate.receipt_id,
        payload_sha256=sha256_bytes(receipt["payload"]),
        envelope_sha256=sha256_bytes(receipt["envelope"]),
        verification_result_sha256=execution_receipt_verification_sha256(receipt_result),
    )
    certificate_ref = receipt["statement"].predicate.certificate_ref
    evidence = {
        b"source-event": sha256_bytes(b"source-event"),
        b"before-state": sha256_bytes(b"before-state"),
        b"after-state": sha256_bytes(b"after-state"),
        b"provider-event": sha256_bytes(b"provider-event"),
        b"observer-evidence": sha256_bytes(b"observer-evidence"),
    }
    evidence_source = OutcomeEvidenceSource(
        source_kind=OutcomeEvidenceSourceKind.LOCAL_BYTES,
        source_version="proofflow.outcome-evidence/v0.1",
        principal_id="outcome-source-001",
        observed_at=NOW - timedelta(seconds=1),
        valid_until=NOW + timedelta(minutes=5),
        source_event_sha256=evidence[b"source-event"],
    )
    reconciliation = EffectReconciliation(
        effect_type="local-synthetic-transform",
        target="process-local-synthetic-store",
        intent_sha256=certificate_ref.intent_sha256,
        idempotency_key="idempotency-001",
        expected_effect_count=1,
        attempts=(
            EffectAttemptObservation(
                effect_id="effect-001",
                attempt_id="effect-attempt-001",
                effect_type="local-synthetic-transform",
                target="process-local-synthetic-store",
                intent_sha256=certificate_ref.intent_sha256,
                idempotency_key="idempotency-001",
                status=EffectAttemptStatus.SUCCEEDED,
                terminal_result=EffectTerminalResult.EFFECT_COMMITTED,
                provider_operation_id="provider-operation-001",
                before_state_sha256=evidence[b"before-state"],
                after_state_sha256=evidence[b"after-state"],
                provider_event_sha256=evidence[b"provider-event"],
                observer_evidence_sha256=evidence[b"observer-evidence"],
            ),
        ),
        unresolved=(),
    )
    predicate = OutcomeClosurePredicate(
        version="0.1",
        closure_id="closure-001",
        execution_id="execution-001",
        task_id="task-001",
        attempt_id="attempt-001",
        closure_sequence=1,
        previous_payload_sha256=None,
        tenant_id="tenant-synthetic",
        case_id="case-001",
        issued_at=NOW,
        certificate_ref=certificate_ref,
        receipt_ref=receipt_ref,
        evidence_source=evidence_source,
        producer=OutcomeProducerDeclaration(
            producer_id="outcome-observer-fixture",
            software_name="ProofFlow outcome observer",
            software_version="0.1",
            observer_principals=("outcome-observer-001",),
        ),
        reconciliation=reconciliation,
        claimed_outcome=ClaimedOutcome.PASS,
    )
    statement = OutcomeClosureStatement(
        _type="https://in-toto.io/Statement/v1",
        subject=(),
        predicateType=OUTCOME_CLOSURE_PREDICATE_TYPE,
        predicate=predicate,
    )
    payload = wire_payload(statement)
    envelope = envelope_bytes(payload, (("outcome-root", outcome_key),))
    return {
        "policy": policy,
        "outcome_key": outcome_key,
        "outcome_root": outcome_root,
        "issuer_key": receipt["issuer_key"],
        "action_envelope": receipt["action_envelope"],
        "action_result": receipt["action_result"],
        "receipt_statement": receipt["statement"],
        "observer_key": receipt["observer_key"],
        "receipt_envelope": receipt["envelope"],
        "receipt_result": receipt_result,
        "statement": statement,
        "payload": payload,
        "envelope": envelope,
        "expected": expected_outcome_binding_for(
            statement,
            human_principal_key_fingerprints=receipt["expected"].human_principal_key_fingerprints,
            executor_workload_key_fingerprints=receipt[
                "expected"
            ].executor_workload_key_fingerprints,
        ),
        "evidence": {digest: raw for raw, digest in evidence.items()},
        "human_fingerprints": receipt["expected"].human_principal_key_fingerprints,
        "workload_fingerprints": receipt["expected"].executor_workload_key_fingerprints,
    }


@pytest.fixture
def outcome_fixture() -> dict[str, Any]:
    return _outcome_fixture(receipt_fixture_factory.__wrapped__())


def _verify(fixture: dict[str, Any], **updates: Any):
    arguments: dict[str, Any] = {
        "trust_policy": fixture["policy"],
        "expected_binding": fixture["expected"],
        "action_certificate_envelope_bytes": fixture["action_envelope"],
        "action_certificate_verification": fixture["action_result"],
        "execution_receipt_envelope_bytes": fixture["receipt_envelope"],
        "execution_receipt_verification": fixture["receipt_result"],
        "outcome_index": InMemoryOutcomeClosureIndex(),
        "now": NOW,
        "evidence_resolver": InMemoryOutcomeEvidenceResolver(fixture["evidence"]),
    }
    arguments.update(updates)
    return verify_outcome_closure(fixture["envelope"], **arguments)


def _replace_predicate(fixture: dict[str, Any], **updates: Any) -> dict[str, Any]:
    statement = fixture["statement"].model_copy(
        update={
            "predicate": fixture["statement"].predicate.model_copy(update=updates),
        }
    )
    attacked = dict(fixture)
    payload = wire_payload(statement)
    attacked.update(
        {
            "statement": statement,
            "payload": payload,
            "envelope": envelope_bytes(payload, (("outcome-root", fixture["outcome_key"]),)),
            "expected": expected_outcome_binding_for(
                statement,
                human_principal_key_fingerprints=fixture["human_fingerprints"],
                executor_workload_key_fingerprints=fixture["workload_fingerprints"],
            ),
        }
    )
    return attacked


def test_valid_pass_is_derived_and_exact_replay_is_idempotent(
    outcome_fixture: dict[str, Any],
) -> None:
    index = InMemoryOutcomeClosureIndex()
    first = _verify(outcome_fixture, outcome_index=index)
    replay = _verify(outcome_fixture, outcome_index=index)
    assert first.status == OutcomeVerdict.PASS
    assert first.reason_codes == (OutcomeClosureVerificationReason.PASS_VERIFIED,)
    assert first.verified_outcome_observer_roots == ("outcome-root",)
    assert first.recorded is True
    assert first.observed_success_count == 1
    assert replay.status == OutcomeVerdict.PASS
    assert replay.reason_codes == (OutcomeClosureVerificationReason.PASS_ALREADY_PRESENT,)
    assert replay.recorded is True


def test_outcome_only_policy_cannot_forge_external_acceptance(
    outcome_fixture: dict[str, Any],
) -> None:
    outcome_only_policy = outcome_fixture["policy"].model_copy(
        update={"roots": (outcome_fixture["outcome_root"],)}
    )
    isolated = dict(outcome_fixture)
    isolated["policy"] = outcome_only_policy
    result = _verify(isolated)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (
        OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED,
    )


def test_claimed_outcome_is_ignored_and_verdict_is_derived(
    outcome_fixture: dict[str, Any],
) -> None:
    attacked = _replace_predicate(outcome_fixture, claimed_outcome=ClaimedOutcome.UNKNOWN)
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.PASS
    assert result.reason_codes == (OutcomeClosureVerificationReason.PASS_VERIFIED,)


def test_invalid_prior_results_are_unknown_before_raw_evidence_is_verified(
    outcome_fixture: dict[str, Any],
) -> None:
    rejected = outcome_fixture["action_result"].model_copy(
        update={
            "status": VerificationStatus.REJECT,
            "reason_codes": (VerificationReason.SIGNATURE_INVALID,),
            "reserved": False,
        }
    )
    result = _verify(
        outcome_fixture,
        action_certificate_verification=rejected,
        evidence_resolver=None,
    )
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.EVIDENCE_BYTES_UNAVAILABLE,)


def test_missing_raw_source_evidence_is_unknown(
    outcome_fixture: dict[str, Any],
) -> None:
    result = _verify(
        outcome_fixture,
        evidence_resolver=InMemoryOutcomeEvidenceResolver({}),
    )
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.EVIDENCE_BYTES_UNAVAILABLE,)


def test_substituted_raw_evidence_is_unknown(
    outcome_fixture: dict[str, Any],
) -> None:
    evidence = dict(outcome_fixture["evidence"])
    digest = outcome_fixture["statement"].predicate.reconciliation.attempts[0].after_state_sha256
    evidence[digest] = b"substituted-state"
    result = _verify(
        outcome_fixture,
        evidence_resolver=InMemoryOutcomeEvidenceResolver(evidence),
    )
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.EVIDENCE_BYTES_UNAVAILABLE,)


def test_expired_authoritative_source_is_unknown(
    outcome_fixture: dict[str, Any],
) -> None:
    source = outcome_fixture["statement"].predicate.evidence_source.model_copy(
        update={"valid_until": NOW - timedelta(seconds=1)}
    )
    attacked = _replace_predicate(outcome_fixture, evidence_source=source)
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.EVIDENCE_SOURCE_INVALID,)


def test_outcome_signature_aliasing_a_prior_key_is_unknown(
    outcome_fixture: dict[str, Any],
) -> None:
    root = outcome_fixture["outcome_root"].model_copy(
        update={"public_key_b64": public_key_b64(outcome_fixture["issuer_key"])}
    )
    policy = outcome_fixture["policy"].model_copy(
        update={"roots": (*outcome_fixture["policy"].roots[:-1], root)}
    )
    attacked = dict(outcome_fixture)
    attacked["policy"] = policy
    payload = attacked["payload"]
    attacked["envelope"] = envelope_bytes(
        payload, (("outcome-root", outcome_fixture["issuer_key"]),)
    )
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.SELF_OBSERVATION,)


def test_outcome_observer_cannot_alias_issuer_or_approver_principal(
    outcome_fixture: dict[str, Any],
) -> None:
    root = outcome_fixture["outcome_root"].model_copy(update={"principal_id": "issuer-001"})
    policy = outcome_fixture["policy"].model_copy(
        update={
            "allowed_outcome_observer_principals": ("issuer-001",),
            "roots": (*outcome_fixture["policy"].roots[:-1], root),
        }
    )
    attacked = _replace_predicate(
        outcome_fixture,
        producer=outcome_fixture["statement"].predicate.producer.model_copy(
            update={"observer_principals": ("issuer-001",)}
        ),
    )
    attacked["policy"] = policy
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.SELF_OBSERVATION,)


def test_outcome_observer_threshold_is_fail_closed(
    outcome_fixture: dict[str, Any],
) -> None:
    policy = outcome_fixture["policy"].model_copy(update={"outcome_observer_threshold": 2})
    attacked = dict(outcome_fixture)
    attacked["policy"] = policy
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (
        OutcomeClosureVerificationReason.OUTCOME_OBSERVER_THRESHOLD_NOT_MET,
    )


def test_external_action_result_root_set_must_be_nonempty_and_exact(
    outcome_fixture: dict[str, Any],
) -> None:
    result_document = outcome_fixture["action_result"].model_copy(
        update={"verified_action_issuer_roots": ()}
    )
    attacked = dict(outcome_fixture)
    attacked["action_result"] = result_document
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (
        OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED,
    )


def test_external_receipt_result_root_set_must_be_nonempty_and_exact(
    outcome_fixture: dict[str, Any],
) -> None:
    result_document = outcome_fixture["receipt_result"].model_copy(
        update={"verified_execution_observer_roots": ()}
    )
    attacked = dict(outcome_fixture)
    attacked["receipt_result"] = result_document
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (
        OutcomeClosureVerificationReason.EXECUTION_RECEIPT_HANDOFF_UNTRUSTED,
    )


def test_resigned_receipt_cross_reference_cannot_pass_with_matching_other_fields(
    outcome_fixture: dict[str, Any],
) -> None:
    receipt_predicate = outcome_fixture["statement"].predicate
    alternate_certificate = receipt_predicate.certificate_ref.model_copy(
        update={"certificate_id": "certificate-B"}
    )
    original_receipt_statement = outcome_fixture["receipt_statement"].model_copy(
        update={
            "predicate": outcome_fixture["receipt_statement"].predicate.model_copy(
                update={"certificate_ref": alternate_certificate}
            )
        }
    )
    receipt_payload = wire_payload(original_receipt_statement)
    receipt_envelope = envelope_bytes(
        receipt_payload, (("observer-root", outcome_fixture["observer_key"]),)
    )
    receipt_result = outcome_fixture["receipt_result"].model_copy(
        update={
            "payload_sha256": sha256_bytes(receipt_payload),
            "envelope_sha256": sha256_bytes(receipt_envelope),
        }
    )
    receipt_ref = ExecutionReceiptReference(
        receipt_id=original_receipt_statement.predicate.receipt_id,
        payload_sha256=sha256_bytes(receipt_payload),
        envelope_sha256=sha256_bytes(receipt_envelope),
        verification_result_sha256=execution_receipt_verification_sha256(receipt_result),
    )
    predicate = outcome_fixture["statement"].predicate.model_copy(
        update={"receipt_ref": receipt_ref}
    )
    statement = outcome_fixture["statement"].model_copy(update={"predicate": predicate})
    payload = wire_payload(statement)
    attacked = dict(outcome_fixture)
    attacked.update(
        {
            "statement": statement,
            "payload": payload,
            "envelope": envelope_bytes(
                payload, (("outcome-root", outcome_fixture["outcome_key"]),)
            ),
            "receipt_envelope": receipt_envelope,
            "receipt_result": receipt_result,
            "expected": expected_outcome_binding_for(
                statement,
                human_principal_key_fingerprints=outcome_fixture["human_fingerprints"],
                executor_workload_key_fingerprints=outcome_fixture["workload_fingerprints"],
            ),
        }
    )
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNSAFE_SUCCESS
    assert result.reason_codes == (OutcomeClosureVerificationReason.EFFECT_BINDING_MISMATCH,)


def test_external_action_root_purpose_cannot_be_relabelled(
    outcome_fixture: dict[str, Any],
) -> None:
    issuer = outcome_fixture["policy"].roots[0]
    relabelled = issuer.model_copy(update={"purpose": TrustPurpose.OUTCOME_OBSERVER})
    # model_copy is intentionally bypassed here to exercise verifier-side root checks.
    policy = outcome_fixture["policy"].model_copy(
        update={"roots": (relabelled, *outcome_fixture["policy"].roots[1:])}
    )
    attacked = dict(outcome_fixture)
    attacked["policy"] = policy
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (
        OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED,
    )


def test_failure_result_requires_authoritative_terminal_rejection(
    outcome_fixture: dict[str, Any],
) -> None:
    original = outcome_fixture["statement"].predicate.reconciliation.attempts[0]
    failed = original.model_copy(
        update={
            "status": EffectAttemptStatus.FAILED,
            "terminal_result": EffectTerminalResult.EFFECT_COMMITTED,
        }
    )
    attacked = _replace_predicate(
        outcome_fixture,
        reconciliation=outcome_fixture["statement"].predicate.reconciliation.model_copy(
            update={"attempts": (failed,)}
        ),
    )
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.PAYLOAD_INVALID,)


def test_closure_time_window_is_checked_against_source_and_now(
    outcome_fixture: dict[str, Any],
) -> None:
    future = outcome_fixture["statement"].predicate.model_copy(
        update={"issued_at": NOW + timedelta(seconds=1)}
    )
    statement = outcome_fixture["statement"].model_copy(update={"predicate": future})
    attacked = dict(outcome_fixture)
    payload = wire_payload(statement)
    attacked.update(
        {
            "statement": statement,
            "payload": payload,
            "envelope": envelope_bytes(
                payload, (("outcome-root", outcome_fixture["outcome_key"]),)
            ),
            "expected": expected_outcome_binding_for(
                statement,
                human_principal_key_fingerprints=outcome_fixture["human_fingerprints"],
                executor_workload_key_fingerprints=outcome_fixture["workload_fingerprints"],
            ),
        }
    )
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNSAFE_SUCCESS
    assert result.reason_codes == (OutcomeClosureVerificationReason.OUTCOME_WINDOW_UNSAFE,)


def test_expected_count_two_with_one_failure_is_not_fail(
    outcome_fixture: dict[str, Any],
) -> None:
    original = outcome_fixture["statement"].predicate.reconciliation.attempts[0]
    failed = original.model_copy(
        update={
            "status": EffectAttemptStatus.FAILED,
            "terminal_result": EffectTerminalResult.EFFECT_REJECTED,
        }
    )
    reconciliation = outcome_fixture["statement"].predicate.reconciliation.model_copy(
        update={"expected_effect_count": 2, "attempts": (failed,)}
    )
    attacked = _replace_predicate(
        outcome_fixture,
        reconciliation=reconciliation,
        claimed_outcome=ClaimedOutcome.FAIL,
    )
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.EFFECT_COVERAGE_INCOMPLETE,)


def test_duplicate_provider_operation_ids_cannot_parse_as_outcome(
    outcome_fixture: dict[str, Any],
) -> None:
    original = outcome_fixture["statement"].predicate.reconciliation.attempts[0]
    duplicate = original.model_copy(update={"effect_id": "effect-002", "attempt_id": "attempt-002"})
    reconciliation = outcome_fixture["statement"].predicate.reconciliation.model_copy(
        update={"attempts": (original, duplicate)}
    )
    attacked = _replace_predicate(outcome_fixture, reconciliation=reconciliation)
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.PAYLOAD_INVALID,)


def test_outcome_index_enforces_attempt_sequence_and_previous_digest() -> None:
    index = InMemoryOutcomeClosureIndex(capacity=4)
    first = index.append_once(
        tenant_id="tenant-synthetic",
        closure_id="closure-001",
        execution_id="execution-001",
        attempt_id="attempt-001",
        closure_sequence=1,
        previous_payload_sha256=None,
        payload_sha256=ZERO_HASH,
        idempotency_key="idempotency-001",
        intent_sha256=ONE_HASH,
    )
    assert first.value == "APPENDED"
    assert (
        index.append_once(
            tenant_id="tenant-synthetic",
            closure_id="closure-001",
            execution_id="execution-001",
            attempt_id="attempt-001",
            closure_sequence=1,
            previous_payload_sha256=None,
            payload_sha256=ZERO_HASH,
            idempotency_key="idempotency-001",
            intent_sha256=ONE_HASH,
        ).value
        == "ALREADY_PRESENT"
    )
    assert (
        index.append_once(
            tenant_id="tenant-synthetic",
            closure_id="closure-002",
            execution_id="execution-001",
            attempt_id="attempt-001",
            closure_sequence=2,
            previous_payload_sha256=ONE_HASH,
            payload_sha256=TWO_HASH,
            idempotency_key="idempotency-001",
            intent_sha256=ONE_HASH,
        ).value
        == "PREVIOUS_DIGEST_CONFLICT"
    )
    assert (
        index.append_once(
            tenant_id="tenant-synthetic",
            closure_id="closure-002",
            execution_id="execution-001",
            attempt_id="attempt-001",
            closure_sequence=2,
            previous_payload_sha256=ZERO_HASH,
            payload_sha256=TWO_HASH,
            idempotency_key="idempotency-001",
            intent_sha256=ONE_HASH,
        ).value
        == "APPENDED"
    )
    assert (
        index.append_once(
            tenant_id="tenant-synthetic",
            closure_id="closure-001",
            execution_id="execution-002",
            attempt_id="attempt-002",
            closure_sequence=1,
            previous_payload_sha256=None,
            payload_sha256=THREE_HASH,
            idempotency_key="idempotency-002",
            intent_sha256=TWO_HASH,
        ).value
        == "CLOSURE_ID_CONFLICT"
    )


def test_outcome_index_is_atomic_under_concurrency() -> None:
    index = InMemoryOutcomeClosureIndex()

    def append() -> str:
        return index.append_once(
            tenant_id="tenant-synthetic",
            closure_id="closure-001",
            execution_id="execution-001",
            attempt_id="attempt-001",
            closure_sequence=1,
            previous_payload_sha256=None,
            payload_sha256=ZERO_HASH,
            idempotency_key="idempotency-001",
            intent_sha256=ONE_HASH,
        ).value

    with ThreadPoolExecutor(max_workers=16) as executor:
        statuses = list(executor.map(lambda _: append(), range(32)))
    assert statuses.count("APPENDED") == 1
    assert statuses.count("ALREADY_PRESENT") == 31


def test_known_failure_derives_fail_without_success_claim(outcome_fixture: dict[str, Any]) -> None:
    original = outcome_fixture["statement"].predicate.reconciliation.attempts[0]
    failed = original.model_copy(
        update={
            "status": EffectAttemptStatus.FAILED,
            "terminal_result": EffectTerminalResult.EFFECT_REJECTED,
        }
    )
    reconciliation = outcome_fixture["statement"].predicate.reconciliation.model_copy(
        update={"attempts": (failed,)}
    )
    attacked = _replace_predicate(
        outcome_fixture,
        reconciliation=reconciliation,
        claimed_outcome=ClaimedOutcome.FAIL,
    )
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.FAIL
    assert result.recorded is True
    assert result.observed_success_count == 0


def test_unresolved_reconciliation_is_unknown_and_never_recorded(
    outcome_fixture: dict[str, Any],
) -> None:
    unresolved = UnresolvedEffectObservation(
        effect_id="effect-unresolved-001",
        reason=UnresolvedEffectReason.QUERY_UNAVAILABLE,
        observer_evidence_sha256=outcome_fixture["statement"]
        .predicate.reconciliation.attempts[0]
        .observer_evidence_sha256,
    )
    reconciliation = outcome_fixture["statement"].predicate.reconciliation.model_copy(
        update={"unresolved": (unresolved,)}
    )
    attacked = _replace_predicate(outcome_fixture, reconciliation=reconciliation)
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNSAFE_SUCCESS
    assert result.reason_codes == (OutcomeClosureVerificationReason.UNSAFE_UNRESOLVED_EFFECT,)
    assert result.recorded is False


def test_duplicate_success_is_unsafe_success_and_not_recorded(
    outcome_fixture: dict[str, Any],
) -> None:
    original = outcome_fixture["statement"].predicate.reconciliation.attempts[0]
    duplicate = original.model_copy(
        update={"effect_id": "effect-002", "attempt_id": "effect-attempt-002"}
    )
    reconciliation = outcome_fixture["statement"].predicate.reconciliation.model_copy(
        update={"attempts": (original, duplicate)}
    )
    attacked = _replace_predicate(outcome_fixture, reconciliation=reconciliation)
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.PAYLOAD_INVALID,)
    assert result.recorded is False


def test_rejected_external_action_input_with_success_claim_is_unsafe(
    outcome_fixture: dict[str, Any],
) -> None:
    rejected = outcome_fixture["action_result"].model_copy(
        update={
            "status": VerificationStatus.REJECT,
            "reason_codes": (VerificationReason.SIGNATURE_INVALID,),
            "reserved": False,
        }
    )
    attacked = dict(outcome_fixture)
    attacked["action_result"] = rejected
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNSAFE_SUCCESS
    assert result.recorded is False


def test_index_conflicts_are_fail_closed(outcome_fixture: dict[str, Any]) -> None:
    index = InMemoryOutcomeClosureIndex(capacity=1)
    first = _verify(outcome_fixture, outcome_index=index)
    assert first.status == OutcomeVerdict.PASS
    second = _replace_predicate(outcome_fixture, closure_id="closure-002")
    second_result = _verify(second, outcome_index=index)
    assert second_result.status == OutcomeVerdict.UNKNOWN
    assert second_result.reason_codes == (
        OutcomeClosureVerificationReason.ATTEMPT_SEQUENCE_CONFLICT,
    )


@pytest.mark.parametrize(
    ("field", "expected_reason"),
    (
        ("tenant_id", OutcomeClosureVerificationReason.PRODUCER_SIGNER_MISMATCH),
        ("execution_id", OutcomeClosureVerificationReason.EFFECT_BINDING_MISMATCH),
    ),
)
def test_operator_binding_cannot_be_replaced_by_signed_closure(
    outcome_fixture: dict[str, Any],
    field: str,
    expected_reason: OutcomeClosureVerificationReason,
) -> None:
    predicate = outcome_fixture["statement"].predicate
    altered_value = "tenant-attacker" if field == "tenant_id" else "execution-attacker"
    altered = predicate.model_copy(update={field: altered_value})
    statement = outcome_fixture["statement"].model_copy(update={"predicate": altered})
    attacked = dict(outcome_fixture)
    payload = wire_payload(statement)
    attacked.update(
        {
            "statement": statement,
            "payload": payload,
            "envelope": envelope_bytes(
                payload, (("outcome-root", outcome_fixture["outcome_key"]),)
            ),
        }
    )
    # Deliberately retain the independently supplied original expected binding.
    result = _verify(attacked)
    assert result.status == (
        OutcomeVerdict.UNKNOWN if field == "tenant_id" else OutcomeVerdict.UNSAFE_SUCCESS
    )
    assert result.reason_codes == (expected_reason,)


def test_outcome_observer_cannot_be_the_execution_observer(
    outcome_fixture: dict[str, Any],
) -> None:
    root = outcome_fixture["outcome_root"].model_copy(update={"principal_id": "observer-001"})
    policy = outcome_fixture["policy"].model_copy(
        update={
            "allowed_outcome_observer_principals": ("observer-001",),
            "roots": (*outcome_fixture["policy"].roots[:-1], root),
        }
    )
    attacked = _replace_predicate(
        outcome_fixture,
        producer=outcome_fixture["statement"].predicate.producer.model_copy(
            update={"observer_principals": ("observer-001",)}
        ),
    )
    attacked["policy"] = policy
    result = _verify(attacked)
    assert result.status == OutcomeVerdict.UNKNOWN
    assert result.reason_codes == (OutcomeClosureVerificationReason.SELF_OBSERVATION,)


def test_schema_model_parity_for_public_outcome_documents(
    outcome_fixture: dict[str, Any],
) -> None:
    result = _verify(outcome_fixture)
    documents: dict[str, tuple[type[BaseModel], dict[str, Any]]] = {
        "outcome-closure-expected-binding-v0p1": (
            ExpectedOutcomeBinding,
            outcome_fixture["expected"].model_dump(mode="json"),
        ),
        "outcome-closure-predicate-v0p1": (
            OutcomeClosurePredicate,
            outcome_fixture["statement"].predicate.model_dump(mode="json"),
        ),
        "outcome-closure-statement-v0p1": (
            OutcomeClosureStatement,
            outcome_fixture["statement"].model_dump(mode="json", by_alias=True),
        ),
        "outcome-closure-verification-result-v0p1": (
            OutcomeClosureVerificationResult,
            result.model_dump(mode="json"),
        ),
    }
    for schema_name, (model, document) in documents.items():
        schema = json.loads((ROOT / "schemas" / f"{schema_name}.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
        assert (
            model.model_validate_json(json.dumps(document)).model_dump(mode="json", by_alias=True)
            == document
        )


@pytest.mark.parametrize(
    "update",
    (
        {"status": OutcomeVerdict.PASS, "reason_codes": ("FAIL_VERIFIED",)},
        {"status": OutcomeVerdict.UNKNOWN, "reason_codes": ("PASS_VERIFIED",)},
        {"status": OutcomeVerdict.UNSAFE_SUCCESS, "recorded": True},
        {"status": OutcomeVerdict.FAIL, "reason_codes": ("EVIDENCE_BYTES_UNAVAILABLE",)},
        {
            "status": OutcomeVerdict.PASS,
            "reason_codes": ("PASS_VERIFIED", "FAIL_VERIFIED"),
        },
        {
            "status": OutcomeVerdict.FAIL,
            "reason_codes": ("FAIL_VERIFIED", "PASS_VERIFIED"),
        },
    ),
)
def test_verdict_reason_recorded_contract_is_closed(
    outcome_fixture: dict[str, Any], update: dict[str, Any]
) -> None:
    result = _verify(outcome_fixture).model_dump(mode="json")
    result.update(update)
    with pytest.raises(ValidationError):
        OutcomeClosureVerificationResult.model_validate(result)
    schema = json.loads(
        (ROOT / "schemas" / "outcome-closure-verification-result-v0p1.schema.json").read_text()
    )
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)


@pytest.mark.parametrize(
    ("reason", "evidence"),
    (
        ("MISSING_EVIDENCE", ONE_HASH),
        ("QUERY_UNAVAILABLE", None),
        ("PENDING", None),
        ("CONFLICT", None),
    ),
)
def test_unresolved_reason_evidence_schema_model_parity(
    outcome_fixture: dict[str, Any], reason: str, evidence: str | None
) -> None:
    predicate = outcome_fixture["statement"].predicate.model_dump(mode="json")
    predicate["reconciliation"]["unresolved"] = [
        {
            "effect_id": "effect-unresolved-schema",
            "reason": reason,
            "observer_evidence_sha256": evidence,
        }
    ]
    # Every row is intentionally invalid: MISSING_EVIDENCE must not carry a
    # digest, while the other unresolved reasons must carry one.
    model_rejected = False
    try:
        OutcomeClosurePredicate.model_validate(predicate)
    except ValidationError:
        model_rejected = True
    assert model_rejected is True
    schema = json.loads(
        (ROOT / "schemas" / "outcome-closure-predicate-v0p1.schema.json").read_text()
    )
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(predicate)


def test_python_optimized_mode_cannot_accept_unrecorded_pass() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            (
                "from proofflow.outcome_closure import OutcomeClosureVerificationResult as R; "
                "from pydantic import ValidationError; "
                "d={'verification_version':'proofflow.outcome-closure-verification/v0.1',"
                "'status':'PASS','reason_codes':['APPENDED'],'closure_id':None,"
                "'payload_sha256':None,'envelope_sha256':'sha256:'+'0'*64,"
                "'verified_outcome_observer_roots':[],'recorded':False}; "
                "\ntry: R.model_validate(d)\nexcept ValidationError: raise SystemExit(0)"
                "\nraise SystemExit(9)"
            ),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_outcome_cli_uses_closed_exit_codes(outcome_fixture: dict[str, Any], tmp_path: Any) -> None:
    def run(fixture: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        directory = tmp_path / fixture["statement"].predicate.closure_id
        directory.mkdir(exist_ok=True)
        values = {
            "outcome.json": fixture["envelope"],
            "action.json": fixture["action_envelope"],
            "receipt.json": fixture["receipt_envelope"],
            "trust.json": json.dumps(fixture["policy"].model_dump(mode="json")).encode(),
            "expected.json": json.dumps(
                fixture["expected"].model_dump(mode="json")
                if isinstance(fixture["expected"], BaseModel)
                else fixture["expected"]
            ).encode(),
            "action-result.json": json.dumps(
                fixture["action_result"].model_dump(mode="json")
            ).encode(),
            "receipt-result.json": json.dumps(
                fixture["receipt_result"].model_dump(mode="json")
            ).encode(),
            "evidence.json": json.dumps(
                {
                    digest: base64.b64encode(raw).decode("ascii")
                    for digest, raw in fixture["evidence"].items()
                }
            ).encode(),
        }
        for name, payload in values.items():
            (directory / name).write_bytes(payload)
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "proofflow.cli",
                "outcome",
                "verify",
                "--envelope",
                str(directory / "outcome.json"),
                "--trust-policy",
                str(directory / "trust.json"),
                "--expected-binding",
                str(directory / "expected.json"),
                "--action-certificate-envelope",
                str(directory / "action.json"),
                "--action-certificate-verification",
                str(directory / "action-result.json"),
                "--execution-receipt-envelope",
                str(directory / "receipt.json"),
                "--execution-receipt-verification",
                str(directory / "receipt-result.json"),
                "--evidence",
                str(directory / "evidence.json"),
                "--at",
                "2026-08-30T04:00:00Z",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    first = run(outcome_fixture)
    assert first.returncode == 0
    original = outcome_fixture["statement"].predicate.reconciliation.attempts[0]
    failed = _replace_predicate(
        outcome_fixture,
        closure_id="closure-failed",
        reconciliation=outcome_fixture["statement"].predicate.reconciliation.model_copy(
            update={
                "attempts": (
                    original.model_copy(
                        update={
                            "status": EffectAttemptStatus.FAILED,
                            "terminal_result": EffectTerminalResult.EFFECT_REJECTED,
                        }
                    ),
                )
            }
        ),
        claimed_outcome=ClaimedOutcome.FAIL,
    )
    assert run(failed).returncode == 1
    unknown = _replace_predicate(
        outcome_fixture,
        closure_id="closure-unknown",
        reconciliation=outcome_fixture["statement"].predicate.reconciliation.model_copy(
            update={
                "attempts": (),
                "unresolved": (
                    UnresolvedEffectObservation(
                        effect_id="effect-unknown",
                        reason=UnresolvedEffectReason.QUERY_UNAVAILABLE,
                        observer_evidence_sha256=THREE_HASH,
                    ),
                ),
            }
        ),
        claimed_outcome=ClaimedOutcome.UNKNOWN,
    )
    assert run(unknown).returncode == 3
    unsafe = dict(outcome_fixture)
    unsafe["action_result"] = outcome_fixture["action_result"].model_copy(
        update={
            "status": VerificationStatus.REJECT,
            "reason_codes": (VerificationReason.SIGNATURE_INVALID,),
            "reserved": False,
        }
    )
    assert run(unsafe).returncode == 4
    malformed = dict(outcome_fixture)
    malformed["expected"] = {"not": "an expected binding"}
    assert run(malformed).returncode == 2


@pytest.mark.parametrize("model", (OutcomeClosurePredicate, ExpectedOutcomeBinding))
def test_remote_reference_is_rejected_by_strict_models(
    outcome_fixture: dict[str, Any], model: type[BaseModel]
) -> None:
    document = (
        outcome_fixture["statement"].predicate.model_dump(mode="json")
        if model is OutcomeClosurePredicate
        else outcome_fixture["expected"].model_dump(mode="json")
    )
    if model is OutcomeClosurePredicate:
        document["reconciliation"]["target"] = "https://attacker.invalid/effect"
    else:
        document["effect_target"] = "https://attacker.invalid/effect"
    with pytest.raises(ValidationError):
        model.model_validate(document)
