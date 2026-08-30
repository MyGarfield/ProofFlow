from __future__ import annotations

import base64
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, ValidationError

from proofflow.action_certificate import (
    ACTION_CERTIFICATE_PREDICATE_TYPE,
    DSSE_PAYLOAD_TYPE,
    ActionBinding,
    ActionCertificatePredicate,
    ActionCertificateStatement,
    ActionCertificateVerificationResult,
    ApprovalBinding,
    ApprovalRevocationEntry,
    ApprovalRevocationSnapshot,
    ApprovalRevocationStatus,
    ContextBinding,
    DelegationHop,
    EffectBinding,
    ExecutionObserverScope,
    InMemoryReplayLedger,
    InTotoSubject,
    PolicyBinding,
    PrincipalBinding,
    ResourceBinding,
    Sha256DigestSet,
    SnapshotApprovalRevocationResolver,
    SubjectBinding,
    TrustPolicy,
    TrustPurpose,
    TrustRoot,
    VerificationReason,
    VerificationStatus,
    approval_scope_sha256,
    dsse_pae,
    expected_binding_for,
    sha256_bytes,
    verify_action_certificate,
)
from proofflow.execution_receipt import (
    EXECUTION_RECEIPT_AUDIENCE,
    EXECUTION_RECEIPT_PREDICATE_TYPE,
    REQUIRED_EXECUTION_OBSERVER_SCOPES,
    A2aProtocolObservation,
    ActionCertificateReference,
    ArtifactObservation,
    AttemptObservation,
    CostObservation,
    DurationObservation,
    EffectObservation,
    ExecutionReceiptPredicate,
    ExecutionReceiptStatement,
    ExecutionReceiptVerificationReason,
    ExecutionReceiptVerificationResult,
    ExpectedExecutionBinding,
    InMemoryReceiptIndex,
    LocalProtocolObservation,
    McpProtocolObservation,
    ObservationState,
    ProducerDeclaration,
    ProvenanceReference,
    ReceiptIndexStatus,
    RuntimeObservation,
    ToolOperationObservation,
    TraceObservation,
    action_certificate_verification_sha256,
    expected_execution_binding_for,
    verify_execution_receipt,
)

NOW = datetime(2026, 8, 30, 4, 0, tzinfo=UTC)
ROOT = Path(__file__).parents[2]
ZERO_HASH = "sha256:" + "0" * 64
ONE_HASH = "sha256:" + "1" * 64
TWO_HASH = "sha256:" + "2" * 64
THREE_HASH = "sha256:" + "3" * 64
TRACE_ID = "a" * 32
SPAN_ID = "b" * 16


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode("ascii")


def key_fingerprint(private_key: Ed25519PrivateKey) -> str:
    return sha256_bytes(private_key.public_key().public_bytes_raw())


def root(
    root_id: str,
    key: Ed25519PrivateKey,
    purpose: TrustPurpose,
    principal: str,
    *,
    tenant_id: str = "tenant-synthetic",
    revoked_at: datetime | None = None,
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=1),
) -> TrustRoot:
    observer = purpose == TrustPurpose.EXECUTION_OBSERVER
    return TrustRoot(
        root_id=root_id,
        keyid_hints=(root_id,),
        algorithm="Ed25519",
        purpose=purpose,
        public_key_b64=public_key_b64(key),
        tenant_id=tenant_id,
        principal_id=principal,
        audiences=(EXECUTION_RECEIPT_AUDIENCE,) if observer else ("proof-executor",),
        predicate_types=(
            (EXECUTION_RECEIPT_PREDICATE_TYPE,)
            if observer
            else (ACTION_CERTIFICATE_PREDICATE_TYPE,)
        ),
        execution_observer_scopes=(
            tuple(sorted(REQUIRED_EXECUTION_OBSERVER_SCOPES, key=lambda item: item.value))
            if observer
            else ()
        ),
        not_before=not_before,
        not_after=not_after,
        revoked_at=revoked_at,
    )


def policy(
    issuer_root: TrustRoot,
    approval_root: TrustRoot,
    observer_roots: tuple[TrustRoot, ...],
    *,
    observer_threshold: int = 1,
) -> TrustPolicy:
    return TrustPolicy(
        policy_version="proofflow.action-certificate-trust/v0.1",
        allowed_tenants=("tenant-synthetic",),
        allowed_human_principals=("requestor-001",),
        allowed_workload_principals=("workload-001",),
        allowed_action_issuer_principals=("issuer-001",),
        allowed_approval_principals=("reviewer-001",),
        allowed_execution_observer_principals=tuple(
            dict.fromkeys(item.principal_id for item in observer_roots)
        ),
        allowed_audiences=("proof-executor", EXECUTION_RECEIPT_AUDIENCE),
        allowed_predicate_types=(
            ACTION_CERTIFICATE_PREDICATE_TYPE,
            EXECUTION_RECEIPT_PREDICATE_TYPE,
        ),
        approval_required=True,
        action_issuer_threshold=1,
        human_approval_threshold=1,
        execution_observer_threshold=observer_threshold,
        max_certificate_lifetime_seconds=3600,
        max_clock_skew_seconds=0,
        roots=(issuer_root, approval_root, *observer_roots),
    )


def action_statement() -> ActionCertificateStatement:
    predicate = ActionCertificatePredicate(
        version="0.1",
        certificate_id="certificate-001",
        tenant_id="tenant-synthetic",
        human_principal=PrincipalBinding(
            principal_id="requestor-001", identity_issuer="operator.example"
        ),
        workload_principal=PrincipalBinding(
            principal_id="workload-001", identity_issuer="operator.example"
        ),
        audience="proof-executor",
        delegation_chain=(
            DelegationHop(
                delegator="requestor-001",
                delegatee="workload-001",
                scope_sha256=ONE_HASH,
            ),
        ),
        subject=SubjectBinding(
            subject_type="case", subject_id="case-001", attributes_sha256=ONE_HASH
        ),
        action=ActionBinding(action_name="local-synthetic-transform", parameters_sha256=ONE_HASH),
        resource=ResourceBinding(
            resource_type="artifact",
            resource_id="output-artifact-001",
            attributes_sha256=ZERO_HASH,
        ),
        context=ContextBinding(
            request_id="execution-001",
            trace_id=TRACE_ID,
            environment="public-synthetic",
            attributes_sha256=ONE_HASH,
        ),
        data_classification="PUBLIC_SYNTHETIC",
        policy=PolicyBinding(
            policy_id="policy-001",
            policy_revision="revision-001",
            policy_sha256=TWO_HASH,
            decision="ALLOW",
            evaluated_at=NOW - timedelta(minutes=3),
            expires_at=NOW + timedelta(minutes=30),
        ),
        approval=ApprovalBinding(
            required=True,
            approval_id="approval-001",
            scope_sha256=ZERO_HASH,
            approver_principals=("reviewer-001",),
            expires_at=NOW + timedelta(minutes=20),
        ),
        effect=EffectBinding(
            effect_type="local-synthetic-transform",
            target="process-local-synthetic-store",
            request_sha256=ONE_HASH,
            idempotency_key="idempotency-001",
        ),
        nonce="nonce-001",
        issued_at=NOW - timedelta(minutes=2),
        not_before=NOW - timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=10),
    )
    statement = ActionCertificateStatement(
        _type="https://in-toto.io/Statement/v1",
        subject=(
            InTotoSubject(name="input-artifact-001", digest=Sha256DigestSet(sha256="3" * 64)),
        ),
        predicateType=ACTION_CERTIFICATE_PREDICATE_TYPE,
        predicate=predicate,
    )
    return statement.model_copy(
        update={
            "predicate": predicate.model_copy(
                update={
                    "approval": predicate.approval.model_copy(
                        update={"scope_sha256": approval_scope_sha256(statement)}
                    )
                }
            )
        }
    )


def wire_payload(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def envelope_bytes(
    payload: bytes,
    signatures: tuple[tuple[str, Ed25519PrivateKey], ...],
    *,
    payload_type: str = DSSE_PAYLOAD_TYPE,
) -> bytes:
    pae = dsse_pae(payload_type, payload)
    return json.dumps(
        {
            "payloadType": payload_type,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {"keyid": keyid, "sig": base64.b64encode(key.sign(pae)).decode("ascii")}
                for keyid, key in signatures
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


@pytest.fixture
def receipt_fixture() -> dict[str, Any]:
    issuer_key = Ed25519PrivateKey.generate()
    approval_key = Ed25519PrivateKey.generate()
    observer_key = Ed25519PrivateKey.generate()
    human_key = Ed25519PrivateKey.generate()
    workload_key = Ed25519PrivateKey.generate()
    issuer_root = root("issuer-root", issuer_key, TrustPurpose.ACTION_ISSUER, "issuer-001")
    approval_root = root("approval-root", approval_key, TrustPurpose.HUMAN_APPROVAL, "reviewer-001")
    observer_root = root(
        "observer-root", observer_key, TrustPurpose.EXECUTION_OBSERVER, "observer-001"
    )
    trust_policy = policy(issuer_root, approval_root, (observer_root,))

    action = action_statement()
    action_payload = wire_payload(action)
    action_envelope = envelope_bytes(
        action_payload,
        (("issuer-root", issuer_key), ("approval-root", approval_key)),
    )
    resolver = SnapshotApprovalRevocationResolver(
        ApprovalRevocationSnapshot(
            snapshot_version="proofflow.approval-revocations/v0.1",
            as_of=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(minutes=10),
            entries=(
                ApprovalRevocationEntry(
                    tenant_id="tenant-synthetic",
                    approval_id="approval-001",
                    approval_scope_sha256=approval_scope_sha256(action),
                    status=ApprovalRevocationStatus.ACTIVE,
                ),
            ),
        )
    )
    action_result = verify_action_certificate(
        action_envelope,
        trust_policy=trust_policy,
        expected_binding=expected_binding_for(action),
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=resolver,
        now=NOW - timedelta(seconds=4),
    )
    assert action_result.status == VerificationStatus.ACCEPT

    certificate_ref = ActionCertificateReference(
        certificate_id="certificate-001",
        payload_sha256=sha256_bytes(action_payload),
        envelope_sha256=sha256_bytes(action_envelope),
        verification_result_sha256=action_certificate_verification_sha256(action_result),
        intent_sha256=approval_scope_sha256(action),
        verification_at=NOW - timedelta(seconds=4),
        reserved_at=NOW - timedelta(seconds=4),
    )
    output = ArtifactObservation(
        artifact_id="output-artifact-001",
        sha256="sha256:" + "4" * 64,
        media_type="application/json",
    )
    receipt = ExecutionReceiptStatement(
        _type="https://in-toto.io/Statement/v1",
        subject=(
            InTotoSubject(
                name=output.artifact_id,
                digest=Sha256DigestSet(sha256=output.sha256.removeprefix("sha256:")),
            ),
        ),
        predicateType=EXECUTION_RECEIPT_PREDICATE_TYPE,
        predicate=ExecutionReceiptPredicate(
            version="0.1",
            receipt_id="receipt-001",
            execution_id="execution-001",
            task_id="task-001",
            issued_at=NOW - timedelta(seconds=1),
            certificate_ref=certificate_ref,
            tenant_id="tenant-synthetic",
            case_id="case-001",
            producer=ProducerDeclaration(
                producer_id="local-observer-fixture",
                software_name="ProofFlow reference observer",
                software_version="0.1",
                observer_principals=("observer-001",),
            ),
            attempt=AttemptObservation(
                attempt_id="attempt-001",
                attempt_number=1,
                started_at=NOW - timedelta(seconds=3),
                ended_at=NOW - timedelta(seconds=2),
                status="COMPLETED",
            ),
            executor_workload=action.predicate.workload_principal,
            runtime=RuntimeObservation(
                runtime_name="ProofFlow synthetic local reference",
                runtime_version="0.1.0a0",
                runtime_build_sha256=TWO_HASH,
                instance_id="local-instance-001",
            ),
            protocol=LocalProtocolObservation(
                kind="LOCAL",
                version="proofflow.local/v0.1",
                handler_name="local-synthetic-transform",
                request_sha256=ONE_HASH,
                response_sha256=TWO_HASH,
            ),
            trace=TraceObservation(
                trace_id=TRACE_ID,
                span_id=SPAN_ID,
                parent_span_id=None,
                linked_span_ids=(),
                otel_schema_uri="https://opentelemetry.io/schemas/1.39.0",
                conventions_revision="proofflow.agent-proof/v0.1",
                observer_evidence_sha256=THREE_HASH,
            ),
            inputs=(
                ArtifactObservation(
                    artifact_id="input-artifact-001",
                    sha256=THREE_HASH,
                    media_type="application/json",
                ),
            ),
            outputs=(output,),
            operation=ToolOperationObservation(
                kind="TOOL",
                operation_id="operation-001",
                name="local-synthetic-transform",
                version="0.1",
                input_schema_sha256=ZERO_HASH,
                output_schema_sha256=ONE_HASH,
                request_sha256=ONE_HASH,
                response_sha256=TWO_HASH,
            ),
            model_invocation=None,
            effect=EffectObservation(
                effect_type="local-synthetic-transform",
                target="process-local-synthetic-store",
                intent_sha256=approval_scope_sha256(action),
                idempotency_key="idempotency-001",
                status=ObservationState.UNKNOWN,
                provider_result=None,
                provider_operation_id=None,
                outbox_entry_sha256=None,
                inbox_entry_sha256=None,
                provider_request_sha256=None,
                provider_response_sha256=None,
                before_state_sha256=None,
                after_state_sha256=None,
                provider_event_sha256=None,
                observer_evidence_sha256=None,
            ),
            cost=CostObservation(
                status=ObservationState.UNKNOWN,
                currency=None,
                amount_decimal=None,
                rate_card_sha256=None,
                observer_evidence_sha256=None,
            ),
            duration=DurationObservation(
                status=ObservationState.OBSERVED,
                milliseconds=1000,
                clock="MONOTONIC",
                precision_milliseconds=1,
                observer_evidence_sha256=THREE_HASH,
            ),
            provenance=(
                ProvenanceReference(
                    name="local-observer-event-001",
                    media_type="application/json",
                    sha256=THREE_HASH,
                ),
            ),
        ),
    )
    receipt_payload = wire_payload(receipt)
    receipt_envelope = envelope_bytes(receipt_payload, (("observer-root", observer_key),))
    expected = expected_execution_binding_for(
        receipt,
        human_principal=action.predicate.human_principal,
        executor_workload_key_fingerprints=(key_fingerprint(workload_key),),
        human_principal_key_fingerprints=(key_fingerprint(human_key),),
    )
    return {
        "issuer_key": issuer_key,
        "approval_key": approval_key,
        "observer_key": observer_key,
        "human_key": human_key,
        "workload_key": workload_key,
        "issuer_root": issuer_root,
        "approval_root": approval_root,
        "observer_root": observer_root,
        "policy": trust_policy,
        "action": action,
        "action_payload": action_payload,
        "action_envelope": action_envelope,
        "action_result": action_result,
        "statement": receipt,
        "payload": receipt_payload,
        "envelope": receipt_envelope,
        "expected": expected,
    }


def verify(fixture: dict[str, Any], **updates: Any) -> ExecutionReceiptVerificationResult:
    arguments: dict[str, Any] = {
        "trust_policy": fixture["policy"],
        "expected_binding": fixture["expected"],
        "action_certificate_envelope_bytes": fixture["action_envelope"],
        "action_certificate_verification": fixture["action_result"],
        "receipt_index": InMemoryReceiptIndex(),
        "now": NOW,
    }
    arguments.update(updates)
    return verify_execution_receipt(fixture["envelope"], **arguments)


def expected_for(
    fixture: dict[str, Any], statement: ExecutionReceiptStatement
) -> ExpectedExecutionBinding:
    return expected_execution_binding_for(
        statement,
        human_principal=fixture["action"].predicate.human_principal,
        executor_workload_key_fingerprints=(key_fingerprint(fixture["workload_key"]),),
        human_principal_key_fingerprints=(key_fingerprint(fixture["human_key"]),),
    )


def resign(
    fixture: dict[str, Any],
    statement: ExecutionReceiptStatement,
    *signers: tuple[str, Ed25519PrivateKey],
) -> bytes:
    return envelope_bytes(
        wire_payload(statement), tuple(signers) or (("observer-root", fixture["observer_key"]),)
    )


def replace_statement(
    fixture: dict[str, Any], **predicate_updates: Any
) -> ExecutionReceiptStatement:
    predicate = fixture["statement"].predicate.model_copy(update=predicate_updates)
    subjects = tuple(
        InTotoSubject(
            name=item.artifact_id,
            digest=Sha256DigestSet(sha256=item.sha256.removeprefix("sha256:")),
        )
        for item in predicate.outputs
    )
    return fixture["statement"].model_copy(update={"predicate": predicate, "subject": subjects})


def assert_schema_and_model_reject(
    schema_name: str,
    model: type[BaseModel],
    document: dict[str, Any],
) -> None:
    schema = json.loads((ROOT / "schemas" / f"{schema_name}.schema.json").read_text())
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps(document))


def test_valid_observer_receipt_appends_and_exact_replay_is_idempotent(
    receipt_fixture: dict[str, Any],
) -> None:
    index = InMemoryReceiptIndex()
    first = verify(receipt_fixture, receipt_index=index)
    replay = verify(receipt_fixture, receipt_index=index)

    assert first.status == VerificationStatus.ACCEPT
    assert first.reason_codes == (ExecutionReceiptVerificationReason.APPENDED,)
    assert first.recorded is True
    assert first.verified_execution_observer_roots == ("observer-root",)
    assert first.inference_status == ObservationState.UNKNOWN
    assert first.usage_status == ObservationState.UNKNOWN
    assert first.effect_status == ObservationState.UNKNOWN
    assert first.cost_status == ObservationState.UNKNOWN
    assert first.duration_status == ObservationState.OBSERVED
    assert replay.status == VerificationStatus.ACCEPT
    assert replay.reason_codes == (ExecutionReceiptVerificationReason.ALREADY_PRESENT,)
    assert replay.recorded is True


@pytest.mark.parametrize(
    ("attack", "reason"),
    (
        ("payload", ExecutionReceiptVerificationReason.SIGNATURE_INVALID),
        ("signature", ExecutionReceiptVerificationReason.SIGNATURE_INVALID),
        ("payload_type", ExecutionReceiptVerificationReason.ENVELOPE_INVALID),
    ),
)
def test_dsse_payload_type_payload_and_signature_attacks_reject(
    receipt_fixture: dict[str, Any],
    attack: str,
    reason: ExecutionReceiptVerificationReason,
) -> None:
    envelope = json.loads(receipt_fixture["envelope"])
    if attack == "payload":
        payload = base64.b64decode(envelope["payload"])
        envelope["payload"] = base64.b64encode(payload + b" ").decode("ascii")
    elif attack == "signature":
        envelope["signatures"][0]["sig"] = base64.b64encode(b"\0" * 64).decode("ascii")
    else:
        envelope["payloadType"] = "text/plain"
    attacked = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()

    result = verify_execution_receipt(
        attacked,
        trust_policy=receipt_fixture["policy"],
        expected_binding=receipt_fixture["expected"],
        action_certificate_envelope_bytes=receipt_fixture["action_envelope"],
        action_certificate_verification=receipt_fixture["action_result"],
        receipt_index=InMemoryReceiptIndex(),
        now=NOW,
    )

    assert result.status == VerificationStatus.REJECT
    assert reason in result.reason_codes
    assert result.recorded is False


def test_unconfigured_signing_key_does_not_open_observer_gate(
    receipt_fixture: dict[str, Any],
) -> None:
    rogue = Ed25519PrivateKey.generate()
    envelope = envelope_bytes(receipt_fixture["payload"], (("observer-root", rogue),))
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture["envelope"] = envelope

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.SIGNATURE_INVALID,)


def test_receipt_issued_in_the_future_rejects(receipt_fixture: dict[str, Any]) -> None:
    statement = replace_statement(receipt_fixture, issued_at=NOW + timedelta(seconds=1))
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.RECEIPT_TIME_INVALID,)


@pytest.mark.parametrize("window_attack", ("before_not_before", "at_expiry"))
def test_attempt_must_remain_inside_action_certificate_window(
    receipt_fixture: dict[str, Any], window_attack: str
) -> None:
    action = receipt_fixture["action"].predicate
    if window_attack == "before_not_before":
        attempt = receipt_fixture["statement"].predicate.attempt.model_copy(
            update={
                "started_at": action.not_before - timedelta(seconds=2),
                "ended_at": action.not_before - timedelta(seconds=1),
            }
        )
        issued_at = action.not_before
        verification_time = NOW
        reference = receipt_fixture["statement"].predicate.certificate_ref.model_copy(
            update={
                "verification_at": action.not_before - timedelta(seconds=4),
                "reserved_at": action.not_before - timedelta(seconds=3),
            }
        )
    else:
        attempt = receipt_fixture["statement"].predicate.attempt.model_copy(
            update={
                "started_at": action.expires_at - timedelta(seconds=1),
                "ended_at": action.expires_at,
            }
        )
        issued_at = action.expires_at + timedelta(seconds=1)
        verification_time = action.expires_at + timedelta(seconds=2)
        reference = receipt_fixture["statement"].predicate.certificate_ref
    statement = replace_statement(
        receipt_fixture,
        attempt=attempt,
        issued_at=issued_at,
        certificate_ref=reference,
    )
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture, now=verification_time)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.CERTIFICATE_EXECUTION_WINDOW_MISMATCH,
    )


def test_action_reservation_must_precede_attempt(receipt_fixture: dict[str, Any]) -> None:
    predicate = receipt_fixture["statement"].predicate
    reference = predicate.certificate_ref.model_copy(
        update={"reserved_at": predicate.attempt.started_at + timedelta(seconds=1)}
    )
    statement = replace_statement(receipt_fixture, certificate_ref=reference)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_RESERVATION_ORDER_INVALID,
    )


def test_declared_action_verification_cannot_precede_certificate_window(
    receipt_fixture: dict[str, Any],
) -> None:
    predicate = receipt_fixture["statement"].predicate
    action = receipt_fixture["action"].predicate
    reference = predicate.certificate_ref.model_copy(
        update={
            "verification_at": action.not_before - timedelta(seconds=2),
            "reserved_at": action.not_before - timedelta(seconds=1),
        }
    )
    statement = replace_statement(receipt_fixture, certificate_ref=reference)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.CERTIFICATE_EXECUTION_WINDOW_MISMATCH,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("tenant_id", "tenant-other"),
        ("case_id", "case-other"),
        ("attempt_id", "attempt-other"),
        ("attempt_number", 2),
        ("effect_intent_sha256", ZERO_HASH),
        ("idempotency_key", "idempotency-other"),
    ),
)
def test_expected_binding_scalar_swaps_reject(
    receipt_fixture: dict[str, Any], field: str, replacement: Any
) -> None:
    expected_document = receipt_fixture["expected"].model_dump(mode="json")
    expected_document[field] = replacement
    attacked = ExpectedExecutionBinding.model_validate_json(json.dumps(expected_document))

    result = verify(receipt_fixture, expected_binding=attacked)

    assert result.status == VerificationStatus.REJECT
    expected_reason = (
        ExecutionReceiptVerificationReason.TRUST_POLICY_MISMATCH
        if field == "tenant_id"
        else ExecutionReceiptVerificationReason.EXPECTED_BINDING_MISMATCH
    )
    assert result.reason_codes == (expected_reason,)
    assert result.inference_status == ObservationState.UNKNOWN
    assert result.usage_status == ObservationState.UNKNOWN
    assert result.effect_status == ObservationState.UNKNOWN
    assert result.cost_status == ObservationState.UNKNOWN
    assert result.duration_status == ObservationState.UNKNOWN


@pytest.mark.parametrize(
    "field", ("runtime", "protocol", "trace", "inputs", "outputs", "operation")
)
def test_expected_binding_structural_swaps_reject(
    receipt_fixture: dict[str, Any], field: str
) -> None:
    expected_document = receipt_fixture["expected"].model_dump(mode="json")
    if field in {"inputs", "outputs"}:
        expected_document[field][0]["sha256"] = ZERO_HASH
    elif field == "trace":
        expected_document[field]["span_id"] = "c" * 16
    elif field == "runtime":
        expected_document[field]["instance_id"] = "other-instance"
    elif field == "protocol":
        expected_document[field]["response_sha256"] = ZERO_HASH
    else:
        expected_document[field]["response_sha256"] = ZERO_HASH
    attacked = ExpectedExecutionBinding.model_validate_json(json.dumps(expected_document))

    result = verify(receipt_fixture, expected_binding=attacked)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.EXPECTED_BINDING_MISMATCH,)


def test_action_certificate_envelope_and_result_are_external_trusted_inputs(
    receipt_fixture: dict[str, Any],
) -> None:
    tampered_envelope = receipt_fixture["action_envelope"] + b" "
    envelope_result = verify(
        receipt_fixture,
        action_certificate_envelope_bytes=tampered_envelope,
    )
    assert envelope_result.status == VerificationStatus.REJECT
    assert envelope_result.reason_codes == (
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
    )

    unknown_action_result = ActionCertificateVerificationResult(
        verification_version="proofflow.action-certificate-verification/v0.1",
        status=VerificationStatus.UNKNOWN,
        reason_codes=(VerificationReason.APPROVAL_REVOCATION_UNKNOWN,),
        certificate_id="certificate-001",
        payload_sha256=receipt_fixture["statement"].predicate.certificate_ref.payload_sha256,
        verified_action_issuer_roots=("issuer-root",),
        verified_human_approval_roots=("approval-root",),
        reserved=False,
    )
    ref = receipt_fixture["statement"].predicate.certificate_ref.model_copy(
        update={
            "verification_result_sha256": action_certificate_verification_sha256(
                unknown_action_result
            )
        }
    )
    statement = replace_statement(receipt_fixture, certificate_ref=ref)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )
    unknown = verify(
        attacked_fixture,
        action_certificate_verification=unknown_action_result,
    )
    assert unknown.status == VerificationStatus.UNKNOWN
    assert unknown.reason_codes == (
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN,
    )


@pytest.mark.parametrize(
    "root_ids",
    ((), ("unknown-issuer-root",), ("observer-root",), ("approval-root",)),
)
def test_forged_accepted_result_without_bound_authority_stays_unknown(
    receipt_fixture: dict[str, Any], root_ids: tuple[str, ...]
) -> None:
    forged_result = receipt_fixture["action_result"].model_copy(
        update={"verified_action_issuer_roots": root_ids}
    )
    reference = receipt_fixture["statement"].predicate.certificate_ref.model_copy(
        update={"verification_result_sha256": action_certificate_verification_sha256(forged_result)}
    )
    statement = replace_statement(receipt_fixture, certificate_ref=reference)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture, action_certificate_verification=forged_result)

    assert result.status == VerificationStatus.UNKNOWN
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_AUTHORITY_UNKNOWN,
    )


@pytest.mark.parametrize(
    "attack",
    (
        "certificate_id",
        "case",
        "trace",
        "input_artifact",
        "output_artifact",
        "logical_request",
        "effect_target",
        "operation_name",
        "intent",
        "idempotency",
    ),
)
def test_resigned_receipt_cannot_swap_action_certificate_bindings(
    receipt_fixture: dict[str, Any], attack: str
) -> None:
    predicate = receipt_fixture["statement"].predicate
    updates: dict[str, Any] = {}
    if attack == "certificate_id":
        updates["certificate_ref"] = predicate.certificate_ref.model_copy(
            update={"certificate_id": "certificate-other"}
        )
    elif attack == "case":
        updates["case_id"] = "case-other"
    elif attack == "trace":
        updates["trace"] = predicate.trace.model_copy(update={"trace_id": "c" * 32})
    elif attack == "input_artifact":
        updates["inputs"] = (predicate.inputs[0].model_copy(update={"sha256": ZERO_HASH}),)
    elif attack == "output_artifact":
        updates["outputs"] = (
            predicate.outputs[0].model_copy(update={"artifact_id": "output-artifact-other"}),
        )
    elif attack == "logical_request":
        updates["protocol"] = predicate.protocol.model_copy(update={"request_sha256": ZERO_HASH})
        updates["operation"] = predicate.operation.model_copy(update={"request_sha256": ZERO_HASH})
    elif attack == "effect_target":
        updates["effect"] = predicate.effect.model_copy(update={"target": "target-other"})
    elif attack == "operation_name":
        updates["protocol"] = predicate.protocol.model_copy(update={"handler_name": "name-other"})
        updates["operation"] = predicate.operation.model_copy(update={"name": "name-other"})
    elif attack == "intent":
        updates["certificate_ref"] = predicate.certificate_ref.model_copy(
            update={"intent_sha256": ZERO_HASH}
        )
        updates["effect"] = predicate.effect.model_copy(update={"intent_sha256": ZERO_HASH})
    else:
        updates["effect"] = predicate.effect.model_copy(
            update={"idempotency_key": "idempotency-other"}
        )
    statement = replace_statement(receipt_fixture, **updates)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
    )


def test_allowlisted_workload_swap_still_rejects_action_binding(
    receipt_fixture: dict[str, Any],
) -> None:
    workload = PrincipalBinding(principal_id="workload-other", identity_issuer="operator.example")
    statement = replace_statement(receipt_fixture, executor_workload=workload)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )
    attacked_policy = receipt_fixture["policy"].model_copy(
        update={"allowed_workload_principals": ("workload-001", "workload-other")}
    )

    result = verify(attacked_fixture, trust_policy=attacked_policy)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
    )


@pytest.mark.parametrize("root_attack", ("purpose", "tenant", "stale", "revoked"))
def test_wrong_observer_purpose_tenant_time_and_revocation_fail_closed(
    receipt_fixture: dict[str, Any], root_attack: str
) -> None:
    observer_key = receipt_fixture["observer_key"]
    if root_attack == "purpose":
        attacked_observer = root(
            "observer-root", observer_key, TrustPurpose.ACTION_ISSUER, "observer-001"
        )
    elif root_attack == "tenant":
        attacked_observer = root(
            "observer-root",
            observer_key,
            TrustPurpose.EXECUTION_OBSERVER,
            "observer-001",
            tenant_id="tenant-other",
        )
    elif root_attack == "stale":
        attacked_observer = root(
            "observer-root",
            observer_key,
            TrustPurpose.EXECUTION_OBSERVER,
            "observer-001",
            not_before=NOW - timedelta(days=2),
            not_after=NOW,
        )
    else:
        attacked_observer = root(
            "observer-root",
            observer_key,
            TrustPurpose.EXECUTION_OBSERVER,
            "observer-001",
            revoked_at=NOW,
        )
    attacked_policy = policy(
        receipt_fixture["issuer_root"],
        receipt_fixture["approval_root"],
        (attacked_observer,),
    )

    result = verify(receipt_fixture, trust_policy=attacked_policy)

    assert result.status == VerificationStatus.REJECT
    if root_attack in {"stale", "revoked"}:
        assert result.reason_codes == (
            ExecutionReceiptVerificationReason.ROOT_TIME_OR_REVOCATION_INVALID,
        )
    else:
        assert result.reason_codes == (ExecutionReceiptVerificationReason.TRUST_POLICY_MISMATCH,)


def test_observer_key_must_be_valid_at_receipt_issued_at(
    receipt_fixture: dict[str, Any],
) -> None:
    observer = root(
        "observer-root",
        receipt_fixture["observer_key"],
        TrustPurpose.EXECUTION_OBSERVER,
        "observer-001",
        not_before=NOW - timedelta(microseconds=500_000),
        not_after=NOW + timedelta(days=1),
    )
    attacked_policy = policy(
        receipt_fixture["issuer_root"],
        receipt_fixture["approval_root"],
        (observer,),
    )

    result = verify(receipt_fixture, trust_policy=attacked_policy)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.ROOT_TIME_OR_REVOCATION_INVALID,
    )


def test_action_authority_key_must_be_valid_at_declared_verification_time(
    receipt_fixture: dict[str, Any],
) -> None:
    issuer = root(
        "issuer-root",
        receipt_fixture["issuer_key"],
        TrustPurpose.ACTION_ISSUER,
        "issuer-001",
        not_before=NOW - timedelta(seconds=3),
        not_after=NOW + timedelta(days=1),
    )
    attacked_policy = policy(
        issuer,
        receipt_fixture["approval_root"],
        (receipt_fixture["observer_root"],),
    )

    result = verify(receipt_fixture, trust_policy=attacked_policy)

    assert result.status == VerificationStatus.UNKNOWN
    assert result.reason_codes == (
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_AUTHORITY_UNKNOWN,
    )


def test_executor_or_action_authority_cannot_self_observe(
    receipt_fixture: dict[str, Any],
) -> None:
    for principal, key in (
        ("workload-001", receipt_fixture["observer_key"]),
        ("observer-001", receipt_fixture["issuer_key"]),
    ):
        attacked_observer = root("observer-root", key, TrustPurpose.EXECUTION_OBSERVER, principal)
        attacked_policy = policy(
            receipt_fixture["issuer_root"],
            receipt_fixture["approval_root"],
            (attacked_observer,),
        )
        statement = replace_statement(
            receipt_fixture,
            producer=receipt_fixture["statement"].predicate.producer.model_copy(
                update={"observer_principals": (principal,)}
            ),
        )
        attacked_fixture = dict(receipt_fixture)
        attacked_fixture.update(
            {
                "statement": statement,
                "envelope": resign(receipt_fixture, statement, ("observer-root", key)),
                "expected": expected_for(receipt_fixture, statement),
            }
        )

        result = verify(attacked_fixture, trust_policy=attacked_policy)

        assert result.status == VerificationStatus.REJECT
        assert result.reason_codes == (ExecutionReceiptVerificationReason.SELF_OBSERVATION,)


@pytest.mark.parametrize("identity_key", ("workload_key", "human_key"))
def test_executor_or_human_key_alias_cannot_observe_under_another_principal(
    receipt_fixture: dict[str, Any], identity_key: str
) -> None:
    signing_key = receipt_fixture[identity_key]
    attacked_observer = root(
        "observer-root", signing_key, TrustPurpose.EXECUTION_OBSERVER, "observer-001"
    )
    attacked_policy = policy(
        receipt_fixture["issuer_root"],
        receipt_fixture["approval_root"],
        (attacked_observer,),
    )
    statement = receipt_fixture["statement"]
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture["envelope"] = resign(
        receipt_fixture, statement, ("observer-root", signing_key)
    )

    result = verify(attacked_fixture, trust_policy=attacked_policy)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.SELF_OBSERVATION,)


@pytest.mark.parametrize("duplicate_dimension", ("principal", "key"))
def test_duplicate_principal_or_key_cannot_fake_observer_threshold(
    receipt_fixture: dict[str, Any], duplicate_dimension: str
) -> None:
    second_key = Ed25519PrivateKey.generate()
    first_principal = "observer-001"
    second_principal = "observer-001" if duplicate_dimension == "principal" else "observer-002"
    second_root_key = (
        second_key if duplicate_dimension == "principal" else receipt_fixture["observer_key"]
    )
    second_root = root(
        "observer-root-2",
        second_root_key,
        TrustPurpose.EXECUTION_OBSERVER,
        second_principal,
    )
    attacked_policy = policy(
        receipt_fixture["issuer_root"],
        receipt_fixture["approval_root"],
        (receipt_fixture["observer_root"], second_root),
        observer_threshold=2,
    )
    statement = replace_statement(
        receipt_fixture,
        producer=receipt_fixture["statement"].predicate.producer.model_copy(
            update={
                "observer_principals": tuple(dict.fromkeys((first_principal, second_principal)))
            }
        ),
    )
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(
                receipt_fixture,
                statement,
                ("observer-root", receipt_fixture["observer_key"]),
                ("observer-root-2", second_root_key),
            ),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture, trust_policy=attacked_policy)

    if duplicate_dimension == "principal":
        assert result.status == VerificationStatus.UNKNOWN
        assert result.reason_codes == (
            ExecutionReceiptVerificationReason.EXECUTION_OBSERVER_THRESHOLD_NOT_MET,
        )
    else:
        assert result.status == VerificationStatus.REJECT
        assert result.reason_codes == (ExecutionReceiptVerificationReason.PRODUCER_SIGNER_MISMATCH,)


@pytest.mark.parametrize(
    "declared",
    (("observer-other",), ("observer-001", "observer-extra")),
)
def test_producer_observer_set_must_equal_counted_signers(
    receipt_fixture: dict[str, Any], declared: tuple[str, ...]
) -> None:
    statement = replace_statement(
        receipt_fixture,
        producer=receipt_fixture["statement"].predicate.producer.model_copy(
            update={"observer_principals": declared}
        ),
    )
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.PRODUCER_SIGNER_MISMATCH,)


def test_receipt_and_attempt_conflicts_are_append_only(receipt_fixture: dict[str, Any]) -> None:
    index = InMemoryReceiptIndex()
    assert verify(receipt_fixture, receipt_index=index).status == VerificationStatus.ACCEPT

    changed_output = (
        receipt_fixture["statement"].predicate.outputs[0].model_copy(update={"sha256": ZERO_HASH})
    )
    same_receipt = replace_statement(receipt_fixture, outputs=(changed_output,))
    same_receipt_fixture = dict(receipt_fixture)
    same_receipt_fixture.update(
        {
            "statement": same_receipt,
            "envelope": resign(receipt_fixture, same_receipt),
            "expected": expected_for(receipt_fixture, same_receipt),
        }
    )
    receipt_conflict = verify(same_receipt_fixture, receipt_index=index)
    assert receipt_conflict.status == VerificationStatus.REJECT
    assert receipt_conflict.reason_codes == (
        ExecutionReceiptVerificationReason.RECEIPT_ID_CONFLICT,
    )

    other_receipt = replace_statement(receipt_fixture, receipt_id="receipt-002")
    other_fixture = dict(receipt_fixture)
    other_fixture.update(
        {
            "statement": other_receipt,
            "envelope": resign(receipt_fixture, other_receipt),
            "expected": expected_for(receipt_fixture, other_receipt),
        }
    )
    attempt_conflict = verify(other_fixture, receipt_index=index)
    assert attempt_conflict.status == VerificationStatus.REJECT
    assert attempt_conflict.reason_codes == (ExecutionReceiptVerificationReason.ATTEMPT_CONFLICT,)


def test_semantically_equal_but_differently_encoded_payload_conflicts(
    receipt_fixture: dict[str, Any],
) -> None:
    index = InMemoryReceiptIndex()
    assert verify(receipt_fixture, receipt_index=index).status == VerificationStatus.ACCEPT
    pretty_payload = json.dumps(
        receipt_fixture["statement"].model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode()
    pretty_envelope = envelope_bytes(
        pretty_payload, (("observer-root", receipt_fixture["observer_key"]),)
    )
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture["envelope"] = pretty_envelope

    result = verify(attacked_fixture, receipt_index=index)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.RECEIPT_ID_CONFLICT,)


@pytest.mark.parametrize("protocol_kind", ("MCP", "A2A"))
def test_protocol_success_like_response_cannot_upgrade_unknown_effect(
    receipt_fixture: dict[str, Any], protocol_kind: str
) -> None:
    protocol = (
        McpProtocolObservation(
            kind="MCP",
            version="2026-07-28",
            server_name="synthetic-server",
            tool_name="local-synthetic-transform",
            request_sha256=ONE_HASH,
            response_sha256=TWO_HASH,
        )
        if protocol_kind == "MCP"
        else A2aProtocolObservation(
            kind="A2A",
            version="1.0.1",
            agent_name="synthetic-agent",
            task_id="task-001",
            request_sha256=ONE_HASH,
            response_sha256=TWO_HASH,
        )
    )
    statement = replace_statement(receipt_fixture, protocol=protocol)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.ACCEPT
    assert result.effect_status == ObservationState.UNKNOWN


def test_protocol_and_operation_digest_chain_cannot_split(
    receipt_fixture: dict[str, Any],
) -> None:
    protocol = receipt_fixture["statement"].predicate.protocol.model_copy(
        update={"response_sha256": ZERO_HASH}
    )
    statement = replace_statement(receipt_fixture, protocol=protocol)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.PAYLOAD_INVALID,)


def test_a2a_task_id_cannot_split_from_receipt_task(
    receipt_fixture: dict[str, Any],
) -> None:
    protocol = A2aProtocolObservation(
        kind="A2A",
        version="1.0.1",
        agent_name="synthetic-agent",
        task_id="task-other",
        request_sha256=ONE_HASH,
        response_sha256=TWO_HASH,
    )
    statement = replace_statement(receipt_fixture, protocol=protocol)
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture.update(
        {
            "statement": statement,
            "envelope": resign(receipt_fixture, statement),
            "expected": expected_for(receipt_fixture, statement),
        }
    )

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.PAYLOAD_INVALID,)


def test_receipt_index_idempotency_capacity_and_concurrency() -> None:
    index = InMemoryReceiptIndex(capacity=1)
    assert (
        index.append_once(
            tenant_id="tenant-synthetic",
            receipt_id="receipt-001",
            execution_id="execution-001",
            attempt_id="attempt-001",
            payload_sha256=ZERO_HASH,
            idempotency_key="idempotency-001",
            intent_sha256=ONE_HASH,
        )
        == ReceiptIndexStatus.APPENDED
    )
    assert (
        index.append_once(
            tenant_id="tenant-synthetic",
            receipt_id="receipt-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
            payload_sha256=TWO_HASH,
            idempotency_key="idempotency-001",
            intent_sha256=THREE_HASH,
        )
        == ReceiptIndexStatus.IDEMPOTENCY_CONFLICT
    )
    assert (
        index.append_once(
            tenant_id="tenant-synthetic",
            receipt_id="receipt-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
            payload_sha256=TWO_HASH,
            idempotency_key="idempotency-002",
            intent_sha256=ONE_HASH,
        )
        == ReceiptIndexStatus.UNAVAILABLE
    )

    concurrent = InMemoryReceiptIndex()

    def append() -> ReceiptIndexStatus:
        return concurrent.append_once(
            tenant_id="tenant-synthetic",
            receipt_id="receipt-001",
            execution_id="execution-001",
            attempt_id="attempt-001",
            payload_sha256=ZERO_HASH,
            idempotency_key="idempotency-001",
            intent_sha256=ONE_HASH,
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        statuses = list(executor.map(lambda _: append(), range(64)))
    assert statuses.count(ReceiptIndexStatus.APPENDED) == 1
    assert statuses.count(ReceiptIndexStatus.ALREADY_PRESENT) == 63


@pytest.mark.parametrize(
    ("model", "document"),
    (
        (
            CostObservation,
            {
                "status": "UNKNOWN",
                "currency": "USD",
                "amount_decimal": "0",
                "observer_evidence_sha256": ZERO_HASH,
            },
        ),
        (
            DurationObservation,
            {"status": "UNKNOWN", "milliseconds": 0, "observer_evidence_sha256": ZERO_HASH},
        ),
        (
            EffectObservation,
            {
                "intent_sha256": ZERO_HASH,
                "idempotency_key": "idempotency-001",
                "status": "UNKNOWN",
                "provider_result": "TRANSPORT_ACK",
            },
        ),
    ),
)
def test_unknown_observations_cannot_hide_implicit_zero_or_effect_claims(
    model: type[BaseModel], document: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(document)


def test_observed_zero_requires_and_accepts_observer_evidence() -> None:
    cost = CostObservation(
        status=ObservationState.OBSERVED,
        currency="USD",
        amount_decimal="0",
        rate_card_sha256=ONE_HASH,
        observer_evidence_sha256=ZERO_HASH,
    )
    duration = DurationObservation(
        status=ObservationState.OBSERVED,
        milliseconds=0,
        clock="MONOTONIC",
        precision_milliseconds=1,
        observer_evidence_sha256=ZERO_HASH,
    )
    assert cost.amount_decimal == "0"
    assert duration.milliseconds == 0


def test_schema_model_parity_for_public_receipt_documents(receipt_fixture: dict[str, Any]) -> None:
    documents: dict[str, tuple[type[BaseModel], dict[str, Any]]] = {
        "execution-receipt-expected-binding-v0p1": (
            ExpectedExecutionBinding,
            receipt_fixture["expected"].model_dump(mode="json"),
        ),
        "execution-receipt-predicate-v0p1": (
            ExecutionReceiptPredicate,
            receipt_fixture["statement"].predicate.model_dump(mode="json"),
        ),
        "execution-receipt-statement-v0p1": (
            ExecutionReceiptStatement,
            receipt_fixture["statement"].model_dump(mode="json", by_alias=True),
        ),
        "execution-receipt-verification-result-v0p1": (
            ExecutionReceiptVerificationResult,
            verify(receipt_fixture).model_dump(mode="json"),
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


def test_schema_and_model_reject_remote_reference_and_protocol_cross_shape(
    receipt_fixture: dict[str, Any],
) -> None:
    predicate = receipt_fixture["statement"].predicate.model_dump(mode="json")
    predicate["runtime"]["runtime_name"] = "https://attacker.invalid/runtime"
    assert_schema_and_model_reject(
        "execution-receipt-predicate-v0p1", ExecutionReceiptPredicate, predicate
    )

    expected = receipt_fixture["expected"].model_dump(mode="json")
    expected["executor_workload_key_fingerprints"] = ["not-a-sha256"]
    assert_schema_and_model_reject(
        "execution-receipt-expected-binding-v0p1", ExpectedExecutionBinding, expected
    )

    predicate = receipt_fixture["statement"].predicate.model_dump(mode="json")
    predicate["producer"]["observer_principals"] = ["https://attacker.invalid/observer"]
    assert_schema_and_model_reject(
        "execution-receipt-predicate-v0p1", ExecutionReceiptPredicate, predicate
    )

    trust = receipt_fixture["policy"].model_dump(mode="json")
    trust["roots"][2]["execution_observer_scopes"] = [
        ExecutionObserverScope.RUNTIME_EXECUTION.value
    ]
    assert_schema_and_model_reject("action-certificate-trust-policy-v0p1", TrustPolicy, trust)

    predicate = receipt_fixture["statement"].predicate.model_dump(mode="json")
    predicate["protocol"]["kind"] = "MCP"
    predicate["protocol"]["version"] = "2026-07-28"
    assert_schema_and_model_reject(
        "execution-receipt-predicate-v0p1", ExecutionReceiptPredicate, predicate
    )


@pytest.mark.parametrize("attack", ("cost", "duration", "effect", "inference"))
def test_schema_and_model_keep_missing_observer_evidence_unknown(
    receipt_fixture: dict[str, Any], attack: str
) -> None:
    predicate = receipt_fixture["statement"].predicate.model_dump(mode="json")
    if attack == "cost":
        predicate["cost"].update(
            {
                "currency": "USD",
                "amount_decimal": "0",
                "observer_evidence_sha256": ZERO_HASH,
            }
        )
    elif attack == "duration":
        predicate["duration"] = {
            "status": "UNKNOWN",
            "milliseconds": 0,
            "observer_evidence_sha256": ZERO_HASH,
        }
    elif attack == "effect":
        predicate["effect"]["provider_result"] = "TRANSPORT_ACK"
    else:
        predicate["model_invocation"] = {
            "invocation_id": "invocation-001",
            "provider": "synthetic-provider",
            "model": "synthetic-model",
            "model_revision": "revision-001",
            "inference_status": "UNKNOWN",
            "request_sha256": ZERO_HASH,
            "response_sha256": None,
            "inference_observer_evidence_sha256": None,
            "usage": {
                "status": "UNKNOWN",
                "input_tokens": None,
                "output_tokens": None,
                "total_tokens": None,
                "observer_evidence_sha256": None,
            },
        }
    assert_schema_and_model_reject(
        "execution-receipt-predicate-v0p1", ExecutionReceiptPredicate, predicate
    )


def test_schema_and_model_reject_missing_conditional_fields(
    receipt_fixture: dict[str, Any],
) -> None:
    predicate = receipt_fixture["statement"].predicate.model_dump(mode="json")
    predicate["cost"] = {"status": "OBSERVED"}
    assert_schema_and_model_reject(
        "execution-receipt-predicate-v0p1", ExecutionReceiptPredicate, predicate
    )

    result = verify(receipt_fixture).model_dump(mode="json")
    del result["receipt_id"]
    assert_schema_and_model_reject(
        "execution-receipt-verification-result-v0p1",
        ExecutionReceiptVerificationResult,
        result,
    )

    trust = receipt_fixture["policy"].model_dump(mode="json")
    del trust["roots"][2]["execution_observer_scopes"]
    assert_schema_and_model_reject("action-certificate-trust-policy-v0p1", TrustPolicy, trust)

    trust = receipt_fixture["policy"].model_dump(mode="json")
    del trust["allowed_approval_principals"]
    assert_schema_and_model_reject("action-certificate-trust-policy-v0p1", TrustPolicy, trust)


def test_schema_and_model_reject_observed_claims_on_nonaccept_result(
    receipt_fixture: dict[str, Any],
) -> None:
    result = verify(receipt_fixture).model_dump(mode="json")
    result.update(
        {
            "status": "REJECT",
            "reason_codes": ["SIGNATURE_INVALID"],
            "recorded": False,
            "duration_status": "OBSERVED",
        }
    )
    assert_schema_and_model_reject(
        "execution-receipt-verification-result-v0p1",
        ExecutionReceiptVerificationResult,
        result,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (("trace_id", "0" * 32), ("span_id", "0" * 16), ("parent_span_id", "0" * 16)),
)
def test_schema_and_model_reject_all_zero_otel_ids(
    receipt_fixture: dict[str, Any], field: str, value: str
) -> None:
    predicate = receipt_fixture["statement"].predicate.model_dump(mode="json")
    predicate["trace"][field] = value
    assert_schema_and_model_reject(
        "execution-receipt-predicate-v0p1", ExecutionReceiptPredicate, predicate
    )


def test_signed_duplicate_json_and_resource_bounds_reject(receipt_fixture: dict[str, Any]) -> None:
    duplicate_payload = receipt_fixture["payload"].replace(
        b'"version":"0.1"', b'"version":"0.1","version":"0.1"', 1
    )
    duplicate_envelope = envelope_bytes(
        duplicate_payload, (("observer-root", receipt_fixture["observer_key"]),)
    )
    duplicate_result = verify_execution_receipt(
        duplicate_envelope,
        trust_policy=receipt_fixture["policy"],
        expected_binding=receipt_fixture["expected"],
        action_certificate_envelope_bytes=receipt_fixture["action_envelope"],
        action_certificate_verification=receipt_fixture["action_result"],
        receipt_index=InMemoryReceiptIndex(),
        now=NOW,
    )
    assert duplicate_result.status == VerificationStatus.REJECT
    assert duplicate_result.reason_codes == (ExecutionReceiptVerificationReason.PAYLOAD_INVALID,)

    oversized = b"{" + b" " * (256 * 1024)
    oversized_result = verify_execution_receipt(
        oversized,
        trust_policy=receipt_fixture["policy"],
        expected_binding=receipt_fixture["expected"],
        action_certificate_envelope_bytes=receipt_fixture["action_envelope"],
        action_certificate_verification=receipt_fixture["action_result"],
        receipt_index=InMemoryReceiptIndex(),
        now=NOW,
    )
    assert oversized_result.status == VerificationStatus.REJECT
    assert oversized_result.reason_codes == (ExecutionReceiptVerificationReason.ENVELOPE_TOO_LARGE,)
    with pytest.raises(ValueError):
        InMemoryReceiptIndex(capacity=0)
    with pytest.raises(ValueError):
        InMemoryReceiptIndex(capacity=1_000_001)


@pytest.mark.parametrize("invalid_payload", (b"\xff", b'{"value":NaN}'))
def test_signed_non_utf8_or_non_finite_json_payload_rejects(
    receipt_fixture: dict[str, Any], invalid_payload: bytes
) -> None:
    envelope = envelope_bytes(
        invalid_payload, (("observer-root", receipt_fixture["observer_key"]),)
    )
    attacked_fixture = dict(receipt_fixture)
    attacked_fixture["envelope"] = envelope

    result = verify(attacked_fixture)

    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (ExecutionReceiptVerificationReason.PAYLOAD_INVALID,)


def test_python_optimized_mode_keeps_closed_result_contract() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            (
                "from proofflow.execution_receipt import "
                "ExecutionReceiptVerificationResult as R; "
                "from pydantic import ValidationError; "
                "d={'verification_version':'proofflow.execution-receipt-verification/v0.1',"
                "'status':'ACCEPT','reason_codes':['APPENDED'],'receipt_id':None,"
                "'payload_sha256':None,'envelope_sha256':'sha256:'+'0'*64,"
                "'verified_execution_observer_roots':[],'recorded':False,"
                "'inference_status':'UNKNOWN','usage_status':'UNKNOWN',"
                "'effect_status':'UNKNOWN','cost_status':'UNKNOWN','duration_status':'UNKNOWN'}; "
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


def write_cli_inputs(
    directory: Path,
    fixture: dict[str, Any],
    *,
    trust_policy: TrustPolicy | None = None,
) -> list[str]:
    files: dict[str, bytes] = {
        "receipt.json": fixture["envelope"],
        "action.json": fixture["action_envelope"],
        "trust.json": json.dumps(
            (trust_policy or fixture["policy"]).model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        "expected.json": json.dumps(
            fixture["expected"].model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        "action-result.json": json.dumps(
            fixture["action_result"].model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
    }
    for name, payload in files.items():
        (directory / name).write_bytes(payload)
    return [
        sys.executable,
        "-m",
        "proofflow.cli",
        "receipt",
        "verify",
        "--envelope",
        str(directory / "receipt.json"),
        "--trust-policy",
        str(directory / "trust.json"),
        "--expected-binding",
        str(directory / "expected.json"),
        "--action-certificate-envelope",
        str(directory / "action.json"),
        "--action-certificate-verification",
        str(directory / "action-result.json"),
        "--at",
        "2026-08-30T04:00:00Z",
    ]


def test_receipt_cli_exit_codes_are_0_1_2_3(
    receipt_fixture: dict[str, Any], tmp_path: Path
) -> None:
    accepted_dir = tmp_path / "accepted"
    accepted_dir.mkdir()
    accepted = subprocess.run(
        write_cli_inputs(accepted_dir, receipt_fixture),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(accepted.stdout)["status"] == "ACCEPT"

    optimized_args = [accepted.args[0], "-O", *accepted.args[1:]]
    optimized = subprocess.run(
        optimized_args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert optimized.returncode == 0, optimized.stderr
    assert json.loads(optimized.stdout)["status"] == "ACCEPT"

    rejected_dir = tmp_path / "rejected"
    rejected_dir.mkdir()
    rejected_args = write_cli_inputs(rejected_dir, receipt_fixture)
    (rejected_dir / "action.json").write_bytes(receipt_fixture["action_envelope"] + b" ")
    rejected = subprocess.run(
        rejected_args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 1
    assert json.loads(rejected.stdout)["status"] == "REJECT"

    unknown_dir = tmp_path / "unknown"
    unknown_dir.mkdir()
    threshold_policy = receipt_fixture["policy"].model_copy(
        update={"execution_observer_threshold": 2}
    )
    unknown = subprocess.run(
        write_cli_inputs(unknown_dir, receipt_fixture, trust_policy=threshold_policy),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert unknown.returncode == 3
    assert json.loads(unknown.stdout)["status"] == "UNKNOWN"

    invalid_dir = tmp_path / "invalid"
    invalid_dir.mkdir()
    invalid_args = write_cli_inputs(invalid_dir, receipt_fixture)
    (invalid_dir / "expected.json").write_text('{"tenant_id":"a","tenant_id":"b"}')
    invalid = subprocess.run(
        invalid_args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert invalid.returncode == 2
    assert json.loads(invalid.stderr)["error"]["code"] == "INVALID_INPUT"
