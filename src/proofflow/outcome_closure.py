"""Fail-closed OutcomeClosure v0.1 reference contracts and verifier.

OutcomeClosure is the last, deliberately small, proof-governance primitive in the
public synthetic slice.  It consumes an already accepted ActionCertificate and an
already accepted ExecutionReceipt as *external trusted inputs*, binds those exact
bytes and verification results, and derives a closed outcome verdict from an
observer-signed reconciliation record.  It never performs a provider query or
effect and cannot establish production exactly-once semantics.
"""

from __future__ import annotations

import re
import threading
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Protocol, Self

from pydantic import Field, StrictInt, ValidationInfo, field_validator, model_validator

from proofflow.action_certificate import (
    ACTION_CERTIFICATE_PREDICATE_TYPE,
    EXECUTION_RECEIPT_PREDICATE_TYPE,
    MAX_ENVELOPE_BYTES,
    MAX_PAYLOAD_BYTES,
    ActionCertificatePredicate,
    ActionCertificateStatement,
    ActionCertificateVerificationResult,
    CertificateWireModel,
    DsseEnvelope,
    InTotoSubject,
    OutcomeEvidenceSourceKind,
    OutcomeObserverScope,
    TrustPolicy,
    TrustPurpose,
    VerificationStatus,
    approval_scope_sha256,
    cryptographically_verified_roots,
    decode_canonical_base64,
    parse_json_model,
    parse_utc_rfc3339_z,
    sha256_bytes,
    trust_root_fingerprint,
    trust_root_is_current,
)
from proofflow.canonical import canonical_json
from proofflow.execution_receipt import (
    REQUIRED_EXECUTION_OBSERVER_SCOPES,
    ActionCertificateReference,
    ExecutionReceiptStatement,
    ExecutionReceiptVerificationResult,
    action_certificate_verification_sha256,
)

OUTCOME_CLOSURE_VERSION = "0.1"
OUTCOME_CLOSURE_AUDIENCE = "proofflow-outcome-closure"
OUTCOME_CLOSURE_PREDICATE_TYPE = "https://proofflow.dev/attestations/outcome-closure/v0.1"
OUTCOME_CLOSURE_VERIFICATION_VERSION = "proofflow.outcome-closure-verification/v0.1"
OUTCOME_EXPECTED_BINDING_VERSION = "proofflow.outcome-closure-expected/v0.1"

MAX_EFFECT_ATTEMPTS = 128
MAX_UNRESOLVED_EFFECTS = 128
MAX_OUTCOME_INDEX_CAPACITY = 1_000_000

SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$"


def _parse_wire_timestamp(value: Any, label: str) -> datetime:
    if isinstance(value, str):
        return parse_utc_rfc3339_z(value, label)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must use UTC RFC 3339 with a trailing Z")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must use UTC")
    return value.astimezone(UTC)


def _reject_reference(value: str, label: str) -> str:
    lowered = value.casefold()
    if "://" in lowered or lowered.startswith(("file:", "data:", "urn:")):
        raise ValueError(f"{label} must not be a remote or indirect reference")
    return value


class OutcomeVerdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    UNSAFE_SUCCESS = "UNSAFE_SUCCESS"


class ClaimedOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class EffectAttemptStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class EffectTerminalResult(StrEnum):
    EFFECT_COMMITTED = "EFFECT_COMMITTED"
    EFFECT_REJECTED = "EFFECT_REJECTED"
    EFFECT_NOT_APPLIED = "EFFECT_NOT_APPLIED"


class UnresolvedEffectReason(StrEnum):
    QUERY_UNAVAILABLE = "QUERY_UNAVAILABLE"
    PENDING = "PENDING"
    CONFLICT = "CONFLICT"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"


class OutcomeProducerDeclaration(CertificateWireModel):
    producer_id: str = Field(pattern=IDENTIFIER_PATTERN)
    software_name: str = Field(min_length=1, max_length=128)
    software_version: str = Field(min_length=1, max_length=64)
    observer_principals: tuple[str, ...] = Field(min_length=1, max_length=16)

    @field_validator("software_name", "software_version")
    @classmethod
    def software_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_reference(value, f"outcome producer {info.field_name}")

    @field_validator("observer_principals")
    @classmethod
    def observer_principals_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("outcome observer principals must be unique")
        for value in values:
            if re.fullmatch(IDENTIFIER_PATTERN, value) is None:
                raise ValueError("outcome observer principal is invalid")
        return values


class ExecutionReceiptReference(CertificateWireModel):
    receipt_id: str = Field(pattern=IDENTIFIER_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    verification_result_sha256: str = Field(pattern=SHA256_PATTERN)


class OutcomeEvidenceSource(CertificateWireModel):
    """Operator-bound, local authoritative evidence source declaration."""

    source_kind: OutcomeEvidenceSourceKind
    source_version: Literal["proofflow.outcome-evidence/v0.1"]
    principal_id: str = Field(pattern=IDENTIFIER_PATTERN)
    observed_at: datetime
    valid_until: datetime
    source_event_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("observed_at", "valid_until", mode="before")
    @classmethod
    def timestamps_use_utc_z_wire_profile(cls, value: Any, info: ValidationInfo) -> datetime:
        return _parse_wire_timestamp(value, f"outcome evidence source {info.field_name}")

    @model_validator(mode="after")
    def source_window_is_valid(self) -> Self:
        if self.valid_until < self.observed_at:
            raise ValueError("outcome evidence source valid_until must follow observed_at")
        return self


class OutcomeEvidenceResolver(Protocol):
    """Operator-controlled resolver for exact local evidence bytes."""

    def resolve(
        self,
        digest: str,
        *,
        source: OutcomeEvidenceSource,
        now: datetime,
    ) -> bytes | None: ...


class InMemoryOutcomeEvidenceResolver:
    """Bounded public-synthetic resolver; it never reads paths or uses a network."""

    def __init__(
        self,
        evidence: dict[str, bytes],
        *,
        max_entries: int = 1024,
        max_bytes: int = 256 * 1024,
    ) -> None:
        if max_entries < 1 or max_bytes < 1:
            raise ValueError("outcome evidence limits must be positive")
        if len(evidence) > max_entries:
            raise ValueError("outcome evidence exceeds entry limit")
        if sum(len(value) for value in evidence.values()) > max_bytes:
            raise ValueError("outcome evidence exceeds byte limit")
        self._evidence = dict(evidence)
        self._max_bytes = max_bytes

    def resolve(
        self,
        digest: str,
        *,
        source: OutcomeEvidenceSource,
        now: datetime,
    ) -> bytes | None:
        if source.source_kind != OutcomeEvidenceSourceKind.LOCAL_BYTES:
            return None
        if source.observed_at > now or source.valid_until < now:
            return None
        source_event = self._evidence.get(source.source_event_sha256)
        if source_event is None or sha256_bytes(source_event) != source.source_event_sha256:
            return None
        value = self._evidence.get(digest)
        if value is None or len(value) > self._max_bytes or sha256_bytes(value) != digest:
            return None
        return bytes(value)


class EffectAttemptObservation(CertificateWireModel):
    effect_id: str = Field(pattern=IDENTIFIER_PATTERN)
    attempt_id: str = Field(pattern=IDENTIFIER_PATTERN)
    effect_type: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=512)
    intent_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)
    status: EffectAttemptStatus
    terminal_result: EffectTerminalResult
    provider_operation_id: str | None = Field(default=None, pattern=IDENTIFIER_PATTERN)
    before_state_sha256: str = Field(pattern=SHA256_PATTERN)
    after_state_sha256: str = Field(pattern=SHA256_PATTERN)
    provider_event_sha256: str = Field(pattern=SHA256_PATTERN)
    observer_evidence_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("effect_type", "target")
    @classmethod
    def effect_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_reference(value, f"outcome effect {info.field_name}")

    @model_validator(mode="after")
    def terminal_result_matches_status(self) -> Self:
        if self.status == EffectAttemptStatus.SUCCEEDED:
            if (
                self.terminal_result != EffectTerminalResult.EFFECT_COMMITTED
                or self.provider_operation_id is None
            ):
                raise ValueError(
                    "SUCCEEDED effect must have committed result and provider operation"
                )
        elif self.terminal_result == EffectTerminalResult.EFFECT_COMMITTED:
            raise ValueError("FAILED effect must not have EFFECT_COMMITTED terminal result")
        return self


class UnresolvedEffectObservation(CertificateWireModel):
    effect_id: str = Field(pattern=IDENTIFIER_PATTERN)
    reason: UnresolvedEffectReason
    observer_evidence_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def unresolved_requires_evidence(self) -> Self:
        if self.reason == UnresolvedEffectReason.MISSING_EVIDENCE:
            if self.observer_evidence_sha256 is not None:
                raise ValueError("MISSING_EVIDENCE must not claim observer evidence")
        elif self.observer_evidence_sha256 is None:
            raise ValueError("an unresolved effect reason requires observer evidence")
        return self


class EffectReconciliation(CertificateWireModel):
    effect_type: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=512)
    intent_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)
    expected_effect_count: StrictInt = Field(ge=1, le=16)
    attempts: tuple[EffectAttemptObservation, ...] = Field(max_length=MAX_EFFECT_ATTEMPTS)
    unresolved: tuple[UnresolvedEffectObservation, ...] = Field(max_length=MAX_UNRESOLVED_EFFECTS)

    @field_validator("effect_type", "target")
    @classmethod
    def effect_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_reference(value, f"reconciliation {info.field_name}")

    @model_validator(mode="after")
    def observations_are_unambiguous(self) -> Self:
        attempt_ids = [item.attempt_id for item in self.attempts]
        effect_ids = [item.effect_id for item in self.attempts]
        unresolved_ids = [item.effect_id for item in self.unresolved]
        if len(attempt_ids) != len(set(attempt_ids)):
            raise ValueError("effect attempt IDs must be unique")
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("effect IDs must be unique")
        provider_operation_ids = [
            item.provider_operation_id
            for item in self.attempts
            if item.provider_operation_id is not None
        ]
        if len(provider_operation_ids) != len(set(provider_operation_ids)):
            raise ValueError("provider operation IDs must be unique")
        if len(unresolved_ids) != len(set(unresolved_ids)):
            raise ValueError("unresolved effect IDs must be unique")
        if set(effect_ids) & set(unresolved_ids):
            raise ValueError("resolved and unresolved effect IDs must be disjoint")
        for item in self.attempts:
            if (
                item.effect_type != self.effect_type
                or item.target != self.target
                or item.intent_sha256 != self.intent_sha256
                or item.idempotency_key != self.idempotency_key
            ):
                raise ValueError("effect attempt is not bound to the reconciled intent")
        if len(self.unresolved) > self.expected_effect_count:
            raise ValueError("unresolved effect count cannot exceed expected effect count")
        return self


class OutcomeClosurePredicate(CertificateWireModel):
    version: Literal["0.1"]
    closure_id: str = Field(pattern=IDENTIFIER_PATTERN)
    execution_id: str = Field(pattern=IDENTIFIER_PATTERN)
    task_id: str = Field(pattern=IDENTIFIER_PATTERN)
    attempt_id: str = Field(pattern=IDENTIFIER_PATTERN)
    closure_sequence: StrictInt = Field(ge=1, le=1_000_000)
    previous_payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=IDENTIFIER_PATTERN)
    issued_at: datetime
    certificate_ref: ActionCertificateReference
    receipt_ref: ExecutionReceiptReference
    evidence_source: OutcomeEvidenceSource
    producer: OutcomeProducerDeclaration
    reconciliation: EffectReconciliation
    claimed_outcome: ClaimedOutcome

    @field_validator("issued_at", mode="before")
    @classmethod
    def issued_at_uses_utc_z_wire_profile(cls, value: Any) -> datetime:
        return _parse_wire_timestamp(value, "OutcomeClosure issued_at")


class OutcomeClosureStatement(CertificateWireModel):
    statement_type: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subject: tuple[InTotoSubject, ...] = Field(max_length=64)
    predicateType: Literal["https://proofflow.dev/attestations/outcome-closure/v0.1"]
    predicate: OutcomeClosurePredicate

    @field_validator("subject")
    @classmethod
    def subjects_are_unique(cls, values: tuple[InTotoSubject, ...]) -> tuple[InTotoSubject, ...]:
        if len({item.name for item in values}) != len(values):
            raise ValueError("outcome subject names must be unique")
        return values


class ExpectedOutcomeBinding(CertificateWireModel):
    binding_version: Literal["proofflow.outcome-closure-expected/v0.1"]
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=IDENTIFIER_PATTERN)
    execution_id: str = Field(pattern=IDENTIFIER_PATTERN)
    task_id: str = Field(pattern=IDENTIFIER_PATTERN)
    attempt_id: str = Field(pattern=IDENTIFIER_PATTERN)
    closure_sequence: StrictInt = Field(ge=1, le=1_000_000)
    previous_payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    certificate_ref: ActionCertificateReference
    receipt_ref: ExecutionReceiptReference
    evidence_source: OutcomeEvidenceSource
    human_principal_key_fingerprints: tuple[str, ...] = Field(min_length=1, max_length=16)
    executor_workload_key_fingerprints: tuple[str, ...] = Field(min_length=1, max_length=16)
    effect_type: str = Field(min_length=1, max_length=128)
    effect_target: str = Field(min_length=1, max_length=512)
    effect_intent_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)
    expected_effect_count: StrictInt = Field(ge=1, le=16)

    @field_validator("effect_type", "effect_target")
    @classmethod
    def effect_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_reference(value, f"expected outcome {info.field_name}")

    @field_validator("human_principal_key_fingerprints", "executor_workload_key_fingerprints")
    @classmethod
    def key_fingerprints_are_unique_and_well_formed(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("identity key fingerprints must be unique")
        for value in values:
            if re.fullmatch(SHA256_PATTERN, value) is None:
                raise ValueError("identity key fingerprint is invalid")
        return values


def expected_outcome_binding_for(
    statement: OutcomeClosureStatement,
    *,
    human_principal_key_fingerprints: tuple[str, ...],
    executor_workload_key_fingerprints: tuple[str, ...],
) -> ExpectedOutcomeBinding:
    """Build an operator-side fixture binding, never a producer-side trust input.

    Production callers must construct this object from an independent operator
    record.  Deriving it from a signed OutcomeClosure is only suitable for the
    public synthetic fixture and is deliberately not done by ``verify_outcome_closure``.
    """
    predicate = statement.predicate
    reconciliation = predicate.reconciliation
    return ExpectedOutcomeBinding(
        binding_version="proofflow.outcome-closure-expected/v0.1",
        tenant_id=predicate.tenant_id,
        case_id=predicate.case_id,
        execution_id=predicate.execution_id,
        task_id=predicate.task_id,
        attempt_id=predicate.attempt_id,
        closure_sequence=predicate.closure_sequence,
        previous_payload_sha256=predicate.previous_payload_sha256,
        certificate_ref=predicate.certificate_ref,
        receipt_ref=predicate.receipt_ref,
        evidence_source=predicate.evidence_source,
        human_principal_key_fingerprints=human_principal_key_fingerprints,
        executor_workload_key_fingerprints=executor_workload_key_fingerprints,
        effect_type=reconciliation.effect_type,
        effect_target=reconciliation.target,
        effect_intent_sha256=reconciliation.intent_sha256,
        idempotency_key=reconciliation.idempotency_key,
        expected_effect_count=reconciliation.expected_effect_count,
    )


class OutcomeIndexStatus(StrEnum):
    APPENDED = "APPENDED"
    ALREADY_PRESENT = "ALREADY_PRESENT"
    CLOSURE_ID_CONFLICT = "CLOSURE_ID_CONFLICT"
    ATTEMPT_SEQUENCE_CONFLICT = "ATTEMPT_SEQUENCE_CONFLICT"
    PREVIOUS_DIGEST_CONFLICT = "PREVIOUS_DIGEST_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"


class OutcomeClosureIndex(Protocol):
    def append_once(
        self,
        *,
        tenant_id: str,
        closure_id: str,
        execution_id: str,
        attempt_id: str,
        closure_sequence: int,
        previous_payload_sha256: str | None,
        payload_sha256: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> OutcomeIndexStatus: ...


class InMemoryOutcomeClosureIndex:
    """Bounded process-local append-only index; it never evicts or overwrites bytes."""

    def __init__(self, *, capacity: int = 10_000) -> None:
        if capacity < 1 or capacity > MAX_OUTCOME_INDEX_CAPACITY:
            raise ValueError("outcome index capacity must be between 1 and 1000000")
        self._capacity = capacity
        self._closures: dict[tuple[str, str], str] = {}
        self._executions: dict[tuple[str, str, str, int], tuple[str, str | None]] = {}
        self._latest: dict[tuple[str, str, str], tuple[int, str]] = {}
        self._idempotency: dict[tuple[str, str, int], tuple[str, str]] = {}
        self._lock = threading.Lock()

    def append_once(
        self,
        *,
        tenant_id: str,
        closure_id: str,
        execution_id: str,
        payload_sha256: str,
        idempotency_key: str,
        intent_sha256: str,
        attempt_id: str = "attempt-001",
        closure_sequence: int = 1,
        previous_payload_sha256: str | None = None,
    ) -> OutcomeIndexStatus:
        closure_key = (tenant_id, closure_id)
        execution_key = (tenant_id, execution_id, attempt_id, closure_sequence)
        latest_key = (tenant_id, execution_id, attempt_id)
        idempotency_keyed = (tenant_id, idempotency_key, closure_sequence)
        with self._lock:
            existing_closure = self._closures.get(closure_key)
            existing_execution = self._executions.get(execution_key)
            existing_intent = self._idempotency.get(idempotency_keyed)
            if existing_closure is not None:
                if (
                    existing_closure == payload_sha256
                    and existing_execution is not None
                    and existing_execution[0] == payload_sha256
                ):
                    return OutcomeIndexStatus.ALREADY_PRESENT
                return OutcomeIndexStatus.CLOSURE_ID_CONFLICT
            if existing_execution is not None:
                return OutcomeIndexStatus.ATTEMPT_SEQUENCE_CONFLICT
            if existing_intent is not None:
                if existing_intent == (intent_sha256, payload_sha256):
                    return OutcomeIndexStatus.ALREADY_PRESENT
                return OutcomeIndexStatus.IDEMPOTENCY_CONFLICT
            latest = self._latest.get(latest_key)
            if closure_sequence == 1:
                if previous_payload_sha256 is not None:
                    return OutcomeIndexStatus.PREVIOUS_DIGEST_CONFLICT
            elif latest is None or latest[0] != closure_sequence - 1:
                return OutcomeIndexStatus.ATTEMPT_SEQUENCE_CONFLICT
            elif previous_payload_sha256 != latest[1]:
                return OutcomeIndexStatus.PREVIOUS_DIGEST_CONFLICT
            if len(self._closures) >= self._capacity:
                return OutcomeIndexStatus.UNAVAILABLE
            self._closures[closure_key] = payload_sha256
            self._executions[execution_key] = (payload_sha256, previous_payload_sha256)
            self._latest[latest_key] = (closure_sequence, payload_sha256)
            self._idempotency[idempotency_keyed] = (intent_sha256, payload_sha256)
            return OutcomeIndexStatus.APPENDED


class OutcomeClosureVerificationReason(StrEnum):
    PASS_VERIFIED = "PASS_VERIFIED"
    FAIL_VERIFIED = "FAIL_VERIFIED"
    PASS_ALREADY_PRESENT = "PASS_ALREADY_PRESENT"
    FAIL_ALREADY_PRESENT = "FAIL_ALREADY_PRESENT"
    ENVELOPE_INVALID = "ENVELOPE_INVALID"
    ENVELOPE_TOO_LARGE = "ENVELOPE_TOO_LARGE"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    TRUST_POLICY_MISMATCH = "TRUST_POLICY_MISMATCH"
    EXPECTED_BINDING_MISMATCH = "EXPECTED_BINDING_MISMATCH"
    CLOSURE_TIME_INVALID = "CLOSURE_TIME_INVALID"
    ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN = "ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN"
    ACTION_CERTIFICATE_HANDOFF_UNTRUSTED = "ACTION_CERTIFICATE_HANDOFF_UNTRUSTED"
    EXECUTION_RECEIPT_ACCEPTANCE_UNKNOWN = "EXECUTION_RECEIPT_ACCEPTANCE_UNKNOWN"
    EXECUTION_RECEIPT_HANDOFF_UNTRUSTED = "EXECUTION_RECEIPT_HANDOFF_UNTRUSTED"
    ACTION_CERTIFICATE_UNSAFE = "ACTION_CERTIFICATE_UNSAFE"
    EXECUTION_RECEIPT_UNSAFE = "EXECUTION_RECEIPT_UNSAFE"
    AUTHORIZATION_BINDING_MISMATCH = "AUTHORIZATION_BINDING_MISMATCH"
    RECEIPT_BINDING_MISMATCH = "RECEIPT_BINDING_MISMATCH"
    EFFECT_BINDING_UNKNOWN = "EFFECT_BINDING_UNKNOWN"
    EFFECT_BINDING_MISMATCH = "EFFECT_BINDING_MISMATCH"
    EFFECT_COUNT_MISMATCH = "EFFECT_COUNT_MISMATCH"
    EFFECT_RECONCILIATION_UNRESOLVED = "EFFECT_RECONCILIATION_UNRESOLVED"
    UNSAFE_UNRESOLVED_EFFECT = "UNSAFE_UNRESOLVED_EFFECT"
    DUPLICATE_EFFECT_SUCCESS = "DUPLICATE_EFFECT_SUCCESS"
    DUPLICATE_PROVIDER_OPERATION_ID = "DUPLICATE_PROVIDER_OPERATION_ID"
    OUTCOME_OBSERVER_THRESHOLD_NOT_MET = "OUTCOME_OBSERVER_THRESHOLD_NOT_MET"
    ROOT_TIME_OR_REVOCATION_INVALID = "ROOT_TIME_OR_REVOCATION_INVALID"
    PRODUCER_SIGNER_MISMATCH = "PRODUCER_SIGNER_MISMATCH"
    SELF_OBSERVATION = "SELF_OBSERVATION"
    CLOSURE_ID_CONFLICT = "CLOSURE_ID_CONFLICT"
    ATTEMPT_SEQUENCE_CONFLICT = "ATTEMPT_SEQUENCE_CONFLICT"
    PREVIOUS_DIGEST_CONFLICT = "PREVIOUS_DIGEST_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    OUTCOME_INDEX_UNAVAILABLE = "OUTCOME_INDEX_UNAVAILABLE"
    EVIDENCE_SOURCE_INVALID = "EVIDENCE_SOURCE_INVALID"
    EVIDENCE_BYTES_UNAVAILABLE = "EVIDENCE_BYTES_UNAVAILABLE"
    EVIDENCE_DIGEST_MISMATCH = "EVIDENCE_DIGEST_MISMATCH"
    EFFECT_COVERAGE_INCOMPLETE = "EFFECT_COVERAGE_INCOMPLETE"
    EFFECT_TERMINAL_INVALID = "EFFECT_TERMINAL_INVALID"
    OUTCOME_WINDOW_UNSAFE = "OUTCOME_WINDOW_UNSAFE"
    OUTCOME_OBSERVER_SOD = "OUTCOME_OBSERVER_SOD"


class OutcomeClosureVerificationResult(CertificateWireModel):
    verification_version: Literal["proofflow.outcome-closure-verification/v0.1"]
    status: OutcomeVerdict
    reason_codes: tuple[OutcomeClosureVerificationReason, ...] = Field(min_length=1, max_length=16)
    closure_id: str | None = Field(default=None, pattern=IDENTIFIER_PATTERN)
    payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    verified_outcome_observer_roots: tuple[str, ...] = Field(default=(), max_length=16)
    recorded: bool
    attempt_id: str | None = Field(default=None, pattern=IDENTIFIER_PATTERN)
    closure_sequence: StrictInt | None = Field(default=None, ge=1, le=1_000_000)
    previous_payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    expected_effect_count: StrictInt | None = Field(default=None, ge=1, le=16)
    observed_success_count: StrictInt | None = Field(default=None, ge=0, le=MAX_EFFECT_ATTEMPTS)
    unresolved_effect_count: StrictInt | None = Field(default=None, ge=0, le=MAX_UNRESOLVED_EFFECTS)

    @model_validator(mode="after")
    def result_semantics_are_closed(self) -> Self:
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("outcome verification reason codes must be unique")
        if len(set(self.verified_outcome_observer_roots)) != len(
            self.verified_outcome_observer_roots
        ):
            raise ValueError("verified outcome observer roots must be unique")
        reason_set = frozenset(self.reason_codes)
        if self.status == OutcomeVerdict.PASS:
            if (
                not self.recorded
                or len(self.reason_codes) != 1
                or not reason_set <= PASS_OUTCOME_REASONS
                or self.reason_codes[0]
                not in (
                    OutcomeClosureVerificationReason.PASS_VERIFIED,
                    OutcomeClosureVerificationReason.PASS_ALREADY_PRESENT,
                )
                or self.closure_id is None
                or self.payload_sha256 is None
                or not self.verified_outcome_observer_roots
                or self.expected_effect_count is None
                or self.observed_success_count is None
                or self.unresolved_effect_count is None
                or self.attempt_id is None
                or self.closure_sequence is None
            ):
                raise ValueError("PASS requires a recorded, observer-bound closure")
        elif self.status == OutcomeVerdict.FAIL:
            if (
                not self.recorded
                or len(self.reason_codes) != 1
                or not reason_set <= FAIL_OUTCOME_REASONS
                or self.reason_codes[0]
                not in (
                    OutcomeClosureVerificationReason.FAIL_VERIFIED,
                    OutcomeClosureVerificationReason.FAIL_ALREADY_PRESENT,
                )
                or self.closure_id is None
                or self.payload_sha256 is None
                or not self.verified_outcome_observer_roots
                or self.expected_effect_count is None
                or self.observed_success_count is None
                or self.unresolved_effect_count is None
                or self.attempt_id is None
                or self.closure_sequence is None
            ):
                raise ValueError("a recorded FAIL requires an observer-bound closure")
        elif self.status == OutcomeVerdict.UNKNOWN:
            if self.recorded or not reason_set <= UNKNOWN_OUTCOME_REASONS:
                raise ValueError("UNKNOWN requires only unavailable or unverified reasons")
        elif self.recorded or not reason_set <= UNSAFE_OUTCOME_REASONS:
            raise ValueError("UNSAFE_SUCCESS requires only unsafe-success reasons")
        return self


PASS_OUTCOME_REASONS = frozenset(
    {
        OutcomeClosureVerificationReason.PASS_VERIFIED,
        OutcomeClosureVerificationReason.PASS_ALREADY_PRESENT,
    }
)
FAIL_OUTCOME_REASONS = frozenset(
    {
        OutcomeClosureVerificationReason.FAIL_VERIFIED,
        OutcomeClosureVerificationReason.FAIL_ALREADY_PRESENT,
    }
)
UNSAFE_OUTCOME_REASONS = frozenset(
    {
        OutcomeClosureVerificationReason.ACTION_CERTIFICATE_UNSAFE,
        OutcomeClosureVerificationReason.EXECUTION_RECEIPT_UNSAFE,
        OutcomeClosureVerificationReason.AUTHORIZATION_BINDING_MISMATCH,
        OutcomeClosureVerificationReason.RECEIPT_BINDING_MISMATCH,
        OutcomeClosureVerificationReason.EFFECT_BINDING_MISMATCH,
        OutcomeClosureVerificationReason.DUPLICATE_EFFECT_SUCCESS,
        OutcomeClosureVerificationReason.DUPLICATE_PROVIDER_OPERATION_ID,
        OutcomeClosureVerificationReason.EFFECT_COUNT_MISMATCH,
        OutcomeClosureVerificationReason.UNSAFE_UNRESOLVED_EFFECT,
        OutcomeClosureVerificationReason.OUTCOME_WINDOW_UNSAFE,
        OutcomeClosureVerificationReason.OUTCOME_OBSERVER_SOD,
    }
)
UNKNOWN_OUTCOME_REASONS = (
    frozenset(OutcomeClosureVerificationReason)
    - UNSAFE_OUTCOME_REASONS
    - PASS_OUTCOME_REASONS
    - FAIL_OUTCOME_REASONS
)


def _result(
    status: OutcomeVerdict,
    reasons: tuple[OutcomeClosureVerificationReason, ...],
    *,
    envelope_sha256: str,
    closure_id: str | None = None,
    payload_sha256: str | None = None,
    observer_roots: tuple[str, ...] = (),
    recorded: bool = False,
    attempt_id: str | None = None,
    closure_sequence: int | None = None,
    previous_payload_sha256: str | None = None,
    reconciliation: EffectReconciliation | None = None,
) -> OutcomeClosureVerificationResult:
    return OutcomeClosureVerificationResult(
        verification_version="proofflow.outcome-closure-verification/v0.1",
        status=status,
        reason_codes=tuple(dict.fromkeys(reasons)),
        closure_id=closure_id,
        payload_sha256=payload_sha256,
        envelope_sha256=envelope_sha256,
        verified_outcome_observer_roots=tuple(sorted(observer_roots)),
        recorded=recorded,
        attempt_id=attempt_id,
        closure_sequence=closure_sequence,
        previous_payload_sha256=previous_payload_sha256,
        expected_effect_count=(
            reconciliation.expected_effect_count if reconciliation is not None else None
        ),
        observed_success_count=(
            sum(item.status == EffectAttemptStatus.SUCCEEDED for item in reconciliation.attempts)
            if reconciliation is not None
            else None
        ),
        unresolved_effect_count=(
            len(reconciliation.unresolved) if reconciliation is not None else None
        ),
    )


def execution_receipt_verification_sha256(
    result: ExecutionReceiptVerificationResult,
) -> str:
    """Hash the normalized strict receipt verification result used as external input."""

    return sha256_bytes(canonical_json(result.model_dump(mode="json")))


def _unknown(
    predicate: OutcomeClosurePredicate | None,
    reason: OutcomeClosureVerificationReason,
    *,
    envelope_sha256: str,
    closure_id: str | None = None,
    payload_sha256: str | None = None,
    observer_roots: tuple[str, ...] = (),
) -> OutcomeClosureVerificationResult:
    return _result(
        OutcomeVerdict.UNKNOWN,
        (reason,),
        envelope_sha256=envelope_sha256,
        closure_id=closure_id,
        payload_sha256=payload_sha256,
        observer_roots=observer_roots,
        reconciliation=predicate.reconciliation if predicate is not None else None,
        attempt_id=predicate.attempt_id if predicate is not None else None,
        closure_sequence=predicate.closure_sequence if predicate is not None else None,
        previous_payload_sha256=(
            predicate.previous_payload_sha256 if predicate is not None else None
        ),
    )


def _unsafe(
    predicate: OutcomeClosurePredicate,
    reason: OutcomeClosureVerificationReason,
    *,
    envelope_sha256: str,
    closure_id: str,
    payload_sha256: str,
    observer_roots: tuple[str, ...] = (),
) -> OutcomeClosureVerificationResult:
    return _result(
        OutcomeVerdict.UNSAFE_SUCCESS,
        (reason,),
        envelope_sha256=envelope_sha256,
        closure_id=closure_id,
        payload_sha256=payload_sha256,
        observer_roots=observer_roots,
        reconciliation=predicate.reconciliation,
        attempt_id=predicate.attempt_id,
        closure_sequence=predicate.closure_sequence,
        previous_payload_sha256=predicate.previous_payload_sha256,
    )


def _parse_external_action_certificate(
    envelope_bytes: bytes,
    result: ActionCertificateVerificationResult,
    expected: ActionCertificateReference,
    policy: TrustPolicy,
    verification_time: datetime,
) -> tuple[ActionCertificatePredicate | None, OutcomeClosureVerificationReason | None]:
    if result.status != VerificationStatus.ACCEPT or not result.reserved:
        return None, OutcomeClosureVerificationReason.ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN
    try:
        envelope = parse_json_model(
            envelope_bytes, DsseEnvelope, "external ActionCertificate envelope"
        )
        payload = decode_canonical_base64(
            envelope.payload, "external ActionCertificate payload", allow_urlsafe=True
        )
        statement = parse_json_model(
            payload, ActionCertificateStatement, "external ActionCertificate payload"
        )
    except ValueError:
        return None, OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED
    if (
        sha256_bytes(envelope_bytes) != expected.envelope_sha256
        or sha256_bytes(payload) != expected.payload_sha256
        or statement.predicate.certificate_id != expected.certificate_id
        or result.certificate_id != expected.certificate_id
        or result.payload_sha256 != expected.payload_sha256
        or action_certificate_verification_sha256(result) != expected.verification_result_sha256
        or approval_scope_sha256(statement) != expected.intent_sha256
    ):
        return None, OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED
    verified_roots = cryptographically_verified_roots(envelope, payload, policy.roots)
    verified_by_id = {root.root_id: root for root in verified_roots}
    issuer_ids = tuple(result.verified_action_issuer_roots)
    approval_ids = tuple(result.verified_human_approval_roots)
    if (
        not issuer_ids
        or (statement.predicate.approval.required and not approval_ids)
        or (not statement.predicate.approval.required and approval_ids)
        or len(set(issuer_ids)) != len(issuer_ids)
        or len(set(approval_ids)) != len(approval_ids)
    ):
        return None, OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED
    skew = timedelta(seconds=policy.max_clock_skew_seconds)
    issuer_roots = [verified_by_id.get(root_id) for root_id in issuer_ids]
    approval_roots = [verified_by_id.get(root_id) for root_id in approval_ids]
    if any(root is None for root in (*issuer_roots, *approval_roots)):
        return None, OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED
    if any(
        root is None
        or root.purpose != TrustPurpose.ACTION_ISSUER
        or root.tenant_id != statement.predicate.tenant_id
        or statement.predicate.audience not in root.audiences
        or ACTION_CERTIFICATE_PREDICATE_TYPE not in root.predicate_types
        or statement.predicate.audience not in policy.allowed_audiences
        or ACTION_CERTIFICATE_PREDICATE_TYPE not in policy.allowed_predicate_types
        or root.principal_id not in policy.allowed_action_issuer_principals
        or not trust_root_is_current(root, expected.verification_at, skew)
        or not trust_root_is_current(root, verification_time, skew)
        for root in issuer_roots
    ) or any(
        root is None
        or root.purpose != TrustPurpose.HUMAN_APPROVAL
        or root.tenant_id != statement.predicate.tenant_id
        or statement.predicate.audience not in root.audiences
        or ACTION_CERTIFICATE_PREDICATE_TYPE not in root.predicate_types
        or statement.predicate.audience not in policy.allowed_audiences
        or ACTION_CERTIFICATE_PREDICATE_TYPE not in policy.allowed_predicate_types
        or root.principal_id not in policy.allowed_approval_principals
        or root.principal_id not in statement.predicate.approval.approver_principals
        or not trust_root_is_current(root, expected.verification_at, skew)
        or not trust_root_is_current(root, verification_time, skew)
        for root in approval_roots
    ):
        return None, OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED
    issuer_principals = {root.principal_id for root in issuer_roots if root is not None}
    issuer_fingerprints = {
        trust_root_fingerprint(root) for root in issuer_roots if root is not None
    }
    approval_principals = {root.principal_id for root in approval_roots if root is not None}
    approval_fingerprints = {
        trust_root_fingerprint(root) for root in approval_roots if root is not None
    }
    if (
        statement.predicate.human_principal.principal_id not in policy.allowed_human_principals
        or statement.predicate.workload_principal.principal_id
        not in policy.allowed_workload_principals
        or statement.predicate.human_principal.principal_id
        == statement.predicate.workload_principal.principal_id
        or len(issuer_principals) < policy.action_issuer_threshold
        or len(issuer_fingerprints) < policy.action_issuer_threshold
        or (
            statement.predicate.approval.required
            and (
                len(approval_principals) < policy.human_approval_threshold
                or len(approval_fingerprints) < policy.human_approval_threshold
            )
        )
        or issuer_principals & approval_principals
        or issuer_fingerprints & approval_fingerprints
    ):
        return None, OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED
    return statement.predicate, None


def _parse_external_receipt(
    envelope_bytes: bytes,
    result: ExecutionReceiptVerificationResult,
    expected: ExecutionReceiptReference,
    policy: TrustPolicy,
    verification_time: datetime,
) -> tuple[
    ExecutionReceiptStatement | None,
    OutcomeClosureVerificationReason | None,
]:
    if result.status != VerificationStatus.ACCEPT or not result.recorded:
        return None, OutcomeClosureVerificationReason.EXECUTION_RECEIPT_ACCEPTANCE_UNKNOWN
    try:
        envelope = parse_json_model(
            envelope_bytes, DsseEnvelope, "external ExecutionReceipt envelope"
        )
        payload = decode_canonical_base64(
            envelope.payload, "external ExecutionReceipt payload", allow_urlsafe=True
        )
        statement = parse_json_model(
            payload, ExecutionReceiptStatement, "external ExecutionReceipt payload"
        )
    except ValueError:
        return None, OutcomeClosureVerificationReason.EXECUTION_RECEIPT_HANDOFF_UNTRUSTED
    if (
        sha256_bytes(envelope_bytes) != expected.envelope_sha256
        or sha256_bytes(payload) != expected.payload_sha256
        or statement.predicate.receipt_id != expected.receipt_id
        or result.receipt_id != expected.receipt_id
        or result.payload_sha256 != expected.payload_sha256
        or result.envelope_sha256 != expected.envelope_sha256
        or execution_receipt_verification_sha256(result) != expected.verification_result_sha256
    ):
        return None, OutcomeClosureVerificationReason.EXECUTION_RECEIPT_HANDOFF_UNTRUSTED
    verified_roots = cryptographically_verified_roots(envelope, payload, policy.roots)
    root_ids = tuple(result.verified_execution_observer_roots)
    if not root_ids or len(set(root_ids)) != len(root_ids):
        return None, OutcomeClosureVerificationReason.EXECUTION_RECEIPT_HANDOFF_UNTRUSTED
    verified_by_id = {root.root_id: root for root in verified_roots}
    receipt_roots = [verified_by_id.get(root_id) for root_id in root_ids]
    skew = timedelta(seconds=policy.max_clock_skew_seconds)
    if any(
        root is None
        or root.purpose != TrustPurpose.EXECUTION_OBSERVER
        or root.tenant_id != statement.predicate.tenant_id
        or "proofflow-execution-receipt" not in root.audiences
        or EXECUTION_RECEIPT_PREDICATE_TYPE not in root.predicate_types
        or "proofflow-execution-receipt" not in policy.allowed_audiences
        or EXECUTION_RECEIPT_PREDICATE_TYPE not in policy.allowed_predicate_types
        or root.principal_id not in policy.allowed_execution_observer_principals
        or frozenset(root.execution_observer_scopes) != REQUIRED_EXECUTION_OBSERVER_SCOPES
        or not trust_root_is_current(root, statement.predicate.issued_at, skew)
        or not trust_root_is_current(root, verification_time, skew)
        for root in receipt_roots
    ):
        return None, OutcomeClosureVerificationReason.EXECUTION_RECEIPT_HANDOFF_UNTRUSTED
    receipt_principals = {root.principal_id for root in receipt_roots if root is not None}
    receipt_fingerprints = {
        trust_root_fingerprint(root) for root in receipt_roots if root is not None
    }
    if (
        len(receipt_principals) < policy.execution_observer_threshold
        or len(receipt_fingerprints) < policy.execution_observer_threshold
    ):
        return None, OutcomeClosureVerificationReason.EXECUTION_RECEIPT_HANDOFF_UNTRUSTED
    return statement, None


def _qualifying_outcome_observers(
    envelope: DsseEnvelope,
    payload: bytes,
    statement: OutcomeClosureStatement,
    policy: TrustPolicy,
    action: ActionCertificatePredicate | None,
    receipt: ExecutionReceiptStatement | None,
    action_result: ActionCertificateVerificationResult,
    receipt_result: ExecutionReceiptVerificationResult,
    expected: ExpectedOutcomeBinding,
    now: datetime,
) -> tuple[tuple[str, ...], OutcomeClosureVerificationReason | None]:
    roots = cryptographically_verified_roots(envelope, payload, policy.roots)
    authority_principals: set[str] = set()
    authority_fingerprints: set[str] = set()
    if action is not None:
        authority_principals.update(
            (action.human_principal.principal_id, action.workload_principal.principal_id)
        )
    if receipt is not None:
        authority_principals.update(receipt.predicate.producer.observer_principals)
    authority_principals.add(statement.predicate.evidence_source.principal_id)
    result_root_ids = (
        set(action_result.verified_action_issuer_roots)
        | set(action_result.verified_human_approval_roots)
        | set(receipt_result.verified_execution_observer_roots)
    )
    policy_roots_by_id = {root.root_id: root for root in policy.roots}
    for root_id in result_root_ids:
        root = policy_roots_by_id.get(root_id)
        if root is not None:
            authority_principals.add(root.principal_id)
            authority_fingerprints.add(trust_root_fingerprint(root))
    authority_fingerprints.update(expected.human_principal_key_fingerprints)
    authority_fingerprints.update(expected.executor_workload_key_fingerprints)
    declared = set(statement.predicate.producer.observer_principals)
    qualified: dict[str, str] = {}
    qualified_principals: set[str] = set()
    qualified_fingerprints: set[str] = set()
    stale = False
    self_observed = False
    for root in roots:
        if (
            root.purpose != TrustPurpose.OUTCOME_OBSERVER
            or root.tenant_id != statement.predicate.tenant_id
            or OUTCOME_CLOSURE_AUDIENCE not in root.audiences
            or OUTCOME_CLOSURE_PREDICATE_TYPE not in root.predicate_types
            or root.principal_id not in policy.allowed_outcome_observer_principals
            or frozenset(root.outcome_observer_scopes) != frozenset(OutcomeObserverScope)
            or statement.predicate.evidence_source.source_kind
            not in root.outcome_evidence_source_kinds
            or statement.predicate.evidence_source.principal_id
            not in root.outcome_evidence_source_principals
        ):
            continue
        if root.principal_id not in declared:
            return (), OutcomeClosureVerificationReason.PRODUCER_SIGNER_MISMATCH
        if (
            root.principal_id in authority_principals
            or trust_root_fingerprint(root) in authority_fingerprints
        ):
            self_observed = True
            continue
        if not trust_root_is_current(
            root, statement.predicate.issued_at, timedelta(seconds=policy.max_clock_skew_seconds)
        ) or not trust_root_is_current(root, now, timedelta(seconds=policy.max_clock_skew_seconds)):
            stale = True
            continue
        fingerprint = trust_root_fingerprint(root)
        if (
            root.principal_id not in qualified_principals
            and fingerprint not in qualified_fingerprints
        ):
            qualified[root.root_id] = fingerprint
            qualified_principals.add(root.principal_id)
            qualified_fingerprints.add(fingerprint)
    if self_observed:
        return (), OutcomeClosureVerificationReason.SELF_OBSERVATION
    if stale:
        return tuple(
            sorted(qualified)
        ), OutcomeClosureVerificationReason.ROOT_TIME_OR_REVOCATION_INVALID
    if qualified_principals != declared:
        return tuple(sorted(qualified)), OutcomeClosureVerificationReason.PRODUCER_SIGNER_MISMATCH
    if len(qualified) < policy.outcome_observer_threshold:
        return tuple(
            sorted(qualified)
        ), OutcomeClosureVerificationReason.OUTCOME_OBSERVER_THRESHOLD_NOT_MET
    return tuple(sorted(qualified)), None


def _policy_allows_outcome(policy: TrustPolicy, expected: ExpectedOutcomeBinding) -> bool:
    return (
        expected.tenant_id in policy.allowed_tenants
        and OUTCOME_CLOSURE_AUDIENCE in policy.allowed_audiences
        and OUTCOME_CLOSURE_PREDICATE_TYPE in policy.allowed_predicate_types
        and bool(policy.allowed_outcome_observer_principals)
        and expected.evidence_source.source_kind in policy.allowed_outcome_evidence_source_kinds
        and expected.evidence_source.principal_id
        in policy.allowed_outcome_evidence_source_principals
    )


def _resolve_outcome_evidence(
    predicate: OutcomeClosurePredicate,
    *,
    resolver: OutcomeEvidenceResolver | None,
    now: datetime,
) -> OutcomeClosureVerificationReason | None:
    source = predicate.evidence_source
    if source.source_kind != OutcomeEvidenceSourceKind.LOCAL_BYTES:
        return OutcomeClosureVerificationReason.EVIDENCE_SOURCE_INVALID
    if source.observed_at > now or source.valid_until < now:
        return OutcomeClosureVerificationReason.EVIDENCE_SOURCE_INVALID
    if resolver is None:
        return OutcomeClosureVerificationReason.EVIDENCE_BYTES_UNAVAILABLE
    digests = [source.source_event_sha256]
    for item in predicate.reconciliation.attempts:
        digests.extend(
            (
                item.before_state_sha256,
                item.after_state_sha256,
                item.provider_event_sha256,
                item.observer_evidence_sha256,
            )
        )
    digests.extend(
        item.observer_evidence_sha256
        for item in predicate.reconciliation.unresolved
        if item.observer_evidence_sha256 is not None
    )
    for digest in digests:
        try:
            raw = resolver.resolve(digest, source=source, now=now)
        except Exception:
            raw = None
        if raw is None:
            return OutcomeClosureVerificationReason.EVIDENCE_BYTES_UNAVAILABLE
        if sha256_bytes(raw) != digest:
            return OutcomeClosureVerificationReason.EVIDENCE_DIGEST_MISMATCH
    return None


def verify_outcome_closure(
    envelope_bytes: bytes,
    *,
    trust_policy: TrustPolicy,
    expected_binding: ExpectedOutcomeBinding | None = None,
    action_certificate_envelope_bytes: bytes,
    action_certificate_verification: ActionCertificateVerificationResult | None = None,
    execution_receipt_envelope_bytes: bytes,
    execution_receipt_verification: ExecutionReceiptVerificationResult | None = None,
    outcome_index: OutcomeClosureIndex,
    now: datetime,
    evidence_resolver: OutcomeEvidenceResolver | None = None,
    operator_expected_binding: ExpectedOutcomeBinding | None = None,
    operator_action_certificate_verification: ActionCertificateVerificationResult | None = None,
    operator_execution_receipt_verification: ExecutionReceiptVerificationResult | None = None,
) -> OutcomeClosureVerificationResult:
    """Derive an outcome from an operator-trusted handoff.

    ``action_certificate_verification``, ``execution_receipt_verification``,
    ``expected_binding``, and the exact AC/Receipt envelope bytes are unsigned or
    externally supplied operator inputs.  They must never be accepted from the
    Outcome producer.  If a caller permits the producer to rewrite any of these
    handoff values, the resulting verdict is outside this verifier's safety claim.
    """

    envelope_sha256 = sha256_bytes(envelope_bytes)
    if operator_expected_binding is not None:
        if expected_binding is not None and expected_binding != operator_expected_binding:
            return _result(
                OutcomeVerdict.UNKNOWN,
                (OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED,),
                envelope_sha256=envelope_sha256,
            )
        expected_binding = operator_expected_binding
    if operator_action_certificate_verification is not None:
        if (
            action_certificate_verification is not None
            and action_certificate_verification != operator_action_certificate_verification
        ):
            return _result(
                OutcomeVerdict.UNKNOWN,
                (OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED,),
                envelope_sha256=envelope_sha256,
            )
        action_certificate_verification = operator_action_certificate_verification
    if operator_execution_receipt_verification is not None:
        if (
            execution_receipt_verification is not None
            and execution_receipt_verification != operator_execution_receipt_verification
        ):
            return _result(
                OutcomeVerdict.UNKNOWN,
                (OutcomeClosureVerificationReason.EXECUTION_RECEIPT_HANDOFF_UNTRUSTED,),
                envelope_sha256=envelope_sha256,
            )
        execution_receipt_verification = operator_execution_receipt_verification
    if (
        expected_binding is None
        or action_certificate_verification is None
        or execution_receipt_verification is None
    ):
        return _result(
            OutcomeVerdict.UNKNOWN,
            (OutcomeClosureVerificationReason.ACTION_CERTIFICATE_HANDOFF_UNTRUSTED,),
            envelope_sha256=envelope_sha256,
        )
    try:
        verification_time = _parse_wire_timestamp(now, "verification time")
    except ValueError:
        return _result(
            OutcomeVerdict.UNKNOWN,
            (OutcomeClosureVerificationReason.ENVELOPE_INVALID,),
            envelope_sha256=envelope_sha256,
        )
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        return _result(
            OutcomeVerdict.UNKNOWN,
            (OutcomeClosureVerificationReason.ENVELOPE_TOO_LARGE,),
            envelope_sha256=envelope_sha256,
        )
    try:
        envelope = parse_json_model(envelope_bytes, DsseEnvelope, "OutcomeClosure DSSE envelope")
        payload = decode_canonical_base64(
            envelope.payload, "OutcomeClosure payload", allow_urlsafe=True
        )
    except ValueError:
        return _result(
            OutcomeVerdict.UNKNOWN,
            (OutcomeClosureVerificationReason.ENVELOPE_INVALID,),
            envelope_sha256=envelope_sha256,
        )
    if len(payload) > MAX_PAYLOAD_BYTES:
        return _result(
            OutcomeVerdict.UNKNOWN,
            (OutcomeClosureVerificationReason.PAYLOAD_TOO_LARGE,),
            envelope_sha256=envelope_sha256,
        )
    payload_sha256 = sha256_bytes(payload)
    # The outcome signature is checked before parsing any external ACCEPT result.
    if not cryptographically_verified_roots(envelope, payload, trust_policy.roots):
        return _result(
            OutcomeVerdict.UNKNOWN,
            (OutcomeClosureVerificationReason.SIGNATURE_INVALID,),
            envelope_sha256=envelope_sha256,
            payload_sha256=payload_sha256,
        )
    try:
        statement = parse_json_model(
            payload, OutcomeClosureStatement, "signed OutcomeClosure payload"
        )
    except ValueError:
        return _result(
            OutcomeVerdict.UNKNOWN,
            (OutcomeClosureVerificationReason.PAYLOAD_INVALID,),
            envelope_sha256=envelope_sha256,
            payload_sha256=payload_sha256,
        )
    predicate = statement.predicate
    observer_roots, observer_reason = _qualifying_outcome_observers(
        envelope,
        payload,
        statement,
        trust_policy,
        None,
        None,
        action_certificate_verification,
        execution_receipt_verification,
        expected_binding,
        verification_time,
    )
    if observer_reason is not None:
        return _unknown(
            predicate,
            observer_reason,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    source_reason = _resolve_outcome_evidence(
        predicate, resolver=evidence_resolver, now=verification_time
    )
    if source_reason is not None:
        return _unknown(
            predicate,
            source_reason,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    if (
        expected_outcome_binding_for(
            statement,
            human_principal_key_fingerprints=expected_binding.human_principal_key_fingerprints,
            executor_workload_key_fingerprints=expected_binding.executor_workload_key_fingerprints,
        )
        != expected_binding
    ):
        if any(
            item.status == EffectAttemptStatus.SUCCEEDED
            for item in predicate.reconciliation.attempts
        ):
            return _unsafe(
                predicate,
                OutcomeClosureVerificationReason.EFFECT_BINDING_MISMATCH,
                envelope_sha256=envelope_sha256,
                closure_id=predicate.closure_id,
                payload_sha256=payload_sha256,
                observer_roots=observer_roots,
            )
        return _unknown(
            predicate,
            OutcomeClosureVerificationReason.EXPECTED_BINDING_MISMATCH,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    action, action_reason = _parse_external_action_certificate(
        action_certificate_envelope_bytes,
        action_certificate_verification,
        predicate.certificate_ref,
        trust_policy,
        verification_time,
    )
    if action_reason is not None:
        if (
            action_reason == OutcomeClosureVerificationReason.ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN
            and any(
                item.status == EffectAttemptStatus.SUCCEEDED
                for item in predicate.reconciliation.attempts
            )
        ):
            return _unsafe(
                predicate,
                OutcomeClosureVerificationReason.ACTION_CERTIFICATE_UNSAFE,
                envelope_sha256=envelope_sha256,
                closure_id=predicate.closure_id,
                payload_sha256=payload_sha256,
                observer_roots=observer_roots,
            )
        return _unknown(
            predicate,
            action_reason,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    receipt, receipt_reason = _parse_external_receipt(
        execution_receipt_envelope_bytes,
        execution_receipt_verification,
        predicate.receipt_ref,
        trust_policy,
        verification_time,
    )
    if receipt_reason is not None:
        if (
            receipt_reason == OutcomeClosureVerificationReason.EXECUTION_RECEIPT_ACCEPTANCE_UNKNOWN
            and any(
                item.status == EffectAttemptStatus.SUCCEEDED
                for item in predicate.reconciliation.attempts
            )
        ):
            return _unsafe(
                predicate,
                OutcomeClosureVerificationReason.EXECUTION_RECEIPT_UNSAFE,
                envelope_sha256=envelope_sha256,
                closure_id=predicate.closure_id,
                payload_sha256=payload_sha256,
                observer_roots=observer_roots,
            )
        return _unknown(
            predicate,
            receipt_reason,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    if action is None or receipt is None:
        return _unknown(
            predicate,
            OutcomeClosureVerificationReason.EXECUTION_RECEIPT_ACCEPTANCE_UNKNOWN,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    receipt_predicate = receipt.predicate
    # Re-run observer SoD after accepted prior roots are known.
    observer_roots, observer_reason = _qualifying_outcome_observers(
        envelope,
        payload,
        statement,
        trust_policy,
        action,
        receipt,
        action_certificate_verification,
        execution_receipt_verification,
        expected_binding,
        verification_time,
    )
    if observer_reason is not None:
        return _unknown(
            predicate,
            observer_reason,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    binding_mismatch = (
        action.tenant_id != predicate.tenant_id
        or action.subject.subject_id != predicate.case_id
        or action.context.request_id != predicate.execution_id
        or predicate.attempt_id != receipt_predicate.attempt.attempt_id
        or action.effect.effect_type != predicate.reconciliation.effect_type
        or action.effect.target != predicate.reconciliation.target
        or predicate.certificate_ref.intent_sha256 != predicate.reconciliation.intent_sha256
        or action.effect.idempotency_key != predicate.reconciliation.idempotency_key
        or receipt_predicate.tenant_id != predicate.tenant_id
        or receipt_predicate.case_id != predicate.case_id
        or receipt_predicate.execution_id != predicate.execution_id
        or receipt_predicate.task_id != predicate.task_id
        or receipt_predicate.certificate_ref != predicate.certificate_ref
        or receipt_predicate.effect.effect_type != predicate.reconciliation.effect_type
        or receipt_predicate.effect.target != predicate.reconciliation.target
        or receipt_predicate.effect.intent_sha256 != predicate.reconciliation.intent_sha256
        or receipt_predicate.effect.idempotency_key != predicate.reconciliation.idempotency_key
    )
    if binding_mismatch:
        if any(
            item.status == EffectAttemptStatus.SUCCEEDED
            for item in predicate.reconciliation.attempts
        ):
            return _unsafe(
                predicate,
                OutcomeClosureVerificationReason.EFFECT_BINDING_MISMATCH,
                envelope_sha256=envelope_sha256,
                closure_id=predicate.closure_id,
                payload_sha256=payload_sha256,
                observer_roots=observer_roots,
            )
        return _unknown(
            predicate,
            OutcomeClosureVerificationReason.EFFECT_BINDING_UNKNOWN,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    attempts = predicate.reconciliation.attempts
    successes = sum(item.status == EffectAttemptStatus.SUCCEEDED for item in attempts)
    ordered_times = (
        action.not_before,
        predicate.certificate_ref.verification_at,
        predicate.certificate_ref.reserved_at,
        receipt_predicate.attempt.started_at,
        receipt_predicate.issued_at,
        predicate.evidence_source.observed_at,
        predicate.issued_at,
    )
    window_invalid = (
        any(
            ordered_times[index] > ordered_times[index + 1]
            for index in range(len(ordered_times) - 1)
        )
        or predicate.issued_at > verification_time
        or predicate.evidence_source.valid_until < predicate.issued_at
        or predicate.certificate_ref.reserved_at >= action.expires_at
        or predicate.issued_at >= action.expires_at
        or action.expires_at > action.policy.expires_at
        or predicate.evidence_source.observed_at > predicate.evidence_source.valid_until
        or receipt_predicate.issued_at >= action.expires_at
    )
    if window_invalid:
        if successes:
            return _unsafe(
                predicate,
                OutcomeClosureVerificationReason.OUTCOME_WINDOW_UNSAFE,
                envelope_sha256=envelope_sha256,
                closure_id=predicate.closure_id,
                payload_sha256=payload_sha256,
                observer_roots=observer_roots,
            )
        return _unknown(
            predicate,
            OutcomeClosureVerificationReason.CLOSURE_TIME_INVALID,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    terminal_count = len(attempts) + len(predicate.reconciliation.unresolved)
    if successes > predicate.reconciliation.expected_effect_count:
        return _unsafe(
            predicate,
            OutcomeClosureVerificationReason.DUPLICATE_EFFECT_SUCCESS,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    if predicate.reconciliation.unresolved:
        if successes:
            return _unsafe(
                predicate,
                OutcomeClosureVerificationReason.UNSAFE_UNRESOLVED_EFFECT,
                envelope_sha256=envelope_sha256,
                closure_id=predicate.closure_id,
                payload_sha256=payload_sha256,
                observer_roots=observer_roots,
            )
        return _unknown(
            predicate,
            OutcomeClosureVerificationReason.EFFECT_RECONCILIATION_UNRESOLVED,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    if terminal_count != predicate.reconciliation.expected_effect_count:
        if successes:
            return _unsafe(
                predicate,
                OutcomeClosureVerificationReason.EFFECT_COUNT_MISMATCH,
                envelope_sha256=envelope_sha256,
                closure_id=predicate.closure_id,
                payload_sha256=payload_sha256,
                observer_roots=observer_roots,
            )
        return _unknown(
            predicate,
            OutcomeClosureVerificationReason.EFFECT_COVERAGE_INCOMPLETE,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    if successes == predicate.reconciliation.expected_effect_count and all(
        item.terminal_result == EffectTerminalResult.EFFECT_COMMITTED for item in attempts
    ):
        verdict = OutcomeVerdict.PASS
    elif (
        successes == 0
        and len(attempts) == predicate.reconciliation.expected_effect_count
        and all(
            item.status == EffectAttemptStatus.FAILED
            and item.terminal_result
            in (EffectTerminalResult.EFFECT_REJECTED, EffectTerminalResult.EFFECT_NOT_APPLIED)
            for item in attempts
        )
    ):
        verdict = OutcomeVerdict.FAIL
    elif successes:
        return _unsafe(
            predicate,
            OutcomeClosureVerificationReason.EFFECT_TERMINAL_INVALID,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    else:
        return _unknown(
            predicate,
            OutcomeClosureVerificationReason.EFFECT_TERMINAL_INVALID,
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
        )
    try:
        index_status = outcome_index.append_once(
            tenant_id=predicate.tenant_id,
            closure_id=predicate.closure_id,
            execution_id=predicate.execution_id,
            attempt_id=predicate.attempt_id,
            closure_sequence=predicate.closure_sequence,
            previous_payload_sha256=predicate.previous_payload_sha256,
            payload_sha256=payload_sha256,
            idempotency_key=predicate.reconciliation.idempotency_key,
            intent_sha256=predicate.reconciliation.intent_sha256,
        )
    except Exception:
        index_status = OutcomeIndexStatus.UNAVAILABLE
    if index_status in (OutcomeIndexStatus.APPENDED, OutcomeIndexStatus.ALREADY_PRESENT):
        reason = (
            OutcomeClosureVerificationReason.PASS_VERIFIED
            if verdict == OutcomeVerdict.PASS
            else OutcomeClosureVerificationReason.FAIL_VERIFIED
        )
        if index_status == OutcomeIndexStatus.ALREADY_PRESENT:
            reason = (
                OutcomeClosureVerificationReason.PASS_ALREADY_PRESENT
                if verdict == OutcomeVerdict.PASS
                else OutcomeClosureVerificationReason.FAIL_ALREADY_PRESENT
            )
        return _result(
            verdict,
            (reason,),
            envelope_sha256=envelope_sha256,
            closure_id=predicate.closure_id,
            payload_sha256=payload_sha256,
            observer_roots=observer_roots,
            recorded=True,
            attempt_id=predicate.attempt_id,
            closure_sequence=predicate.closure_sequence,
            previous_payload_sha256=predicate.previous_payload_sha256,
            reconciliation=predicate.reconciliation,
        )
    index_reason = {
        OutcomeIndexStatus.CLOSURE_ID_CONFLICT: (
            OutcomeClosureVerificationReason.CLOSURE_ID_CONFLICT
        ),
        OutcomeIndexStatus.ATTEMPT_SEQUENCE_CONFLICT: (
            OutcomeClosureVerificationReason.ATTEMPT_SEQUENCE_CONFLICT
        ),
        OutcomeIndexStatus.PREVIOUS_DIGEST_CONFLICT: (
            OutcomeClosureVerificationReason.PREVIOUS_DIGEST_CONFLICT
        ),
        OutcomeIndexStatus.IDEMPOTENCY_CONFLICT: (
            OutcomeClosureVerificationReason.IDEMPOTENCY_CONFLICT
        ),
        OutcomeIndexStatus.UNAVAILABLE: OutcomeClosureVerificationReason.OUTCOME_INDEX_UNAVAILABLE,
    }[index_status]
    return _unknown(
        predicate,
        index_reason,
        envelope_sha256=envelope_sha256,
        closure_id=predicate.closure_id,
        payload_sha256=payload_sha256,
        observer_roots=observer_roots,
    )


# Compatibility names retain one wire contract while making the primitive easy to discover.
OutcomeClosureStatus = OutcomeVerdict
OutcomeClosureIndexStatus = OutcomeIndexStatus
InMemoryOutcomeIndex = InMemoryOutcomeClosureIndex


__all__ = [
    "OUTCOME_CLOSURE_AUDIENCE",
    "OUTCOME_CLOSURE_PREDICATE_TYPE",
    "OUTCOME_CLOSURE_VERSION",
    "ActionCertificateReference",
    "ClaimedOutcome",
    "EffectAttemptObservation",
    "EffectAttemptStatus",
    "EffectReconciliation",
    "EffectTerminalResult",
    "ExecutionReceiptReference",
    "ExpectedOutcomeBinding",
    "InMemoryOutcomeClosureIndex",
    "InMemoryOutcomeEvidenceResolver",
    "InMemoryOutcomeIndex",
    "OutcomeClosureIndex",
    "OutcomeClosureIndexStatus",
    "OutcomeClosurePredicate",
    "OutcomeClosureStatement",
    "OutcomeClosureStatus",
    "OutcomeClosureVerificationReason",
    "OutcomeClosureVerificationResult",
    "OutcomeEvidenceResolver",
    "OutcomeEvidenceSource",
    "OutcomeEvidenceSourceKind",
    "OutcomeIndexStatus",
    "OutcomeProducerDeclaration",
    "OutcomeVerdict",
    "UnresolvedEffectObservation",
    "UnresolvedEffectReason",
    "execution_receipt_verification_sha256",
    "expected_outcome_binding_for",
    "verify_outcome_closure",
]
