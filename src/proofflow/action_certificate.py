"""Fail-closed ActionCertificate v0.1 contracts and reference verification.

This module is deliberately a pre-execution authorization slice.  It verifies
operator-configured Ed25519 trust roots and reserves a process-local replay key;
it does not perform an external effect or claim durable exactly-once delivery.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from proofflow.canonical import canonical_json

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
ACTION_CERTIFICATE_PREDICATE_TYPE = "https://proofflow.dev/attestations/action-certificate/v0.1"
EXECUTION_RECEIPT_PREDICATE_TYPE = "https://proofflow.dev/attestations/execution-receipt/v0.1"
ACTION_CERTIFICATE_VERSION = "0.1"

MAX_ENVELOPE_BYTES = 256 * 1024
MAX_PAYLOAD_BYTES = 128 * 1024
MAX_SIGNATURES = 16
MAX_TRUST_ROOTS = 64
MAX_REVOCATION_ENTRIES = 4096

SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
HEX_SHA256_PATTERN = r"^[0-9a-f]{64}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$"
UTC_RFC3339_Z_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"


class CertificateWireModel(BaseModel):
    """Strict immutable base for every public ActionCertificate contract."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        populate_by_name=False,
    )


def _require_aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def parse_utc_rfc3339_z(value: str, label: str) -> datetime:
    """Parse the v0.1 wire timestamp profile: UTC RFC 3339 with a literal trailing Z."""

    if re.fullmatch(UTC_RFC3339_Z_PATTERN, value) is None:
        raise ValueError(f"{label} must be UTC RFC 3339 with a trailing Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid calendar date-time") from exc


def _reject_remote_reference(value: str, label: str) -> str:
    lowered = value.casefold()
    if "://" in lowered or lowered.startswith(("file:", "data:", "urn:")):
        raise ValueError(f"{label} must not be a remote or indirect reference")
    return value


def decode_canonical_base64(
    value: str,
    label: str,
    *,
    expected_bytes: int | None = None,
    allow_urlsafe: bool = False,
) -> bytes:
    try:
        encoded = value.encode("ascii")
        normalized = encoded.translate(bytes.maketrans(b"-_", b"+/")) if allow_urlsafe else encoded
        decoded = base64.b64decode(normalized, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64") from exc
    canonical_encodings = {base64.b64encode(decoded).decode("ascii")}
    if allow_urlsafe:
        canonical_encodings.add(base64.urlsafe_b64encode(decoded).decode("ascii"))
    if value not in canonical_encodings:
        raise ValueError(f"{label} must be canonical padded base64")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise ValueError(f"{label} must decode to exactly {expected_bytes} bytes")
    return decoded


class DsseSignature(CertificateWireModel):
    keyid: str = Field(default="", max_length=128)
    sig: str = Field(min_length=88, max_length=88)

    @field_validator("keyid")
    @classmethod
    def keyid_is_only_a_local_hint(cls, value: str) -> str:
        return _reject_remote_reference(value, "keyid")

    @field_validator("sig")
    @classmethod
    def signature_is_ed25519_sized_base64(cls, value: str) -> str:
        decode_canonical_base64(value, "signature", expected_bytes=64, allow_urlsafe=True)
        return value


class DsseEnvelope(CertificateWireModel):
    payloadType: Literal["application/vnd.in-toto+json"]
    payload: str = Field(min_length=1, max_length=((MAX_PAYLOAD_BYTES + 2) // 3) * 4)
    signatures: tuple[DsseSignature, ...] = Field(min_length=1, max_length=MAX_SIGNATURES)

    @field_validator("payload")
    @classmethod
    def payload_is_bounded_canonical_base64(cls, value: str) -> str:
        decoded = decode_canonical_base64(value, "payload", allow_urlsafe=True)
        if len(decoded) > MAX_PAYLOAD_BYTES:
            raise ValueError("decoded payload exceeds the attestation byte limit")
        return value


class Sha256DigestSet(CertificateWireModel):
    sha256: str = Field(pattern=HEX_SHA256_PATTERN)


class InTotoSubject(CertificateWireModel):
    name: str = Field(min_length=1, max_length=256)
    digest: Sha256DigestSet

    @field_validator("name")
    @classmethod
    def subject_name_is_not_a_remote_reference(cls, value: str) -> str:
        return _reject_remote_reference(value, "in-toto subject name")


class PrincipalBinding(CertificateWireModel):
    principal_id: str = Field(pattern=IDENTIFIER_PATTERN)
    identity_issuer: str = Field(min_length=1, max_length=256)


class DelegationHop(CertificateWireModel):
    delegator: str = Field(pattern=IDENTIFIER_PATTERN)
    delegatee: str = Field(pattern=IDENTIFIER_PATTERN)
    scope_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def reject_self_delegation(self) -> Self:
        if self.delegator == self.delegatee:
            raise ValueError("delegator and delegatee must differ")
        return self


class SubjectBinding(CertificateWireModel):
    subject_type: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=256)
    attributes_sha256: str = Field(pattern=SHA256_PATTERN)


class ActionBinding(CertificateWireModel):
    action_name: str = Field(min_length=1, max_length=128)
    parameters_sha256: str = Field(pattern=SHA256_PATTERN)


class ResourceBinding(CertificateWireModel):
    resource_type: str = Field(min_length=1, max_length=128)
    resource_id: str = Field(min_length=1, max_length=512)
    attributes_sha256: str = Field(pattern=SHA256_PATTERN)


class ContextBinding(CertificateWireModel):
    request_id: str = Field(pattern=IDENTIFIER_PATTERN)
    trace_id: str = Field(pattern=IDENTIFIER_PATTERN)
    environment: str = Field(min_length=1, max_length=64)
    attributes_sha256: str = Field(pattern=SHA256_PATTERN)


class PolicyBinding(CertificateWireModel):
    policy_id: str = Field(pattern=IDENTIFIER_PATTERN)
    policy_revision: str = Field(min_length=1, max_length=128)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    decision: Literal["ALLOW"]
    evaluated_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_policy_window(self) -> Self:
        evaluated = _require_aware(self.evaluated_at, "policy evaluated_at")
        expires = _require_aware(self.expires_at, "policy expires_at")
        if expires <= evaluated:
            raise ValueError("policy expires_at must follow evaluated_at")
        return self


class ApprovalBinding(CertificateWireModel):
    required: bool
    approval_id: str | None = Field(default=None, pattern=IDENTIFIER_PATTERN)
    scope_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    approver_principals: tuple[str, ...] = Field(default=(), max_length=16)
    expires_at: datetime | None = None

    @field_validator("approver_principals")
    @classmethod
    def validate_approver_principals(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("approver principals must be unique")
        for value in values:
            if not value or len(value) > 128:
                raise ValueError("approver principal is invalid")
        return values

    @model_validator(mode="after")
    def enforce_conditional_shape(self) -> Self:
        if self.required:
            if (
                self.approval_id is None
                or self.scope_sha256 is None
                or not self.approver_principals
                or self.expires_at is None
            ):
                raise ValueError("approval-required certificates need complete approval binding")
            _require_aware(self.expires_at, "approval expires_at")
        elif (
            self.approval_id is not None
            or self.scope_sha256 is not None
            or self.approver_principals
            or self.expires_at is not None
        ):
            raise ValueError("approval fields must be absent when approval is not required")
        return self


class EffectBinding(CertificateWireModel):
    effect_type: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=512)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)


class ActionCertificatePredicate(CertificateWireModel):
    version: Literal["0.1"]
    certificate_id: str = Field(pattern=IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    human_principal: PrincipalBinding
    workload_principal: PrincipalBinding
    audience: str = Field(min_length=1, max_length=256)
    delegation_chain: tuple[DelegationHop, ...] = Field(max_length=16)
    subject: SubjectBinding
    action: ActionBinding
    resource: ResourceBinding
    context: ContextBinding
    data_classification: Literal["PUBLIC_SYNTHETIC", "INTERNAL", "RESTRICTED"]
    policy: PolicyBinding
    approval: ApprovalBinding
    effect: EffectBinding
    nonce: str = Field(pattern=IDENTIFIER_PATTERN)
    issued_at: datetime
    not_before: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_certificate_window_and_delegation(self) -> Self:
        issued = _require_aware(self.issued_at, "issued_at")
        not_before = _require_aware(self.not_before, "not_before")
        expires = _require_aware(self.expires_at, "expires_at")
        if not_before < issued:
            raise ValueError("not_before must not precede issued_at")
        if expires <= not_before:
            raise ValueError("expires_at must follow not_before")
        if self.policy.evaluated_at > self.issued_at:
            raise ValueError("policy evaluation must not follow certificate issuance")
        if self.policy.expires_at < self.expires_at:
            raise ValueError("policy authorization must cover the certificate lifetime")
        if self.approval.expires_at is not None and self.approval.expires_at < self.expires_at:
            raise ValueError("approval must cover the certificate lifetime")
        if len(set(self.delegation_chain)) != len(self.delegation_chain):
            raise ValueError("delegation hops must be unique")
        if self.delegation_chain:
            if self.delegation_chain[0].delegator != self.human_principal.principal_id:
                raise ValueError("delegation chain must begin at the human principal")
            for left, right in zip(self.delegation_chain, self.delegation_chain[1:], strict=False):
                if left.delegatee != right.delegator:
                    raise ValueError("delegation chain is not contiguous")
            if self.delegation_chain[-1].delegatee != self.workload_principal.principal_id:
                raise ValueError("delegation chain must end at the workload principal")
        elif self.human_principal.principal_id != self.workload_principal.principal_id:
            raise ValueError("distinct principals require an explicit delegation chain")
        return self


class ActionCertificateStatement(CertificateWireModel):
    statement_type: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subject: tuple[InTotoSubject, ...] = Field(min_length=1, max_length=64)
    predicateType: Literal["https://proofflow.dev/attestations/action-certificate/v0.1"]
    predicate: ActionCertificatePredicate

    @field_validator("subject")
    @classmethod
    def subjects_are_unique(cls, values: tuple[InTotoSubject, ...]) -> tuple[InTotoSubject, ...]:
        if len({item.name for item in values}) != len(values):
            raise ValueError("in-toto subject names must be unique")
        return values


class TrustPurpose(StrEnum):
    ACTION_ISSUER = "ACTION_ISSUER"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    EXECUTION_OBSERVER = "EXECUTION_OBSERVER"


class ExecutionObserverScope(StrEnum):
    RUNTIME_EXECUTION = "RUNTIME_EXECUTION"
    ARTIFACT_IO = "ARTIFACT_IO"
    PROTOCOL_EXCHANGE = "PROTOCOL_EXCHANGE"
    TRACE_EXPORT = "TRACE_EXPORT"
    INFERENCE_RESPONSE = "INFERENCE_RESPONSE"
    EFFECT_ATTEMPT = "EFFECT_ATTEMPT"
    METRICS = "METRICS"


class TrustRoot(CertificateWireModel):
    root_id: str = Field(pattern=IDENTIFIER_PATTERN)
    keyid_hints: tuple[str, ...] = Field(default=(), max_length=8)
    algorithm: Literal["Ed25519"]
    purpose: TrustPurpose
    public_key_b64: str = Field(min_length=44, max_length=44)
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    principal_id: str = Field(pattern=IDENTIFIER_PATTERN)
    audiences: tuple[str, ...] = Field(min_length=1, max_length=16)
    predicate_types: tuple[
        Literal[
            "https://proofflow.dev/attestations/action-certificate/v0.1",
            "https://proofflow.dev/attestations/execution-receipt/v0.1",
        ],
        ...,
    ] = Field(min_length=1, max_length=4)
    execution_observer_scopes: tuple[ExecutionObserverScope, ...] = Field(default=(), max_length=7)
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None = None

    @field_validator("keyid_hints")
    @classmethod
    def keyid_hints_are_unique_and_local(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("keyid hints must be unique")
        for value in values:
            _reject_remote_reference(value, "keyid hint")
            if len(value) > 128:
                raise ValueError("keyid hint exceeds the size limit")
        return values

    @field_validator("public_key_b64")
    @classmethod
    def public_key_is_ed25519_sized_base64(cls, value: str) -> str:
        decode_canonical_base64(value, "Ed25519 public key", expected_bytes=32)
        return value

    @model_validator(mode="after")
    def validate_root_window(self) -> Self:
        not_before = _require_aware(self.not_before, "root not_before")
        not_after = _require_aware(self.not_after, "root not_after")
        if not_after <= not_before:
            raise ValueError("root not_after must follow not_before")
        if self.revoked_at is not None:
            _require_aware(self.revoked_at, "root revoked_at")
        if len(set(self.audiences)) != len(self.audiences):
            raise ValueError("root audiences must be unique")
        if len(set(self.predicate_types)) != len(self.predicate_types):
            raise ValueError("root predicate types must be unique")
        if len(set(self.execution_observer_scopes)) != len(self.execution_observer_scopes):
            raise ValueError("execution observer scopes must be unique")
        if self.purpose == TrustPurpose.EXECUTION_OBSERVER and frozenset(
            self.execution_observer_scopes
        ) != frozenset(ExecutionObserverScope):
            raise ValueError("EXECUTION_OBSERVER roots require every v0.1 observer scope")
        if self.purpose != TrustPurpose.EXECUTION_OBSERVER and self.execution_observer_scopes:
            raise ValueError("only EXECUTION_OBSERVER roots may declare observer scopes")
        return self


class TrustPolicy(CertificateWireModel):
    policy_version: Literal["proofflow.action-certificate-trust/v0.1"]
    allowed_tenants: tuple[str, ...] = Field(min_length=1, max_length=64)
    allowed_human_principals: tuple[str, ...] = Field(min_length=1, max_length=128)
    allowed_workload_principals: tuple[str, ...] = Field(min_length=1, max_length=128)
    allowed_action_issuer_principals: tuple[str, ...] = Field(min_length=1, max_length=64)
    allowed_approval_principals: tuple[str, ...] = Field(default=(), max_length=64)
    allowed_execution_observer_principals: tuple[str, ...] = Field(default=(), max_length=64)
    allowed_audiences: tuple[str, ...] = Field(min_length=1, max_length=32)
    allowed_predicate_types: tuple[
        Literal[
            "https://proofflow.dev/attestations/action-certificate/v0.1",
            "https://proofflow.dev/attestations/execution-receipt/v0.1",
        ],
        ...,
    ] = Field(min_length=1, max_length=4)
    approval_required: bool
    action_issuer_threshold: StrictInt = Field(ge=1, le=16)
    human_approval_threshold: StrictInt = Field(ge=1, le=16)
    execution_observer_threshold: StrictInt = Field(default=1, ge=1, le=16)
    max_certificate_lifetime_seconds: StrictInt = Field(ge=1, le=86400)
    max_clock_skew_seconds: StrictInt = Field(default=0, ge=0, le=300)
    roots: tuple[TrustRoot, ...] = Field(min_length=1, max_length=MAX_TRUST_ROOTS)

    @model_validator(mode="after")
    def validate_policy_sets(self) -> Self:
        named_sets = (
            self.allowed_tenants,
            self.allowed_human_principals,
            self.allowed_workload_principals,
            self.allowed_action_issuer_principals,
            self.allowed_approval_principals,
            self.allowed_execution_observer_principals,
            self.allowed_audiences,
            self.allowed_predicate_types,
        )
        if any(len(values) != len(set(values)) for values in named_sets):
            raise ValueError("trust policy allowlists must not contain duplicates")
        if len({root.root_id for root in self.roots}) != len(self.roots):
            raise ValueError("trust root IDs must be unique")
        if self.approval_required and not self.allowed_approval_principals:
            raise ValueError("approval-required policy needs allowed approval principals")
        return self


class ExpectedBinding(CertificateWireModel):
    binding_version: Literal["proofflow.action-certificate-expected/v0.1"]
    certificate_id: str = Field(pattern=IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    human_principal: PrincipalBinding
    workload_principal: PrincipalBinding
    audience: str = Field(min_length=1, max_length=256)
    delegation_chain: tuple[DelegationHop, ...] = Field(max_length=16)
    statement_subjects: tuple[InTotoSubject, ...] = Field(min_length=1, max_length=64)
    subject: SubjectBinding
    action: ActionBinding
    resource: ResourceBinding
    context: ContextBinding
    data_classification: Literal["PUBLIC_SYNTHETIC", "INTERNAL", "RESTRICTED"]
    policy: PolicyBinding
    approval: ApprovalBinding
    effect: EffectBinding
    nonce: str = Field(pattern=IDENTIFIER_PATTERN)


class ApprovalRevocationStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class ApprovalRevocationEntry(CertificateWireModel):
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    approval_id: str = Field(pattern=IDENTIFIER_PATTERN)
    approval_scope_sha256: str = Field(pattern=SHA256_PATTERN)
    status: ApprovalRevocationStatus


class ApprovalRevocationSnapshot(CertificateWireModel):
    snapshot_version: Literal["proofflow.approval-revocations/v0.1"]
    as_of: datetime
    valid_until: datetime
    entries: tuple[ApprovalRevocationEntry, ...] = Field(max_length=MAX_REVOCATION_ENTRIES)

    @field_validator("as_of", "valid_until", mode="before")
    @classmethod
    def timestamps_use_utc_z_wire_profile(cls, value: Any, info: ValidationInfo) -> datetime:
        label = f"approval revocation snapshot {info.field_name}"
        if isinstance(value, str):
            return parse_utc_rfc3339_z(value, label)
        if not isinstance(value, datetime):
            raise ValueError(f"{label} must be a date-time")
        normalized = _require_aware(value, label)
        if value.utcoffset() != timedelta(0):
            raise ValueError(f"{label} must use UTC")
        return normalized

    @model_validator(mode="after")
    def window_and_entries_are_valid(self) -> Self:
        if self.valid_until < self.as_of:
            raise ValueError("approval revocation valid_until must not precede as_of")
        keys = [(item.tenant_id, item.approval_id) for item in self.entries]
        if len(keys) != len(set(keys)):
            raise ValueError("approval revocation entries must be unique")
        return self


class ApprovalRevocationResolver(Protocol):
    """Operator-controlled current-state lookup used immediately before reserve."""

    def resolve(
        self,
        *,
        tenant_id: str,
        approval_id: str,
        approval_scope_sha256: str,
        as_of: datetime,
    ) -> ApprovalRevocationStatus: ...


class SnapshotApprovalRevocationResolver:
    """Offline, immutable resolver used by the reference CLI and tests."""

    def __init__(self, snapshot: ApprovalRevocationSnapshot) -> None:
        self._as_of = snapshot.as_of
        self._valid_until = snapshot.valid_until
        self._entries = {
            (entry.tenant_id, entry.approval_id): (
                entry.approval_scope_sha256,
                entry.status,
            )
            for entry in snapshot.entries
        }

    def resolve(
        self,
        *,
        tenant_id: str,
        approval_id: str,
        approval_scope_sha256: str,
        as_of: datetime,
    ) -> ApprovalRevocationStatus:
        verification_time = _require_aware(as_of, "approval revocation verification time")
        if not self._as_of <= verification_time <= self._valid_until:
            return ApprovalRevocationStatus.UNKNOWN
        entry = self._entries.get((tenant_id, approval_id))
        if entry is None or entry[0] != approval_scope_sha256:
            return ApprovalRevocationStatus.UNKNOWN
        return entry[1]


class ReservationStatus(StrEnum):
    RESERVED = "RESERVED"
    REPLAY = "REPLAY"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"


class ReplayLedger(Protocol):
    """Reference interface; implementations must atomically check and reserve both keys."""

    def reserve_once(
        self,
        *,
        tenant_id: str,
        nonce: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReservationStatus: ...


class InMemoryReplayLedger:
    """Concurrency-safe process-local reference ledger with bounded memory."""

    def __init__(self, *, capacity: int = 10_000) -> None:
        if capacity < 1 or capacity > 1_000_000:
            raise ValueError("replay ledger capacity must be between 1 and 1000000")
        self._capacity = capacity
        self._nonces: dict[tuple[str, str], str] = {}
        self._idempotency: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def reserve_once(
        self,
        *,
        tenant_id: str,
        nonce: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReservationStatus:
        nonce_key = (tenant_id, nonce)
        idempotency = (tenant_id, idempotency_key)
        with self._lock:
            if nonce_key in self._nonces:
                return ReservationStatus.REPLAY
            existing = self._idempotency.get(idempotency)
            if existing is not None:
                if existing == intent_sha256:
                    return ReservationStatus.REPLAY
                return ReservationStatus.IDEMPOTENCY_CONFLICT
            if len(self._nonces) >= self._capacity:
                return ReservationStatus.UNAVAILABLE
            self._nonces[nonce_key] = intent_sha256
            self._idempotency[idempotency] = intent_sha256
            return ReservationStatus.RESERVED


class VerificationStatus(StrEnum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    UNKNOWN = "UNKNOWN"


class VerificationReason(StrEnum):
    ACCEPTED = "ACCEPTED"
    ENVELOPE_INVALID = "ENVELOPE_INVALID"
    ENVELOPE_TOO_LARGE = "ENVELOPE_TOO_LARGE"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    ACTION_ISSUER_THRESHOLD_NOT_MET = "ACTION_ISSUER_THRESHOLD_NOT_MET"
    HUMAN_APPROVAL_THRESHOLD_NOT_MET = "HUMAN_APPROVAL_THRESHOLD_NOT_MET"
    TRUST_POLICY_MISMATCH = "TRUST_POLICY_MISMATCH"
    EXPECTED_BINDING_MISMATCH = "EXPECTED_BINDING_MISMATCH"
    CERTIFICATE_TIME_INVALID = "CERTIFICATE_TIME_INVALID"
    ROOT_TIME_OR_REVOCATION_INVALID = "ROOT_TIME_OR_REVOCATION_INVALID"
    APPROVAL_SCOPE_MISMATCH = "APPROVAL_SCOPE_MISMATCH"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_REVOKED = "APPROVAL_REVOKED"
    APPROVAL_REVOCATION_UNKNOWN = "APPROVAL_REVOCATION_UNKNOWN"
    APPROVAL_REVOCATION_UNAVAILABLE = "APPROVAL_REVOCATION_UNAVAILABLE"
    SELF_APPROVAL = "SELF_APPROVAL"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    REPLAY_LEDGER_UNAVAILABLE = "REPLAY_LEDGER_UNAVAILABLE"


REJECT_VERIFICATION_REASONS = frozenset(
    {
        VerificationReason.ENVELOPE_INVALID,
        VerificationReason.ENVELOPE_TOO_LARGE,
        VerificationReason.PAYLOAD_INVALID,
        VerificationReason.PAYLOAD_TOO_LARGE,
        VerificationReason.SIGNATURE_INVALID,
        VerificationReason.ACTION_ISSUER_THRESHOLD_NOT_MET,
        VerificationReason.HUMAN_APPROVAL_THRESHOLD_NOT_MET,
        VerificationReason.TRUST_POLICY_MISMATCH,
        VerificationReason.EXPECTED_BINDING_MISMATCH,
        VerificationReason.CERTIFICATE_TIME_INVALID,
        VerificationReason.ROOT_TIME_OR_REVOCATION_INVALID,
        VerificationReason.APPROVAL_SCOPE_MISMATCH,
        VerificationReason.APPROVAL_EXPIRED,
        VerificationReason.APPROVAL_REVOKED,
        VerificationReason.SELF_APPROVAL,
        VerificationReason.REPLAY_DETECTED,
        VerificationReason.IDEMPOTENCY_CONFLICT,
    }
)
UNKNOWN_VERIFICATION_REASONS = frozenset(
    {
        VerificationReason.APPROVAL_REVOCATION_UNKNOWN,
        VerificationReason.APPROVAL_REVOCATION_UNAVAILABLE,
        VerificationReason.REPLAY_LEDGER_UNAVAILABLE,
    }
)


class ActionCertificateVerificationResult(CertificateWireModel):
    verification_version: Literal["proofflow.action-certificate-verification/v0.1"]
    status: VerificationStatus
    reason_codes: tuple[VerificationReason, ...] = Field(min_length=1, max_length=16)
    certificate_id: str | None = None
    payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    verified_action_issuer_roots: tuple[str, ...] = Field(default=(), max_length=16)
    verified_human_approval_roots: tuple[str, ...] = Field(default=(), max_length=16)
    reserved: bool

    @model_validator(mode="after")
    def result_semantics_are_closed(self) -> Self:
        reason_set = frozenset(self.reason_codes)
        if len(reason_set) != len(self.reason_codes):
            raise ValueError("verification reason codes must be unique")
        if self.status == VerificationStatus.ACCEPT:
            if self.reason_codes != (VerificationReason.ACCEPTED,) or not self.reserved:
                raise ValueError("ACCEPT requires ACCEPTED and an atomic reservation")
        elif self.status == VerificationStatus.REJECT:
            if self.reserved or not reason_set <= REJECT_VERIFICATION_REASONS:
                raise ValueError("REJECT requires only closed rejection reasons and reserved=false")
        elif self.reserved or not reason_set <= UNKNOWN_VERIFICATION_REASONS:
            raise ValueError("UNKNOWN requires only unavailable reasons and reserved=false")
        return self


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return DSSE v1 PAE bytes exactly as specified by DSSE 1.0.2."""

    type_bytes = payload_type.encode("utf-8")
    return b"".join(
        (
            b"DSSEv1 ",
            str(len(type_bytes)).encode("ascii"),
            b" ",
            type_bytes,
            b" ",
            str(len(payload)).encode("ascii"),
            b" ",
            payload,
        )
    )


def sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _strict_json_object(payload: bytes, label: str) -> Mapping[str, Any]:
    def reject_constant(value: str) -> None:
        del value
        raise ValueError("non-finite JSON number")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} root must be an object")
    return parsed


def parse_json_model[CertificateModelT: CertificateWireModel](
    payload: bytes, model: type[CertificateModelT], label: str
) -> CertificateModelT:
    """Parse a strict JSON object without duplicate keys or non-finite constants."""

    _strict_json_object(payload, label)
    try:
        return model.model_validate_json(payload)
    except ValidationError as exc:
        raise ValueError(f"{label} violates its strict contract") from exc


def approval_scope_sha256(
    statement: ActionCertificateStatement,
) -> str:
    """Compute the exact approval subject defined by ActionCertificate v0.1."""

    predicate = statement.predicate
    value = {
        "tenant_id": predicate.tenant_id,
        "human_principal": predicate.human_principal.model_dump(mode="json"),
        "workload_principal": predicate.workload_principal.model_dump(mode="json"),
        "audience": predicate.audience,
        "delegation_chain": [item.model_dump(mode="json") for item in predicate.delegation_chain],
        "statement_subjects": [item.model_dump(mode="json") for item in statement.subject],
        "subject": predicate.subject.model_dump(mode="json"),
        "action": predicate.action.model_dump(mode="json"),
        "resource": predicate.resource.model_dump(mode="json"),
        "context": predicate.context.model_dump(mode="json"),
        "data_classification": predicate.data_classification,
        "policy": predicate.policy.model_dump(mode="json"),
        "effect": predicate.effect.model_dump(mode="json"),
    }
    return sha256_bytes(canonical_json(value))


def expected_binding_for(
    statement: ActionCertificateStatement,
) -> ExpectedBinding:
    """Build the trusted caller binding view for an already-constructed statement."""

    predicate = statement.predicate
    return ExpectedBinding(
        binding_version="proofflow.action-certificate-expected/v0.1",
        certificate_id=predicate.certificate_id,
        tenant_id=predicate.tenant_id,
        human_principal=predicate.human_principal,
        workload_principal=predicate.workload_principal,
        audience=predicate.audience,
        delegation_chain=predicate.delegation_chain,
        statement_subjects=statement.subject,
        subject=predicate.subject,
        action=predicate.action,
        resource=predicate.resource,
        context=predicate.context,
        data_classification=predicate.data_classification,
        policy=predicate.policy,
        approval=predicate.approval,
        effect=predicate.effect,
        nonce=predicate.nonce,
    )


def _verification_result(
    status: VerificationStatus,
    reasons: tuple[VerificationReason, ...],
    *,
    certificate_id: str | None = None,
    payload_sha256: str | None = None,
    issuer_roots: tuple[str, ...] = (),
    approval_roots: tuple[str, ...] = (),
    reserved: bool = False,
) -> ActionCertificateVerificationResult:
    unique_reasons = tuple(dict.fromkeys(reasons))
    return ActionCertificateVerificationResult(
        verification_version="proofflow.action-certificate-verification/v0.1",
        status=status,
        reason_codes=unique_reasons,
        certificate_id=certificate_id,
        payload_sha256=payload_sha256,
        verified_action_issuer_roots=tuple(sorted(issuer_roots)),
        verified_human_approval_roots=tuple(sorted(approval_roots)),
        reserved=reserved,
    )


def trust_root_fingerprint(root: TrustRoot) -> str:
    return sha256_bytes(decode_canonical_base64(root.public_key_b64, "public key"))


def cryptographically_verified_roots(
    envelope: DsseEnvelope,
    payload: bytes,
    roots: tuple[TrustRoot, ...],
) -> tuple[TrustRoot, ...]:
    pae = dsse_pae(envelope.payloadType, payload)
    verified: dict[str, TrustRoot] = {}
    root_order: dict[str, int] = {root.root_id: index for index, root in enumerate(roots)}
    for signature in envelope.signatures:
        signature_bytes = decode_canonical_base64(
            signature.sig, "signature", expected_bytes=64, allow_urlsafe=True
        )
        candidates = sorted(
            roots,
            key=lambda root: (
                0 if signature.keyid and signature.keyid in root.keyid_hints else 1,
                root_order[root.root_id],
            ),
        )
        for root in candidates:
            public_bytes = decode_canonical_base64(
                root.public_key_b64, "Ed25519 public key", expected_bytes=32
            )
            try:
                Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, pae)
            except InvalidSignature:
                continue
            verified[root.root_id] = root
    return tuple(verified[root_id] for root_id in sorted(verified))


def trust_root_is_current(root: TrustRoot, now: datetime, skew: timedelta) -> bool:
    if now + skew < root.not_before or now - skew >= root.not_after:
        return False
    return root.revoked_at is None or now + skew < root.revoked_at


def _qualifying_roots(
    roots: tuple[TrustRoot, ...],
    *,
    purpose: TrustPurpose,
    predicate: ActionCertificatePredicate,
    policy: TrustPolicy,
    now: datetime,
    approvers: frozenset[str] | None = None,
) -> tuple[TrustRoot, ...]:
    skew = timedelta(seconds=policy.max_clock_skew_seconds)
    allowed_principals = (
        policy.allowed_action_issuer_principals
        if purpose == TrustPurpose.ACTION_ISSUER
        else policy.allowed_approval_principals
    )
    distinct: dict[str, TrustRoot] = {}
    distinct_principals: set[str] = set()
    for root in roots:
        if (
            root.purpose != purpose
            or root.tenant_id != predicate.tenant_id
            or predicate.audience not in root.audiences
            or ACTION_CERTIFICATE_PREDICATE_TYPE not in root.predicate_types
            or root.principal_id not in allowed_principals
            or not trust_root_is_current(root, now, skew)
            or (approvers is not None and root.principal_id not in approvers)
        ):
            continue
        fingerprint = trust_root_fingerprint(root)
        if fingerprint in distinct or root.principal_id in distinct_principals:
            continue
        distinct[fingerprint] = root
        distinct_principals.add(root.principal_id)
    return tuple(distinct[key] for key in sorted(distinct))


def _policy_allows_expected(policy: TrustPolicy, expected: ExpectedBinding) -> bool:
    return (
        expected.tenant_id in policy.allowed_tenants
        and expected.human_principal.principal_id in policy.allowed_human_principals
        and expected.workload_principal.principal_id in policy.allowed_workload_principals
        and expected.audience in policy.allowed_audiences
        and ACTION_CERTIFICATE_PREDICATE_TYPE in policy.allowed_predicate_types
        and expected.approval.required == policy.approval_required
    )


def _certificate_time_is_valid(
    predicate: ActionCertificatePredicate,
    policy: TrustPolicy,
    now: datetime,
) -> bool:
    skew = timedelta(seconds=policy.max_clock_skew_seconds)
    lifetime = predicate.expires_at - predicate.issued_at
    return (
        lifetime <= timedelta(seconds=policy.max_certificate_lifetime_seconds)
        and now + skew >= predicate.not_before
        and now - skew < predicate.expires_at
        and now - skew < predicate.policy.expires_at
    )


def verify_action_certificate(
    envelope_bytes: bytes,
    *,
    trust_policy: TrustPolicy,
    expected_binding: ExpectedBinding,
    replay_ledger: ReplayLedger,
    approval_revocation_resolver: ApprovalRevocationResolver | None,
    now: datetime,
) -> ActionCertificateVerificationResult:
    """Verify and atomically reserve a v0.1 certificate without performing its effect."""

    now = _require_aware(now, "verification time")
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        return _verification_result(
            VerificationStatus.REJECT, (VerificationReason.ENVELOPE_TOO_LARGE,)
        )
    try:
        envelope = parse_json_model(envelope_bytes, DsseEnvelope, "DSSE envelope")
        payload = decode_canonical_base64(envelope.payload, "payload", allow_urlsafe=True)
    except ValueError:
        return _verification_result(
            VerificationStatus.REJECT, (VerificationReason.ENVELOPE_INVALID,)
        )
    if len(payload) > MAX_PAYLOAD_BYTES:
        return _verification_result(
            VerificationStatus.REJECT, (VerificationReason.PAYLOAD_TOO_LARGE,)
        )
    payload_sha256 = sha256_bytes(payload)

    verified_roots = cryptographically_verified_roots(envelope, payload, trust_policy.roots)
    if not verified_roots:
        return _verification_result(
            VerificationStatus.REJECT,
            (VerificationReason.SIGNATURE_INVALID,),
            payload_sha256=payload_sha256,
        )

    # Payload parsing happens only after at least one configured root verifies
    # the DSSE PAE over these exact bytes.
    try:
        statement = parse_json_model(payload, ActionCertificateStatement, "signed payload")
    except ValueError:
        return _verification_result(
            VerificationStatus.REJECT,
            (VerificationReason.PAYLOAD_INVALID,),
            payload_sha256=payload_sha256,
        )
    predicate = statement.predicate

    if not _policy_allows_expected(trust_policy, expected_binding):
        return _verification_result(
            VerificationStatus.REJECT,
            (VerificationReason.TRUST_POLICY_MISMATCH,),
            certificate_id=predicate.certificate_id,
            payload_sha256=payload_sha256,
        )
    if expected_binding_for(statement) != expected_binding:
        return _verification_result(
            VerificationStatus.REJECT,
            (VerificationReason.EXPECTED_BINDING_MISMATCH,),
            certificate_id=predicate.certificate_id,
            payload_sha256=payload_sha256,
        )
    if not _certificate_time_is_valid(predicate, trust_policy, now):
        return _verification_result(
            VerificationStatus.REJECT,
            (VerificationReason.CERTIFICATE_TIME_INVALID,),
            certificate_id=predicate.certificate_id,
            payload_sha256=payload_sha256,
        )

    issuer_roots = _qualifying_roots(
        verified_roots,
        purpose=TrustPurpose.ACTION_ISSUER,
        predicate=predicate,
        policy=trust_policy,
        now=now,
    )
    if len(issuer_roots) < trust_policy.action_issuer_threshold:
        return _verification_result(
            VerificationStatus.REJECT,
            (
                VerificationReason.ROOT_TIME_OR_REVOCATION_INVALID,
                VerificationReason.ACTION_ISSUER_THRESHOLD_NOT_MET,
            ),
            certificate_id=predicate.certificate_id,
            payload_sha256=payload_sha256,
        )

    approval_roots: tuple[TrustRoot, ...] = ()
    if predicate.approval.required:
        scope = approval_scope_sha256(statement)
        if predicate.approval.scope_sha256 != scope:
            return _verification_result(
                VerificationStatus.REJECT,
                (VerificationReason.APPROVAL_SCOPE_MISMATCH,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
            )
        approvers = frozenset(predicate.approval.approver_principals)
        approval_roots = _qualifying_roots(
            verified_roots,
            purpose=TrustPurpose.HUMAN_APPROVAL,
            predicate=predicate,
            policy=trust_policy,
            now=now,
            approvers=approvers,
        )
        if len(approval_roots) < trust_policy.human_approval_threshold:
            return _verification_result(
                VerificationStatus.REJECT,
                (VerificationReason.HUMAN_APPROVAL_THRESHOLD_NOT_MET,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
            )
        issuer_principals = {root.principal_id for root in issuer_roots}
        approval_principals = {root.principal_id for root in approval_roots}
        issuer_fingerprints = {trust_root_fingerprint(root) for root in issuer_roots}
        approval_fingerprints = {trust_root_fingerprint(root) for root in approval_roots}
        if (
            predicate.human_principal.principal_id in approval_principals
            or predicate.workload_principal.principal_id in approval_principals
            or bool(issuer_principals & approval_principals)
            or bool(issuer_fingerprints & approval_fingerprints)
        ):
            return _verification_result(
                VerificationStatus.REJECT,
                (VerificationReason.SELF_APPROVAL,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
                approval_roots=tuple(root.root_id for root in approval_roots),
            )
        if predicate.approval.expires_at is None or now >= predicate.approval.expires_at:
            return _verification_result(
                VerificationStatus.REJECT,
                (VerificationReason.APPROVAL_EXPIRED,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
                approval_roots=tuple(root.root_id for root in approval_roots),
            )
        if approval_revocation_resolver is None:
            return _verification_result(
                VerificationStatus.UNKNOWN,
                (VerificationReason.APPROVAL_REVOCATION_UNKNOWN,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
                approval_roots=tuple(root.root_id for root in approval_roots),
            )
        try:
            revocation = approval_revocation_resolver.resolve(
                tenant_id=predicate.tenant_id,
                approval_id=predicate.approval.approval_id or "",
                approval_scope_sha256=scope,
                as_of=now,
            )
        except Exception:
            return _verification_result(
                VerificationStatus.UNKNOWN,
                (VerificationReason.APPROVAL_REVOCATION_UNAVAILABLE,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
                approval_roots=tuple(root.root_id for root in approval_roots),
            )
        if revocation == ApprovalRevocationStatus.REVOKED:
            return _verification_result(
                VerificationStatus.REJECT,
                (VerificationReason.APPROVAL_REVOKED,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
                approval_roots=tuple(root.root_id for root in approval_roots),
            )
        if revocation != ApprovalRevocationStatus.ACTIVE:
            return _verification_result(
                VerificationStatus.UNKNOWN,
                (VerificationReason.APPROVAL_REVOCATION_UNKNOWN,),
                certificate_id=predicate.certificate_id,
                payload_sha256=payload_sha256,
                issuer_roots=tuple(root.root_id for root in issuer_roots),
                approval_roots=tuple(root.root_id for root in approval_roots),
            )

    try:
        intent_sha256 = approval_scope_sha256(statement)
        reservation = replay_ledger.reserve_once(
            tenant_id=predicate.tenant_id,
            nonce=predicate.nonce,
            idempotency_key=predicate.effect.idempotency_key,
            intent_sha256=intent_sha256,
        )
    except Exception:
        reservation = ReservationStatus.UNAVAILABLE
    issuer_root_ids = tuple(root.root_id for root in issuer_roots)
    approval_root_ids = tuple(root.root_id for root in approval_roots)
    if reservation == ReservationStatus.REPLAY:
        return _verification_result(
            VerificationStatus.REJECT,
            (VerificationReason.REPLAY_DETECTED,),
            certificate_id=predicate.certificate_id,
            payload_sha256=payload_sha256,
            issuer_roots=issuer_root_ids,
            approval_roots=approval_root_ids,
        )
    if reservation == ReservationStatus.IDEMPOTENCY_CONFLICT:
        return _verification_result(
            VerificationStatus.REJECT,
            (VerificationReason.IDEMPOTENCY_CONFLICT,),
            certificate_id=predicate.certificate_id,
            payload_sha256=payload_sha256,
            issuer_roots=issuer_root_ids,
            approval_roots=approval_root_ids,
        )
    if reservation != ReservationStatus.RESERVED:
        return _verification_result(
            VerificationStatus.UNKNOWN,
            (VerificationReason.REPLAY_LEDGER_UNAVAILABLE,),
            certificate_id=predicate.certificate_id,
            payload_sha256=payload_sha256,
            issuer_roots=issuer_root_ids,
            approval_roots=approval_root_ids,
        )
    return _verification_result(
        VerificationStatus.ACCEPT,
        (VerificationReason.ACCEPTED,),
        certificate_id=predicate.certificate_id,
        payload_sha256=payload_sha256,
        issuer_roots=issuer_root_ids,
        approval_roots=approval_root_ids,
        reserved=True,
    )


__all__ = [
    "ACTION_CERTIFICATE_PREDICATE_TYPE",
    "ACTION_CERTIFICATE_VERSION",
    "DSSE_PAYLOAD_TYPE",
    "EXECUTION_RECEIPT_PREDICATE_TYPE",
    "IN_TOTO_STATEMENT_TYPE",
    "REJECT_VERIFICATION_REASONS",
    "UNKNOWN_VERIFICATION_REASONS",
    "UTC_RFC3339_Z_PATTERN",
    "ActionCertificatePredicate",
    "ActionCertificateStatement",
    "ActionCertificateVerificationResult",
    "ApprovalRevocationEntry",
    "ApprovalRevocationResolver",
    "ApprovalRevocationSnapshot",
    "ApprovalRevocationStatus",
    "DsseEnvelope",
    "DsseSignature",
    "ExecutionObserverScope",
    "ExpectedBinding",
    "InMemoryReplayLedger",
    "ReplayLedger",
    "ReservationStatus",
    "SnapshotApprovalRevocationResolver",
    "TrustPolicy",
    "TrustPurpose",
    "TrustRoot",
    "VerificationReason",
    "VerificationStatus",
    "approval_scope_sha256",
    "cryptographically_verified_roots",
    "decode_canonical_base64",
    "dsse_pae",
    "expected_binding_for",
    "parse_json_model",
    "parse_utc_rfc3339_z",
    "sha256_bytes",
    "trust_root_fingerprint",
    "trust_root_is_current",
    "verify_action_certificate",
]
