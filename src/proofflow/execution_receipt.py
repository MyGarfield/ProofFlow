"""Observer-signed ExecutionReceipt v0.1 contracts and reference verification.

This module verifies a bounded, strict DSSE/in-toto receipt against operator-provided
trust and an externally supplied ActionCertificate verification result.  It does not
execute a tool, contact a provider, export telemetry, or provide durable exactly-once
delivery.  An accepted receipt proves configured signer provenance and exact binding;
it does not by itself prove that a producer declaration is true.
"""

from __future__ import annotations

import re
import threading
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol, Self

from pydantic import Field, StrictInt, ValidationInfo, field_validator, model_validator

from proofflow.action_certificate import (
    ACTION_CERTIFICATE_PREDICATE_TYPE,
    DSSE_PAYLOAD_TYPE,
    EXECUTION_RECEIPT_PREDICATE_TYPE,
    MAX_ENVELOPE_BYTES,
    MAX_PAYLOAD_BYTES,
    ActionCertificateStatement,
    ActionCertificateVerificationResult,
    CertificateWireModel,
    DsseEnvelope,
    ExecutionObserverScope,
    InTotoSubject,
    PrincipalBinding,
    TrustPolicy,
    TrustPurpose,
    TrustRoot,
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

EXECUTION_RECEIPT_VERSION = "0.1"
EXECUTION_RECEIPT_AUDIENCE = "proofflow-execution-receipt"

MAX_ARTIFACTS_PER_DIRECTION = 128
MAX_PROVENANCE_REFERENCES = 128
MAX_TRACE_LINKS = 64
MAX_RECEIPT_INDEX_CAPACITY = 1_000_000

REQUIRED_EXECUTION_OBSERVER_SCOPES = frozenset(ExecutionObserverScope)

SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$"
TRACE_ID_PATTERN = r"^[0-9a-f]{32}$"
SPAN_ID_PATTERN = r"^[0-9a-f]{16}$"
DECIMAL_AMOUNT_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,9})?$"


def _reject_remote_reference(value: str, label: str) -> str:
    lowered = value.casefold()
    if "://" in lowered or lowered.startswith(("file:", "data:", "urn:")):
        raise ValueError(f"{label} must not be a remote or indirect reference")
    return value


def _require_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must use UTC")
    return value.astimezone(UTC)


def _parse_utc_wire_timestamp(value: Any, label: str) -> datetime:
    if isinstance(value, str):
        return parse_utc_rfc3339_z(value, label)
    if not isinstance(value, datetime):
        raise ValueError(f"{label} must be a date-time")
    return _require_utc(value, label)


class ObservationState(StrEnum):
    OBSERVED = "OBSERVED"
    UNKNOWN = "UNKNOWN"


class ProducerDeclaration(CertificateWireModel):
    producer_id: str = Field(pattern=IDENTIFIER_PATTERN)
    software_name: str = Field(min_length=1, max_length=128)
    software_version: str = Field(min_length=1, max_length=64)
    observer_principals: tuple[str, ...] = Field(min_length=1, max_length=16)

    @field_validator("software_name", "software_version")
    @classmethod
    def software_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"producer {info.field_name}")

    @field_validator("observer_principals")
    @classmethod
    def observer_principals_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("observer principals must be unique")
        for value in values:
            if re.fullmatch(IDENTIFIER_PATTERN, value) is None:
                raise ValueError("observer principal is invalid")
        return values


class AttemptObservation(CertificateWireModel):
    attempt_id: str = Field(pattern=IDENTIFIER_PATTERN)
    attempt_number: StrictInt = Field(ge=1, le=1_000_000)
    started_at: datetime
    ended_at: datetime
    status: Literal["COMPLETED", "FAILED", "CANCELLED", "UNKNOWN"]

    @field_validator("started_at", "ended_at", mode="before")
    @classmethod
    def timestamps_use_utc_z_wire_profile(cls, value: Any, info: ValidationInfo) -> datetime:
        return _parse_utc_wire_timestamp(value, f"attempt {info.field_name}")

    @model_validator(mode="after")
    def ended_at_does_not_precede_start(self) -> Self:
        if self.ended_at < self.started_at:
            raise ValueError("attempt ended_at must not precede started_at")
        return self


class RuntimeObservation(CertificateWireModel):
    runtime_name: str = Field(min_length=1, max_length=128)
    runtime_version: str = Field(min_length=1, max_length=64)
    runtime_build_sha256: str = Field(pattern=SHA256_PATTERN)
    instance_id: str = Field(pattern=IDENTIFIER_PATTERN)

    @field_validator("runtime_name", "runtime_version")
    @classmethod
    def runtime_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"runtime {info.field_name}")


class LocalProtocolObservation(CertificateWireModel):
    kind: Literal["LOCAL"]
    version: Literal["proofflow.local/v0.1"]
    handler_name: str = Field(min_length=1, max_length=128)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("handler_name")
    @classmethod
    def handler_is_a_local_label(cls, value: str) -> str:
        return _reject_remote_reference(value, "local handler name")


class McpProtocolObservation(CertificateWireModel):
    kind: Literal["MCP"]
    version: Literal["2026-07-28"]
    server_name: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("server_name", "tool_name")
    @classmethod
    def mcp_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"MCP {info.field_name}")


class A2aProtocolObservation(CertificateWireModel):
    kind: Literal["A2A"]
    version: Literal["1.0.1"]
    agent_name: str = Field(min_length=1, max_length=128)
    task_id: str = Field(pattern=IDENTIFIER_PATTERN)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("agent_name")
    @classmethod
    def agent_name_is_a_local_label(cls, value: str) -> str:
        return _reject_remote_reference(value, "A2A agent name")


ProtocolObservation = Annotated[
    LocalProtocolObservation | McpProtocolObservation | A2aProtocolObservation,
    Field(discriminator="kind"),
]


class TraceObservation(CertificateWireModel):
    trace_id: str = Field(pattern=TRACE_ID_PATTERN)
    span_id: str = Field(pattern=SPAN_ID_PATTERN)
    parent_span_id: str | None = Field(default=None, pattern=SPAN_ID_PATTERN)
    linked_span_ids: tuple[str, ...] = Field(default=(), max_length=MAX_TRACE_LINKS)
    otel_schema_uri: Literal["https://opentelemetry.io/schemas/1.39.0"]
    conventions_revision: Literal["proofflow.agent-proof/v0.1"]
    observer_evidence_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("trace_id", "span_id", "parent_span_id")
    @classmethod
    def otel_ids_are_not_all_zero(cls, value: str | None) -> str | None:
        if value is not None and not value.strip("0"):
            raise ValueError("OpenTelemetry trace and span IDs must not be all zero")
        return value

    @field_validator("linked_span_ids")
    @classmethod
    def linked_spans_are_unique_and_well_formed(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("linked span IDs must be unique")
        for value in values:
            if re.fullmatch(SPAN_ID_PATTERN, value) is None:
                raise ValueError("linked span ID is invalid")
            if not value.strip("0"):
                raise ValueError("linked OpenTelemetry span IDs must not be all zero")
        return values

    @model_validator(mode="after")
    def trace_relationships_are_not_self_referential(self) -> Self:
        if self.parent_span_id == self.span_id or self.span_id in self.linked_span_ids:
            raise ValueError("a span cannot parent or link to itself")
        return self


class ArtifactObservation(CertificateWireModel):
    artifact_id: str = Field(pattern=IDENTIFIER_PATTERN)
    sha256: str = Field(pattern=SHA256_PATTERN)
    media_type: str = Field(min_length=1, max_length=128)

    @field_validator("media_type")
    @classmethod
    def media_type_is_not_a_reference(cls, value: str) -> str:
        return _reject_remote_reference(value, "artifact media type")


class ToolOperationObservation(CertificateWireModel):
    kind: Literal["TOOL"]
    operation_id: str = Field(pattern=IDENTIFIER_PATTERN)
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    input_schema_sha256: str = Field(pattern=SHA256_PATTERN)
    output_schema_sha256: str = Field(pattern=SHA256_PATTERN)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("name", "version")
    @classmethod
    def tool_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"tool {info.field_name}")


class SkillOperationObservation(CertificateWireModel):
    kind: Literal["SKILL"]
    operation_id: str = Field(pattern=IDENTIFIER_PATTERN)
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    input_schema_sha256: str = Field(pattern=SHA256_PATTERN)
    output_schema_sha256: str = Field(pattern=SHA256_PATTERN)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("name", "version")
    @classmethod
    def skill_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"Skill {info.field_name}")


OperationObservation = Annotated[
    ToolOperationObservation | SkillOperationObservation,
    Field(discriminator="kind"),
]


class TokenUsageObservation(CertificateWireModel):
    status: ObservationState
    input_tokens: StrictInt | None = Field(ge=0, le=10_000_000_000)
    output_tokens: StrictInt | None = Field(ge=0, le=10_000_000_000)
    total_tokens: StrictInt | None = Field(ge=0, le=20_000_000_000)
    observer_evidence_sha256: str | None = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def observed_usage_requires_exact_evidence(self) -> Self:
        values = (self.input_tokens, self.output_tokens, self.total_tokens)
        if self.status == ObservationState.UNKNOWN:
            if (
                any(value is not None for value in values)
                or self.observer_evidence_sha256 is not None
            ):
                raise ValueError("UNKNOWN usage must not carry token values or observer evidence")
            return self
        if any(value is None for value in values) or self.observer_evidence_sha256 is None:
            raise ValueError("OBSERVED usage requires token values and observer evidence")
        if self.total_tokens != self.input_tokens + self.output_tokens:  # type: ignore[operator]
            raise ValueError("total_tokens must equal input_tokens plus output_tokens")
        return self


class ModelInvocationObservation(CertificateWireModel):
    invocation_id: str = Field(pattern=IDENTIFIER_PATTERN)
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=128)
    model_revision: str = Field(min_length=1, max_length=128)
    inference_status: ObservationState
    request_sha256: str | None = Field(pattern=SHA256_PATTERN)
    response_sha256: str | None = Field(pattern=SHA256_PATTERN)
    inference_observer_evidence_sha256: str | None = Field(pattern=SHA256_PATTERN)
    usage: TokenUsageObservation

    @field_validator("provider", "model", "model_revision")
    @classmethod
    def model_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"model {info.field_name}")

    @model_validator(mode="after")
    def inference_state_controls_observed_fields(self) -> Self:
        evidence = (
            self.request_sha256,
            self.response_sha256,
            self.inference_observer_evidence_sha256,
        )
        if self.inference_status == ObservationState.UNKNOWN:
            if any(value is not None for value in evidence):
                raise ValueError(
                    "UNKNOWN inference must not carry observed request/response evidence"
                )
        elif any(value is None for value in evidence):
            raise ValueError("OBSERVED inference requires request, response, and observer evidence")
        return self


class EffectObservation(CertificateWireModel):
    effect_type: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=512)
    intent_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)
    status: ObservationState
    provider_result: Literal["TRANSPORT_ACK", "PROVIDER_DECLARED_FAILURE", "PENDING"] | None
    provider_operation_id: str | None = Field(pattern=IDENTIFIER_PATTERN)
    outbox_entry_sha256: str | None = Field(pattern=SHA256_PATTERN)
    inbox_entry_sha256: str | None = Field(pattern=SHA256_PATTERN)
    provider_request_sha256: str | None = Field(pattern=SHA256_PATTERN)
    provider_response_sha256: str | None = Field(pattern=SHA256_PATTERN)
    before_state_sha256: str | None = Field(pattern=SHA256_PATTERN)
    after_state_sha256: str | None = Field(pattern=SHA256_PATTERN)
    provider_event_sha256: str | None = Field(pattern=SHA256_PATTERN)
    observer_evidence_sha256: str | None = Field(pattern=SHA256_PATTERN)

    @field_validator("effect_type", "target")
    @classmethod
    def effect_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"effect {info.field_name}")

    @model_validator(mode="after")
    def effect_state_controls_observed_fields(self) -> Self:
        values = (
            self.provider_result,
            self.provider_operation_id,
            self.outbox_entry_sha256,
            self.inbox_entry_sha256,
            self.provider_request_sha256,
            self.provider_response_sha256,
            self.before_state_sha256,
            self.after_state_sha256,
            self.provider_event_sha256,
            self.observer_evidence_sha256,
        )
        if self.status == ObservationState.UNKNOWN:
            if any(value is not None for value in values):
                raise ValueError("UNKNOWN effect must not carry provider or observer evidence")
        elif any(value is None for value in values):
            raise ValueError("OBSERVED effect requires the complete v0.1 evidence set")
        return self


class CostObservation(CertificateWireModel):
    status: ObservationState
    currency: str | None = Field(pattern=r"^[A-Z]{3}$")
    amount_decimal: str | None = Field(pattern=DECIMAL_AMOUNT_PATTERN)
    rate_card_sha256: str | None = Field(pattern=SHA256_PATTERN)
    observer_evidence_sha256: str | None = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def cost_state_controls_observed_fields(self) -> Self:
        values = (
            self.currency,
            self.amount_decimal,
            self.rate_card_sha256,
            self.observer_evidence_sha256,
        )
        if self.status == ObservationState.UNKNOWN:
            if any(value is not None for value in values):
                raise ValueError("UNKNOWN cost must not carry a zero, amount, or observer evidence")
        elif any(value is None for value in values):
            raise ValueError("OBSERVED cost requires currency, amount, and observer evidence")
        return self


class DurationObservation(CertificateWireModel):
    status: ObservationState
    milliseconds: StrictInt | None = Field(ge=0, le=86_400_000)
    clock: Literal["MONOTONIC"] | None
    precision_milliseconds: StrictInt | None = Field(ge=1, le=1000)
    observer_evidence_sha256: str | None = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def duration_state_controls_observed_fields(self) -> Self:
        values = (
            self.milliseconds,
            self.clock,
            self.precision_milliseconds,
            self.observer_evidence_sha256,
        )
        if self.status == ObservationState.UNKNOWN:
            if any(value is not None for value in values):
                raise ValueError(
                    "UNKNOWN duration must not carry a zero, value, or observer evidence"
                )
        elif any(value is None for value in values):
            raise ValueError("OBSERVED duration requires milliseconds and observer evidence")
        return self


class ProvenanceReference(CertificateWireModel):
    name: str = Field(min_length=1, max_length=256)
    media_type: str = Field(min_length=1, max_length=128)
    sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("name", "media_type")
    @classmethod
    def provenance_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"provenance {info.field_name}")


class ActionCertificateReference(CertificateWireModel):
    certificate_id: str = Field(pattern=IDENTIFIER_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    verification_result_sha256: str = Field(pattern=SHA256_PATTERN)
    intent_sha256: str = Field(pattern=SHA256_PATTERN)
    verification_at: datetime
    reserved_at: datetime

    @field_validator("verification_at", "reserved_at", mode="before")
    @classmethod
    def timestamps_use_utc_z_wire_profile(cls, value: Any, info: ValidationInfo) -> datetime:
        return _parse_utc_wire_timestamp(value, f"ActionCertificate {info.field_name}")

    @model_validator(mode="after")
    def reservation_does_not_precede_verification(self) -> Self:
        if self.reserved_at < self.verification_at:
            raise ValueError("ActionCertificate reserved_at must not precede verification_at")
        return self


class ExecutionReceiptPredicate(CertificateWireModel):
    version: Literal["0.1"]
    receipt_id: str = Field(pattern=IDENTIFIER_PATTERN)
    execution_id: str = Field(pattern=IDENTIFIER_PATTERN)
    task_id: str = Field(pattern=IDENTIFIER_PATTERN)
    issued_at: datetime
    certificate_ref: ActionCertificateReference
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=IDENTIFIER_PATTERN)
    producer: ProducerDeclaration
    attempt: AttemptObservation
    executor_workload: PrincipalBinding
    runtime: RuntimeObservation
    protocol: ProtocolObservation
    trace: TraceObservation
    inputs: tuple[ArtifactObservation, ...] = Field(
        min_length=1, max_length=MAX_ARTIFACTS_PER_DIRECTION
    )
    outputs: tuple[ArtifactObservation, ...] = Field(max_length=MAX_ARTIFACTS_PER_DIRECTION)
    operation: OperationObservation
    model_invocation: ModelInvocationObservation | None
    effect: EffectObservation
    cost: CostObservation
    duration: DurationObservation
    provenance: tuple[ProvenanceReference, ...] = Field(
        min_length=1, max_length=MAX_PROVENANCE_REFERENCES
    )

    @field_validator("issued_at", mode="before")
    @classmethod
    def issued_at_uses_utc_z_wire_profile(cls, value: Any) -> datetime:
        return _parse_utc_wire_timestamp(value, "receipt issued_at")

    @field_validator("inputs", "outputs")
    @classmethod
    def artifacts_are_unique(
        cls, values: tuple[ArtifactObservation, ...]
    ) -> tuple[ArtifactObservation, ...]:
        if len({item.artifact_id for item in values}) != len(values):
            raise ValueError("artifact IDs must be unique within each direction")
        return values

    @field_validator("provenance")
    @classmethod
    def provenance_is_unique(
        cls, values: tuple[ProvenanceReference, ...]
    ) -> tuple[ProvenanceReference, ...]:
        if len({item.name for item in values}) != len(values):
            raise ValueError("provenance names must be unique")
        return values

    @model_validator(mode="after")
    def predicate_has_no_ambiguous_artifacts(self) -> Self:
        input_ids = {item.artifact_id for item in self.inputs}
        output_ids = {item.artifact_id for item in self.outputs}
        if input_ids & output_ids:
            raise ValueError("input and output artifact IDs must be disjoint")
        if self.attempt.status == "COMPLETED" and not self.outputs:
            raise ValueError("a completed attempt requires at least one output artifact")
        if self.issued_at < self.attempt.ended_at:
            raise ValueError("receipt issued_at must not precede attempt ended_at")
        if self.certificate_ref.intent_sha256 != self.effect.intent_sha256:
            raise ValueError("certificate intent and effect intent must match")
        if (
            self.protocol.request_sha256 != self.operation.request_sha256
            or self.protocol.response_sha256 != self.operation.response_sha256
        ):
            raise ValueError("protocol and operation request/response digests must match")
        if isinstance(self.protocol, LocalProtocolObservation) and (
            self.protocol.handler_name != self.operation.name
        ):
            raise ValueError("LOCAL handler_name must match the operation name")
        if isinstance(self.protocol, McpProtocolObservation) and (
            self.protocol.tool_name != self.operation.name
        ):
            raise ValueError("MCP tool_name must match the operation name")
        if isinstance(self.protocol, A2aProtocolObservation) and (
            self.protocol.task_id != self.task_id
        ):
            raise ValueError("A2A protocol task_id must match the receipt task_id")
        if (
            self.effect.status == ObservationState.OBSERVED
            and self.effect.provider_request_sha256 != self.operation.request_sha256
        ):
            raise ValueError("observed provider request must match the logical operation request")
        return self


class ExecutionReceiptStatement(CertificateWireModel):
    statement_type: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subject: tuple[InTotoSubject, ...] = Field(max_length=64)
    predicateType: Literal["https://proofflow.dev/attestations/execution-receipt/v0.1"]
    predicate: ExecutionReceiptPredicate

    @field_validator("subject")
    @classmethod
    def subjects_are_unique(cls, values: tuple[InTotoSubject, ...]) -> tuple[InTotoSubject, ...]:
        if len({item.name for item in values}) != len(values):
            raise ValueError("in-toto subject names must be unique")
        return values

    @model_validator(mode="after")
    def subjects_match_output_artifacts(self) -> Self:
        expected = {
            item.artifact_id: item.sha256.removeprefix("sha256:") for item in self.predicate.outputs
        }
        actual = {item.name: item.digest.sha256 for item in self.subject}
        if actual != expected:
            raise ValueError("in-toto subjects must exactly match output artifacts")
        return self


class ExpectedExecutionBinding(CertificateWireModel):
    binding_version: Literal["proofflow.execution-receipt-expected/v0.1"]
    certificate_ref: ActionCertificateReference
    tenant_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=IDENTIFIER_PATTERN)
    execution_id: str = Field(pattern=IDENTIFIER_PATTERN)
    task_id: str = Field(pattern=IDENTIFIER_PATTERN)
    attempt_id: str = Field(pattern=IDENTIFIER_PATTERN)
    attempt_number: StrictInt = Field(ge=1, le=1_000_000)
    human_principal: PrincipalBinding
    executor_workload: PrincipalBinding
    executor_workload_key_fingerprints: tuple[str, ...] = Field(min_length=1, max_length=16)
    human_principal_key_fingerprints: tuple[str, ...] = Field(min_length=1, max_length=16)
    runtime: RuntimeObservation
    protocol: ProtocolObservation
    trace: TraceObservation
    inputs: tuple[ArtifactObservation, ...] = Field(
        min_length=1, max_length=MAX_ARTIFACTS_PER_DIRECTION
    )
    outputs: tuple[ArtifactObservation, ...] = Field(max_length=MAX_ARTIFACTS_PER_DIRECTION)
    operation: OperationObservation
    effect_type: str = Field(min_length=1, max_length=128)
    effect_target: str = Field(min_length=1, max_length=512)
    effect_intent_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)

    @field_validator("effect_type", "effect_target")
    @classmethod
    def effect_fields_are_local_labels(cls, value: str, info: ValidationInfo) -> str:
        return _reject_remote_reference(value, f"expected effect {info.field_name}")

    @field_validator(
        "executor_workload_key_fingerprints",
        "human_principal_key_fingerprints",
    )
    @classmethod
    def identity_key_fingerprints_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("identity key fingerprints must be unique")
        for value in values:
            if re.fullmatch(SHA256_PATTERN, value) is None:
                raise ValueError("identity key fingerprint is invalid")
        return values

    @model_validator(mode="after")
    def artifact_bindings_are_unambiguous(self) -> Self:
        input_ids = [item.artifact_id for item in self.inputs]
        output_ids = [item.artifact_id for item in self.outputs]
        if len(input_ids) != len(set(input_ids)) or len(output_ids) != len(set(output_ids)):
            raise ValueError("expected artifact IDs must be unique within each direction")
        if set(input_ids) & set(output_ids):
            raise ValueError("expected input and output artifact IDs must be disjoint")
        return self


def expected_execution_binding_for(
    statement: ExecutionReceiptStatement,
    *,
    human_principal: PrincipalBinding,
    executor_workload_key_fingerprints: tuple[str, ...],
    human_principal_key_fingerprints: tuple[str, ...],
) -> ExpectedExecutionBinding:
    """Build a comparison view; callers must source the expected values independently."""

    predicate = statement.predicate
    return ExpectedExecutionBinding(
        binding_version="proofflow.execution-receipt-expected/v0.1",
        certificate_ref=predicate.certificate_ref,
        tenant_id=predicate.tenant_id,
        case_id=predicate.case_id,
        execution_id=predicate.execution_id,
        task_id=predicate.task_id,
        attempt_id=predicate.attempt.attempt_id,
        attempt_number=predicate.attempt.attempt_number,
        human_principal=human_principal,
        executor_workload=predicate.executor_workload,
        executor_workload_key_fingerprints=executor_workload_key_fingerprints,
        human_principal_key_fingerprints=human_principal_key_fingerprints,
        runtime=predicate.runtime,
        protocol=predicate.protocol,
        trace=predicate.trace,
        inputs=predicate.inputs,
        outputs=predicate.outputs,
        operation=predicate.operation,
        effect_type=predicate.effect.effect_type,
        effect_target=predicate.effect.target,
        effect_intent_sha256=predicate.effect.intent_sha256,
        idempotency_key=predicate.effect.idempotency_key,
    )


class ReceiptIndexStatus(StrEnum):
    APPENDED = "APPENDED"
    ALREADY_PRESENT = "ALREADY_PRESENT"
    RECEIPT_ID_CONFLICT = "RECEIPT_ID_CONFLICT"
    ATTEMPT_CONFLICT = "ATTEMPT_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"


class ReceiptIndex(Protocol):
    """Reference interface for an atomic, append-only receipt identity index."""

    def append_once(
        self,
        *,
        tenant_id: str,
        receipt_id: str,
        execution_id: str,
        attempt_id: str,
        payload_sha256: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReceiptIndexStatus: ...


class InMemoryReceiptIndex:
    """Concurrency-safe process-local index with bounded memory and no eviction."""

    def __init__(self, *, capacity: int = 10_000) -> None:
        if capacity < 1 or capacity > MAX_RECEIPT_INDEX_CAPACITY:
            raise ValueError("receipt index capacity must be between 1 and 1000000")
        self._capacity = capacity
        self._receipts: dict[tuple[str, str], str] = {}
        self._attempts: dict[tuple[str, str, str], str] = {}
        self._idempotency: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def append_once(
        self,
        *,
        tenant_id: str,
        receipt_id: str,
        execution_id: str,
        attempt_id: str,
        payload_sha256: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReceiptIndexStatus:
        receipt_key = (tenant_id, receipt_id)
        attempt_key = (tenant_id, execution_id, attempt_id)
        idempotency = (tenant_id, idempotency_key)
        with self._lock:
            existing_receipt = self._receipts.get(receipt_key)
            existing_attempt = self._attempts.get(attempt_key)
            existing_intent = self._idempotency.get(idempotency)
            if existing_receipt is not None:
                if existing_receipt == payload_sha256 and existing_attempt == payload_sha256:
                    return ReceiptIndexStatus.ALREADY_PRESENT
                return ReceiptIndexStatus.RECEIPT_ID_CONFLICT
            if existing_attempt is not None:
                return ReceiptIndexStatus.ATTEMPT_CONFLICT
            if existing_intent is not None and existing_intent != intent_sha256:
                return ReceiptIndexStatus.IDEMPOTENCY_CONFLICT
            if len(self._receipts) >= self._capacity:
                return ReceiptIndexStatus.UNAVAILABLE
            self._receipts[receipt_key] = payload_sha256
            self._attempts[attempt_key] = payload_sha256
            self._idempotency[idempotency] = intent_sha256
            return ReceiptIndexStatus.APPENDED


class ExecutionReceiptVerificationReason(StrEnum):
    APPENDED = "APPENDED"
    ALREADY_PRESENT = "ALREADY_PRESENT"
    ENVELOPE_INVALID = "ENVELOPE_INVALID"
    ENVELOPE_TOO_LARGE = "ENVELOPE_TOO_LARGE"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    TRUST_POLICY_MISMATCH = "TRUST_POLICY_MISMATCH"
    EXPECTED_BINDING_MISMATCH = "EXPECTED_BINDING_MISMATCH"
    RECEIPT_TIME_INVALID = "RECEIPT_TIME_INVALID"
    ACTION_CERTIFICATE_REFERENCE_MISMATCH = "ACTION_CERTIFICATE_REFERENCE_MISMATCH"
    ACTION_CERTIFICATE_NOT_ACCEPTED = "ACTION_CERTIFICATE_NOT_ACCEPTED"
    ACTION_CERTIFICATE_RESERVATION_ORDER_INVALID = "ACTION_CERTIFICATE_RESERVATION_ORDER_INVALID"
    CERTIFICATE_EXECUTION_WINDOW_MISMATCH = "CERTIFICATE_EXECUTION_WINDOW_MISMATCH"
    ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN = "ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN"
    ACTION_CERTIFICATE_AUTHORITY_UNKNOWN = "ACTION_CERTIFICATE_AUTHORITY_UNKNOWN"
    EXECUTION_OBSERVER_THRESHOLD_NOT_MET = "EXECUTION_OBSERVER_THRESHOLD_NOT_MET"
    ROOT_TIME_OR_REVOCATION_INVALID = "ROOT_TIME_OR_REVOCATION_INVALID"
    PRODUCER_SIGNER_MISMATCH = "PRODUCER_SIGNER_MISMATCH"
    SELF_OBSERVATION = "SELF_OBSERVATION"
    RECEIPT_ID_CONFLICT = "RECEIPT_ID_CONFLICT"
    ATTEMPT_CONFLICT = "ATTEMPT_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    RECEIPT_INDEX_UNAVAILABLE = "RECEIPT_INDEX_UNAVAILABLE"


REJECT_RECEIPT_REASONS = frozenset(
    {
        ExecutionReceiptVerificationReason.ENVELOPE_INVALID,
        ExecutionReceiptVerificationReason.ENVELOPE_TOO_LARGE,
        ExecutionReceiptVerificationReason.PAYLOAD_INVALID,
        ExecutionReceiptVerificationReason.PAYLOAD_TOO_LARGE,
        ExecutionReceiptVerificationReason.SIGNATURE_INVALID,
        ExecutionReceiptVerificationReason.TRUST_POLICY_MISMATCH,
        ExecutionReceiptVerificationReason.EXPECTED_BINDING_MISMATCH,
        ExecutionReceiptVerificationReason.RECEIPT_TIME_INVALID,
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_NOT_ACCEPTED,
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_RESERVATION_ORDER_INVALID,
        ExecutionReceiptVerificationReason.CERTIFICATE_EXECUTION_WINDOW_MISMATCH,
        ExecutionReceiptVerificationReason.PRODUCER_SIGNER_MISMATCH,
        ExecutionReceiptVerificationReason.SELF_OBSERVATION,
        ExecutionReceiptVerificationReason.RECEIPT_ID_CONFLICT,
        ExecutionReceiptVerificationReason.ATTEMPT_CONFLICT,
        ExecutionReceiptVerificationReason.IDEMPOTENCY_CONFLICT,
        ExecutionReceiptVerificationReason.ROOT_TIME_OR_REVOCATION_INVALID,
    }
)
UNKNOWN_RECEIPT_REASONS = frozenset(
    {
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN,
        ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_AUTHORITY_UNKNOWN,
        ExecutionReceiptVerificationReason.EXECUTION_OBSERVER_THRESHOLD_NOT_MET,
        ExecutionReceiptVerificationReason.RECEIPT_INDEX_UNAVAILABLE,
    }
)


class ExecutionReceiptVerificationResult(CertificateWireModel):
    verification_version: Literal["proofflow.execution-receipt-verification/v0.1"]
    status: VerificationStatus
    reason_codes: tuple[ExecutionReceiptVerificationReason, ...] = Field(
        min_length=1, max_length=16
    )
    receipt_id: str | None = None
    payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    verified_execution_observer_roots: tuple[str, ...] = Field(default=(), max_length=16)
    recorded: bool
    inference_status: ObservationState
    usage_status: ObservationState
    effect_status: ObservationState
    cost_status: ObservationState
    duration_status: ObservationState

    @model_validator(mode="after")
    def result_semantics_are_closed(self) -> Self:
        reason_set = frozenset(self.reason_codes)
        if len(reason_set) != len(self.reason_codes):
            raise ValueError("verification reason codes must be unique")
        if len(set(self.verified_execution_observer_roots)) != len(
            self.verified_execution_observer_roots
        ):
            raise ValueError("verified observer root IDs must be unique")
        observation_states = (
            self.inference_status,
            self.usage_status,
            self.effect_status,
            self.cost_status,
            self.duration_status,
        )
        if self.status == VerificationStatus.ACCEPT:
            if (
                self.reason_codes
                not in (
                    (ExecutionReceiptVerificationReason.APPENDED,),
                    (ExecutionReceiptVerificationReason.ALREADY_PRESENT,),
                )
                or not self.recorded
                or self.receipt_id is None
                or self.payload_sha256 is None
                or not self.verified_execution_observer_roots
            ):
                raise ValueError(
                    "ACCEPT requires a bound receipt, observer root, and recorded=true"
                )
        elif self.status == VerificationStatus.REJECT:
            if (
                self.recorded
                or not reason_set <= REJECT_RECEIPT_REASONS
                or any(state != ObservationState.UNKNOWN for state in observation_states)
            ):
                raise ValueError("REJECT requires only closed rejection reasons and recorded=false")
        elif (
            self.recorded
            or not reason_set <= UNKNOWN_RECEIPT_REASONS
            or any(state != ObservationState.UNKNOWN for state in observation_states)
        ):
            raise ValueError("UNKNOWN requires only unavailable reasons and recorded=false")
        return self


def _result(
    status: VerificationStatus,
    reasons: tuple[ExecutionReceiptVerificationReason, ...],
    *,
    envelope_sha256: str,
    receipt_id: str | None = None,
    payload_sha256: str | None = None,
    observer_roots: tuple[str, ...] = (),
    recorded: bool = False,
    statement: ExecutionReceiptStatement | None = None,
) -> ExecutionReceiptVerificationResult:
    predicate = (
        statement.predicate
        if statement is not None and status == VerificationStatus.ACCEPT
        else None
    )
    model = predicate.model_invocation if predicate is not None else None
    return ExecutionReceiptVerificationResult(
        verification_version="proofflow.execution-receipt-verification/v0.1",
        status=status,
        reason_codes=tuple(dict.fromkeys(reasons)),
        receipt_id=receipt_id,
        payload_sha256=payload_sha256,
        envelope_sha256=envelope_sha256,
        verified_execution_observer_roots=tuple(sorted(observer_roots)),
        recorded=recorded,
        inference_status=(
            model.inference_status if model is not None else ObservationState.UNKNOWN
        ),
        usage_status=(model.usage.status if model is not None else ObservationState.UNKNOWN),
        effect_status=(
            predicate.effect.status if predicate is not None else ObservationState.UNKNOWN
        ),
        cost_status=(predicate.cost.status if predicate is not None else ObservationState.UNKNOWN),
        duration_status=(
            predicate.duration.status if predicate is not None else ObservationState.UNKNOWN
        ),
    )


def action_certificate_verification_sha256(
    result: ActionCertificateVerificationResult,
) -> str:
    """Hash the normalized strict verification result used as trusted local input."""

    return sha256_bytes(canonical_json(result.model_dump(mode="json")))


def _policy_allows_receipt(policy: TrustPolicy, expected: ExpectedExecutionBinding) -> bool:
    return (
        expected.tenant_id in policy.allowed_tenants
        and expected.human_principal.principal_id in policy.allowed_human_principals
        and expected.executor_workload.principal_id in policy.allowed_workload_principals
        and EXECUTION_RECEIPT_AUDIENCE in policy.allowed_audiences
        and EXECUTION_RECEIPT_PREDICATE_TYPE in policy.allowed_predicate_types
        and bool(policy.allowed_execution_observer_principals)
    )


def _action_certificate_context(
    *,
    action_certificate_envelope_bytes: bytes,
    action_certificate_verification: ActionCertificateVerificationResult,
    expected: ActionCertificateReference,
) -> tuple[
    VerificationStatus,
    ExecutionReceiptVerificationReason | None,
    ActionCertificateStatement | None,
]:
    if len(action_certificate_envelope_bytes) > MAX_ENVELOPE_BYTES:
        return (
            VerificationStatus.REJECT,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
            None,
        )
    try:
        envelope = parse_json_model(
            action_certificate_envelope_bytes, DsseEnvelope, "ActionCertificate DSSE envelope"
        )
        payload = decode_canonical_base64(
            envelope.payload, "ActionCertificate payload", allow_urlsafe=True
        )
    except ValueError:
        return (
            VerificationStatus.REJECT,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
            None,
        )
    if envelope.payloadType != DSSE_PAYLOAD_TYPE or len(payload) > MAX_PAYLOAD_BYTES:
        return (
            VerificationStatus.REJECT,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
            None,
        )
    if (
        sha256_bytes(action_certificate_envelope_bytes) != expected.envelope_sha256
        or sha256_bytes(payload) != expected.payload_sha256
        or action_certificate_verification_sha256(action_certificate_verification)
        != expected.verification_result_sha256
        or action_certificate_verification.certificate_id != expected.certificate_id
        or action_certificate_verification.payload_sha256 != expected.payload_sha256
    ):
        return (
            VerificationStatus.REJECT,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
            None,
        )
    if action_certificate_verification.status == VerificationStatus.UNKNOWN:
        return (
            VerificationStatus.UNKNOWN,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN,
            None,
        )
    if (
        action_certificate_verification.status != VerificationStatus.ACCEPT
        or not action_certificate_verification.reserved
    ):
        return (
            VerificationStatus.REJECT,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_NOT_ACCEPTED,
            None,
        )
    try:
        statement = parse_json_model(
            payload, ActionCertificateStatement, "accepted ActionCertificate payload"
        )
    except ValueError:
        return (
            VerificationStatus.REJECT,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
            None,
        )
    if (
        statement.predicate.certificate_id != expected.certificate_id
        or approval_scope_sha256(statement) != expected.intent_sha256
    ):
        return (
            VerificationStatus.REJECT,
            ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,
            None,
        )
    return VerificationStatus.ACCEPT, None, statement


def _authority_roots(
    policy: TrustPolicy,
    action_result: ActionCertificateVerificationResult,
    action_statement: ActionCertificateStatement,
    action_envelope_bytes: bytes,
    verification_at: datetime,
) -> tuple[TrustRoot, ...] | None:
    root_by_id = {root.root_id: root for root in policy.roots}
    issuer_ids = action_result.verified_action_issuer_roots
    approval_ids = action_result.verified_human_approval_roots
    root_ids = issuer_ids + approval_ids
    if (
        len(root_ids) != len(set(root_ids))
        or not issuer_ids
        or any(root_id not in root_by_id for root_id in root_ids)
    ):
        return None
    issuer_roots = tuple(root_by_id[root_id] for root_id in issuer_ids)
    approval_roots = tuple(root_by_id[root_id] for root_id in approval_ids)
    try:
        envelope = parse_json_model(
            action_envelope_bytes, DsseEnvelope, "accepted ActionCertificate DSSE envelope"
        )
        payload = decode_canonical_base64(
            envelope.payload, "accepted ActionCertificate payload", allow_urlsafe=True
        )
        cryptographic_root_ids = {
            root.root_id
            for root in cryptographically_verified_roots(envelope, payload, policy.roots)
        }
    except ValueError:
        return None
    if not set(root_ids) <= cryptographic_root_ids:
        return None
    skew = timedelta(seconds=policy.max_clock_skew_seconds)
    if (
        any(
            root.purpose != TrustPurpose.ACTION_ISSUER
            or root.tenant_id != action_statement.predicate.tenant_id
            or action_statement.predicate.audience not in root.audiences
            or ACTION_CERTIFICATE_PREDICATE_TYPE not in root.predicate_types
            or root.principal_id not in policy.allowed_action_issuer_principals
            or not trust_root_is_current(root, verification_at, skew)
            for root in issuer_roots
        )
        or len({root.principal_id for root in issuer_roots}) < policy.action_issuer_threshold
        or len({trust_root_fingerprint(root) for root in issuer_roots})
        < policy.action_issuer_threshold
    ):
        return None
    if action_statement.predicate.approval.required:
        if (
            len(approval_roots) < policy.human_approval_threshold
            or any(
                root.purpose != TrustPurpose.HUMAN_APPROVAL
                or root.tenant_id != action_statement.predicate.tenant_id
                or action_statement.predicate.audience not in root.audiences
                or ACTION_CERTIFICATE_PREDICATE_TYPE not in root.predicate_types
                or root.principal_id not in policy.allowed_approval_principals
                or root.principal_id not in action_statement.predicate.approval.approver_principals
                or not trust_root_is_current(root, verification_at, skew)
                for root in approval_roots
            )
            or len({root.principal_id for root in approval_roots}) < policy.human_approval_threshold
            or len({trust_root_fingerprint(root) for root in approval_roots})
            < policy.human_approval_threshold
        ):
            return None
    elif approval_roots:
        return None
    issuer_principals = {root.principal_id for root in issuer_roots}
    approval_principals = {root.principal_id for root in approval_roots}
    issuer_fingerprints = {trust_root_fingerprint(root) for root in issuer_roots}
    approval_fingerprints = {trust_root_fingerprint(root) for root in approval_roots}
    if (
        action_statement.predicate.human_principal.principal_id in approval_principals
        or action_statement.predicate.workload_principal.principal_id in approval_principals
        or issuer_principals & approval_principals
        or issuer_fingerprints & approval_fingerprints
    ):
        return None
    return issuer_roots + approval_roots


def _qualifying_observer_roots(
    roots: tuple[TrustRoot, ...],
    *,
    predicate: ExecutionReceiptPredicate,
    policy: TrustPolicy,
    authority_roots: tuple[TrustRoot, ...],
    human_principal_id: str,
    disallowed_key_fingerprints: frozenset[str],
    now: datetime,
) -> tuple[tuple[TrustRoot, ...], bool, bool, bool]:
    skew = timedelta(seconds=policy.max_clock_skew_seconds)
    authority_principals = {root.principal_id for root in authority_roots}
    authority_fingerprints = {trust_root_fingerprint(root) for root in authority_roots}
    declared = frozenset(predicate.producer.observer_principals)
    distinct: dict[str, TrustRoot] = {}
    distinct_principals: set[str] = set()
    stale_or_revoked = False
    self_observation = False
    producer_mismatch = False
    for root in roots:
        if (
            root.purpose != TrustPurpose.EXECUTION_OBSERVER
            or root.tenant_id != predicate.tenant_id
            or EXECUTION_RECEIPT_AUDIENCE not in root.audiences
            or EXECUTION_RECEIPT_PREDICATE_TYPE not in root.predicate_types
            or root.principal_id not in policy.allowed_execution_observer_principals
            or frozenset(root.execution_observer_scopes) != REQUIRED_EXECUTION_OBSERVER_SCOPES
        ):
            continue
        if root.principal_id not in declared:
            producer_mismatch = True
            continue
        fingerprint = trust_root_fingerprint(root)
        if (
            root.principal_id == predicate.executor_workload.principal_id
            or root.principal_id == human_principal_id
            or root.principal_id in authority_principals
            or fingerprint in authority_fingerprints
            or fingerprint in disallowed_key_fingerprints
        ):
            self_observation = True
            continue
        if not trust_root_is_current(root, predicate.issued_at, skew) or not trust_root_is_current(
            root, now, skew
        ):
            stale_or_revoked = True
            continue
        if fingerprint in distinct or root.principal_id in distinct_principals:
            continue
        distinct[fingerprint] = root
        distinct_principals.add(root.principal_id)
    return (
        tuple(distinct[key] for key in sorted(distinct)),
        stale_or_revoked,
        self_observation,
        producer_mismatch,
    )


def verify_execution_receipt(
    envelope_bytes: bytes,
    *,
    trust_policy: TrustPolicy,
    expected_binding: ExpectedExecutionBinding,
    action_certificate_envelope_bytes: bytes,
    action_certificate_verification: ActionCertificateVerificationResult,
    receipt_index: ReceiptIndex,
    now: datetime,
) -> ExecutionReceiptVerificationResult:
    """Verify and process-locally append one observer-signed receipt."""

    verification_time = _require_utc(now, "verification time")
    envelope_sha256 = sha256_bytes(envelope_bytes)
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.ENVELOPE_TOO_LARGE,),
            envelope_sha256=envelope_sha256,
        )
    try:
        envelope = parse_json_model(envelope_bytes, DsseEnvelope, "ExecutionReceipt DSSE envelope")
        payload = decode_canonical_base64(
            envelope.payload, "ExecutionReceipt payload", allow_urlsafe=True
        )
    except ValueError:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.ENVELOPE_INVALID,),
            envelope_sha256=envelope_sha256,
        )
    if len(payload) > MAX_PAYLOAD_BYTES:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.PAYLOAD_TOO_LARGE,),
            envelope_sha256=envelope_sha256,
        )
    payload_sha256 = sha256_bytes(payload)
    verified_roots = cryptographically_verified_roots(envelope, payload, trust_policy.roots)
    if not verified_roots:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.SIGNATURE_INVALID,),
            envelope_sha256=envelope_sha256,
            payload_sha256=payload_sha256,
        )
    try:
        statement = parse_json_model(payload, ExecutionReceiptStatement, "signed receipt payload")
    except ValueError:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.PAYLOAD_INVALID,),
            envelope_sha256=envelope_sha256,
            payload_sha256=payload_sha256,
        )
    predicate = statement.predicate
    skew = timedelta(seconds=trust_policy.max_clock_skew_seconds)
    if predicate.issued_at > verification_time + skew:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.RECEIPT_TIME_INVALID,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    if not _policy_allows_receipt(trust_policy, expected_binding):
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.TRUST_POLICY_MISMATCH,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    if (
        expected_execution_binding_for(
            statement,
            human_principal=expected_binding.human_principal,
            executor_workload_key_fingerprints=(
                expected_binding.executor_workload_key_fingerprints
            ),
            human_principal_key_fingerprints=(expected_binding.human_principal_key_fingerprints),
        )
        != expected_binding
    ):
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.EXPECTED_BINDING_MISMATCH,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    action_status, action_reason, action_statement = _action_certificate_context(
        action_certificate_envelope_bytes=action_certificate_envelope_bytes,
        action_certificate_verification=action_certificate_verification,
        expected=predicate.certificate_ref,
    )
    if action_status != VerificationStatus.ACCEPT:
        safe_status = action_status
        if action_reason is None:
            safe_status = VerificationStatus.UNKNOWN
            action_reason = ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN
        return _result(
            safe_status,
            (action_reason,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    if action_statement is None:
        return _result(
            VerificationStatus.UNKNOWN,
            (ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_ACCEPTANCE_UNKNOWN,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    action_predicate = action_statement.predicate
    action_inputs = {item.name: "sha256:" + item.digest.sha256 for item in action_statement.subject}
    receipt_inputs = {item.artifact_id: item.sha256 for item in predicate.inputs}
    receipt_output_ids = {item.artifact_id for item in predicate.outputs}
    if predicate.certificate_ref.reserved_at > predicate.attempt.started_at:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_RESERVATION_ORDER_INVALID,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    if (
        predicate.certificate_ref.verification_at + skew < action_predicate.not_before
        or predicate.certificate_ref.verification_at - skew >= action_predicate.expires_at
        or predicate.certificate_ref.reserved_at + skew < action_predicate.not_before
        or predicate.certificate_ref.reserved_at - skew >= action_predicate.expires_at
        or predicate.attempt.started_at + skew < action_predicate.not_before
        or predicate.attempt.ended_at - skew >= action_predicate.expires_at
    ):
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.CERTIFICATE_EXECUTION_WINDOW_MISMATCH,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    if (
        action_predicate.tenant_id != predicate.tenant_id
        or action_predicate.human_principal != expected_binding.human_principal
        or action_predicate.subject.subject_id != predicate.case_id
        or action_predicate.workload_principal != predicate.executor_workload
        or action_predicate.context.trace_id != predicate.trace.trace_id
        or action_predicate.context.request_id != predicate.execution_id
        or action_predicate.action.action_name != predicate.operation.name
        or action_predicate.action.parameters_sha256 != predicate.operation.request_sha256
        or action_predicate.effect.effect_type != predicate.effect.effect_type
        or action_predicate.effect.target != predicate.effect.target
        or action_predicate.effect.request_sha256 != predicate.operation.request_sha256
        or action_predicate.effect.idempotency_key != predicate.effect.idempotency_key
        or approval_scope_sha256(action_statement) != predicate.effect.intent_sha256
        or action_inputs != receipt_inputs
        or (
            action_predicate.resource.resource_type == "artifact"
            and action_predicate.resource.resource_id not in receipt_output_ids
        )
    ):
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_REFERENCE_MISMATCH,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    authority_roots = _authority_roots(
        trust_policy,
        action_certificate_verification,
        action_statement,
        action_certificate_envelope_bytes,
        predicate.certificate_ref.verification_at,
    )
    if authority_roots is None:
        return _result(
            VerificationStatus.UNKNOWN,
            (ExecutionReceiptVerificationReason.ACTION_CERTIFICATE_AUTHORITY_UNKNOWN,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    static_observer_roots = tuple(
        root
        for root in verified_roots
        if root.purpose == TrustPurpose.EXECUTION_OBSERVER
        and root.tenant_id == predicate.tenant_id
        and EXECUTION_RECEIPT_AUDIENCE in root.audiences
        and EXECUTION_RECEIPT_PREDICATE_TYPE in root.predicate_types
        and root.principal_id in trust_policy.allowed_execution_observer_principals
        and frozenset(root.execution_observer_scopes) == REQUIRED_EXECUTION_OBSERVER_SCOPES
    )
    if not static_observer_roots:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.TRUST_POLICY_MISMATCH,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    observer_roots, stale_or_revoked, self_observation, producer_mismatch = (
        _qualifying_observer_roots(
            verified_roots,
            predicate=predicate,
            policy=trust_policy,
            authority_roots=authority_roots,
            human_principal_id=action_predicate.human_principal.principal_id,
            disallowed_key_fingerprints=frozenset(
                expected_binding.executor_workload_key_fingerprints
                + expected_binding.human_principal_key_fingerprints
            ),
            now=verification_time,
        )
    )
    if self_observation:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.SELF_OBSERVATION,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    if stale_or_revoked:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.ROOT_TIME_OR_REVOCATION_INVALID,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            observer_roots=tuple(root.root_id for root in observer_roots),
            statement=statement,
        )
    if producer_mismatch or frozenset(root.principal_id for root in observer_roots) != frozenset(
        predicate.producer.observer_principals
    ):
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.PRODUCER_SIGNER_MISMATCH,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            statement=statement,
        )
    if len(observer_roots) < trust_policy.execution_observer_threshold:
        return _result(
            VerificationStatus.UNKNOWN,
            (ExecutionReceiptVerificationReason.EXECUTION_OBSERVER_THRESHOLD_NOT_MET,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            observer_roots=tuple(root.root_id for root in observer_roots),
            statement=statement,
        )
    try:
        index_status = receipt_index.append_once(
            tenant_id=predicate.tenant_id,
            receipt_id=predicate.receipt_id,
            execution_id=predicate.execution_id,
            attempt_id=predicate.attempt.attempt_id,
            payload_sha256=payload_sha256,
            idempotency_key=predicate.effect.idempotency_key,
            intent_sha256=predicate.effect.intent_sha256,
        )
    except Exception:
        index_status = ReceiptIndexStatus.UNAVAILABLE
    root_ids = tuple(root.root_id for root in observer_roots)
    if index_status == ReceiptIndexStatus.ALREADY_PRESENT:
        return _result(
            VerificationStatus.ACCEPT,
            (ExecutionReceiptVerificationReason.ALREADY_PRESENT,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            observer_roots=root_ids,
            recorded=True,
            statement=statement,
        )
    if index_status == ReceiptIndexStatus.RECEIPT_ID_CONFLICT:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.RECEIPT_ID_CONFLICT,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            observer_roots=root_ids,
            statement=statement,
        )
    if index_status == ReceiptIndexStatus.ATTEMPT_CONFLICT:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.ATTEMPT_CONFLICT,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            observer_roots=root_ids,
            statement=statement,
        )
    if index_status == ReceiptIndexStatus.IDEMPOTENCY_CONFLICT:
        return _result(
            VerificationStatus.REJECT,
            (ExecutionReceiptVerificationReason.IDEMPOTENCY_CONFLICT,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            observer_roots=root_ids,
            statement=statement,
        )
    if index_status != ReceiptIndexStatus.APPENDED:
        return _result(
            VerificationStatus.UNKNOWN,
            (ExecutionReceiptVerificationReason.RECEIPT_INDEX_UNAVAILABLE,),
            envelope_sha256=envelope_sha256,
            receipt_id=predicate.receipt_id,
            payload_sha256=payload_sha256,
            observer_roots=root_ids,
            statement=statement,
        )
    return _result(
        VerificationStatus.ACCEPT,
        (ExecutionReceiptVerificationReason.APPENDED,),
        envelope_sha256=envelope_sha256,
        receipt_id=predicate.receipt_id,
        payload_sha256=payload_sha256,
        observer_roots=root_ids,
        recorded=True,
        statement=statement,
    )


__all__ = [
    "EXECUTION_RECEIPT_AUDIENCE",
    "EXECUTION_RECEIPT_PREDICATE_TYPE",
    "EXECUTION_RECEIPT_VERSION",
    "REJECT_RECEIPT_REASONS",
    "UNKNOWN_RECEIPT_REASONS",
    "ActionCertificateReference",
    "ArtifactObservation",
    "CostObservation",
    "DurationObservation",
    "EffectObservation",
    "ExecutionReceiptPredicate",
    "ExecutionReceiptStatement",
    "ExecutionReceiptVerificationReason",
    "ExecutionReceiptVerificationResult",
    "ExpectedExecutionBinding",
    "InMemoryReceiptIndex",
    "ModelInvocationObservation",
    "ObservationState",
    "ReceiptIndex",
    "ReceiptIndexStatus",
    "TokenUsageObservation",
    "action_certificate_verification_sha256",
    "expected_execution_binding_for",
    "verify_execution_receipt",
]
