"""Strict, immutable contracts for the first ProofFlow reference slice."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from proofflow.canonical import sha256_digest

SCHEMA_VERSION = "proofflow.dev/v1alpha1"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class DataClassification(StrEnum):
    PUBLIC_SYNTHETIC = "PUBLIC_SYNTHETIC"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class ActorKind(StrEnum):
    AGENT = "AGENT"
    HUMAN = "HUMAN"
    SYSTEM = "SYSTEM"


class FactStatus(StrEnum):
    PROPOSED = "PROPOSED"
    VERIFIED = "VERIFIED"
    CONFLICTED = "CONFLICTED"
    UNRESOLVED = "UNRESOLVED"


class CaseState(StrEnum):
    RECEIVED = "RECEIVED"
    INGESTING = "INGESTING"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    FACTS_READY = "FACTS_READY"
    RULES_READY = "RULES_READY"
    CALC_READY = "CALC_READY"
    PROPOSAL_READY = "PROPOSAL_READY"
    AUDIT_BLOCKED = "AUDIT_BLOCKED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVISION_REQUIRED = "REVISION_REQUIRED"
    PACKAGED = "PACKAGED"
    CLOSED = "CLOSED"


class SkillStatus(StrEnum):
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    NEEDS_HUMAN = "NEEDS_HUMAN"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"


class AuditVerdict(StrEnum):
    PASS = "PASS"
    REVISE = "REVISE"
    BLOCK = "BLOCK"


class ApprovalDecision(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REVISE = "REVISE"


class ArtifactMeta(StrictModel):
    artifact_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    schema_version: str = SCHEMA_VERSION
    producer_identity: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    created_at: datetime
    source_refs: tuple[str, ...] = ()
    classification: DataClassification = DataClassification.PUBLIC_SYNTHETIC
    content_hash: str | None = None

    @model_validator(mode="after")
    def require_aware_timestamp(self) -> ArtifactMeta:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return self


class Artifact(StrictModel):
    meta: ArtifactMeta

    def seal(self) -> Self:
        digest = sha256_digest(self, exclude_keys=frozenset({"content_hash"}))
        return self.model_copy(
            update={"meta": self.meta.model_copy(update={"content_hash": digest})}
        )

    def verify_hash(self) -> bool:
        if self.meta.content_hash is None:
            return False
        expected = sha256_digest(self, exclude_keys=frozenset({"content_hash"}))
        return self.meta.content_hash == expected


class CaseRecord(StrictModel):
    case_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    state: CaseState = CaseState.RECEIVED
    state_version: int = Field(default=0, ge=0)
    jurisdiction: str = Field(min_length=1)
    as_of_date: date
    input_manifest_hash: str = Field(min_length=1)
    unresolved_items: tuple[str, ...] = ()
    artifact_refs: tuple[str, ...] = ()


class SourceDocument(StrictModel):
    document_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    declared_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    media_type: str
    content: str
    submitted_by: str


class EvidenceObject(Artifact):
    evidence_type: str
    field_name: str
    normalized_value: str
    verbatim_excerpt: str
    source_document_id: str
    fact_status: FactStatus = FactStatus.PROPOSED
    confidence: Decimal = Field(ge=Decimal("0"), le=Decimal("1"))


class TimelineEvent(Artifact):
    occurred_from: date | None = None
    occurred_to: date | None = None
    description: str
    fact_status: FactStatus
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def require_source_or_unresolved(self) -> TimelineEvent:
        has_source = bool(self.meta.source_refs)
        is_unresolved = self.fact_status == FactStatus.UNRESOLVED and bool(self.unresolved_reason)
        if not has_source and not is_unresolved:
            raise ValueError("timeline events require source_refs or an unresolved reason")
        if self.occurred_from and self.occurred_to and self.occurred_to < self.occurred_from:
            raise ValueError("occurred_to must not precede occurred_from")
        return self


class RuleCitation(Artifact):
    rule_id: str
    version: str
    issue_code: str
    title: str
    jurisdiction: str
    effective_from: date
    effective_to: date | None = None
    authoritative_source: str
    locator: str
    excerpt: str
    source_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class CalculationLineItem(StrictModel):
    item_code: str
    formula_id: str
    formula_version: str
    parameters: dict[str, Decimal | str | int]
    intermediate_values: dict[str, Decimal | str | int]
    amount: Decimal


class CalculationSheet(Artifact):
    line_items: tuple[CalculationLineItem, ...]
    total: Decimal | None
    missing_parameters: tuple[str, ...] = ()
    reproducibility_hash: str | None = None

    @model_validator(mode="after")
    def forbid_total_when_parameters_are_missing(self) -> CalculationSheet:
        if self.missing_parameters and self.total is not None:
            raise ValueError("total must be absent when required parameters are missing")
        return self


class Proposal(Artifact):
    option_code: str
    summary: str
    actions: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    rule_refs: tuple[str, ...]
    calculation_ref: str | None = None
    risks: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()


class Conflict(StrictModel):
    conflict_id: str
    severity: str
    object_refs: tuple[str, ...]
    description: str
    required_action: str


class ConflictReport(Artifact):
    conflicts: tuple[Conflict, ...]
    blocker_ids: tuple[str, ...] = ()
    input_complete: bool


class AuditFinding(StrictModel):
    finding_id: str
    severity: str
    object_refs: tuple[str, ...]
    message: str
    required_action: str


class AuditReport(Artifact):
    verdict: AuditVerdict
    findings: tuple[AuditFinding, ...]
    unsupported_claims: tuple[str, ...]
    audited_artifact_hashes: tuple[str, ...]
    policy_version: str


class ApprovalRequest(StrictModel):
    request_id: str
    tenant_id: str
    case_id: str
    artifact_ref: str
    artifact_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audit_report_ref: str
    required_role: str
    expires_at: datetime

    @model_validator(mode="after")
    def require_aware_expiry(self) -> ApprovalRequest:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return self


class HumanDecision(StrictModel):
    actor_id: str
    actor_kind: ActorKind
    actor_role: str
    decision: ApprovalDecision
    reason: str
    decided_at: datetime

    @model_validator(mode="after")
    def require_human_actor_and_aware_time(self) -> HumanDecision:
        if self.actor_kind != ActorKind.HUMAN:
            raise ValueError("approval decisions must come from a human actor")
        if self.decided_at.tzinfo is None or self.decided_at.utcoffset() is None:
            raise ValueError("decided_at must be timezone-aware")
        return self


class ApprovalRecord(Artifact):
    request_id: str
    decision: ApprovalDecision
    approver_id: str
    approver_role: str
    reason: str
    approved_artifact_hash: str
    approval_method: str = "LOCAL_DEMO"
    decided_at: datetime
    expires_at: datetime


class PackageFile(StrictModel):
    path: str
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class PackageManifest(Artifact):
    approval_record_ref: str
    audit_report_ref: str
    files: tuple[PackageFile, ...]
    included_artifact_refs: tuple[str, ...]
    manifest_hash: str | None = None


class TraceEvent(StrictModel):
    sequence: int = Field(ge=1)
    trace_id: str
    tenant_id: str
    case_id: str
    actor_identity: str
    actor_kind: ActorKind
    event_type: str
    input_hash: str | None = None
    output_hash: str | None = None
    status: str
    occurred_at: datetime
    error_code: str | None = None

    @model_validator(mode="after")
    def require_aware_event_time(self) -> TraceEvent:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return self


class SkillContext(StrictModel):
    tenant_id: str
    case_id: str
    caller_identity: str
    actor_kind: ActorKind = ActorKind.AGENT
    trace_id: str
    idempotency_key: str
    schema_version: str = SCHEMA_VERSION
    expected_state_version: int = Field(ge=0)


class Issue(StrictModel):
    code: str
    severity: str
    message: str
    object_refs: tuple[str, ...] = ()
    retryable: bool = False
    needs_human: bool = False


class SkillResult[T](StrictModel):
    status: SkillStatus
    value: T | None = None
    issues: tuple[Issue, ...] = ()
    input_hash: str
    output_hash: str | None = None
    emitted_refs: tuple[str, ...] = ()


def artifact_ref(artifact: Artifact) -> str:
    return f"{artifact.__class__.__name__}:{artifact.meta.artifact_id}"
