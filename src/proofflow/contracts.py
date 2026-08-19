"""Typed requests and outputs for the eight public Skill contracts."""

from __future__ import annotations

from base64 import b64decode
from binascii import Error as Base64Error
from datetime import date
from decimal import Decimal
from typing import Literal

from pydantic import Field, field_validator

from proofflow.models import (
    ActorKind,
    ApprovalRecord,
    ApprovalRequest,
    AuditReport,
    CalculationSheet,
    ConflictReport,
    EvidenceObject,
    PackageManifest,
    Proposal,
    RuleCitation,
    SkillContext,
    StrictModel,
    TimelineEvent,
)


class ManifestDocument(StrictModel):
    document_id: str
    path: str
    media_type: str
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class CaseManifest(StrictModel):
    schema_version: str
    fixture_status: str
    case_id: str
    tenant_id: str
    jurisdiction: str
    as_of_date: date
    issue_codes: tuple[str, ...]
    documents: tuple[ManifestDocument, ...]
    disclaimer: str


class EvidenceIngestRequest(StrictModel):
    document_id: str
    media_type: str
    declared_sha256: str
    raw_content: bytes


class EvidenceIngestOutput(StrictModel):
    evidence_objects: tuple[EvidenceObject, ...]
    source_hash: str
    ignored_fields: tuple[str, ...]


class TimelineBuildRequest(StrictModel):
    evidence: tuple[EvidenceObject, ...]


class TimelineBuildOutput(StrictModel):
    events: tuple[TimelineEvent, ...]
    unresolved_items: tuple[str, ...]


class RuleRecord(StrictModel):
    rule_id: str
    version: str
    issue_code: str
    title: str
    jurisdiction: str
    effective_from: date
    effective_to: date | None = None
    authoritative_source: str
    locator: str
    statement: str


class RuleCatalog(StrictModel):
    catalog_version: str
    status: str
    legal_advice: bool
    source_policy: str
    rules: tuple[RuleRecord, ...]


class RuleRetrieveRequest(StrictModel):
    issue_codes: tuple[str, ...] = Field(
        min_length=1,
        max_length=32,
        json_schema_extra={"uniqueItems": True},
    )
    jurisdiction: str = Field(min_length=1)
    as_of_date: date = Field(strict=True)

    @field_validator("issue_codes")
    @classmethod
    def require_unique_non_empty_issue_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item for item in value):
            raise ValueError("issue codes must not be empty")
        if len(set(value)) != len(value):
            raise ValueError("issue codes must not contain duplicates")
        return value


class RuleScopeReceipt(RuleRetrieveRequest):
    """Deterministic rule-query receipt; integrity metadata, not authentication."""

    catalog_version: str = Field(min_length=1)
    rule_query_input_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class RuleRetrieveOutput(StrictModel):
    citations: tuple[RuleCitation, ...]
    missing_issue_codes: tuple[str, ...]
    catalog_version: str
    rule_scope: RuleScopeReceipt


class CalculateRequest(StrictModel):
    evidence: tuple[EvidenceObject, ...]
    rule_citations: tuple[RuleCitation, ...]
    rule_scope: RuleScopeReceipt
    formula_version: str = "cn-economic-compensation-v0.1"


class CalculateOutput(StrictModel):
    sheet: CalculationSheet


class ConflictDetectRequest(StrictModel):
    evidence: tuple[EvidenceObject, ...]
    rules: tuple[RuleCitation, ...]
    calculation: CalculationSheet | None
    policy_version: str = "conflict-policy-v0.1"


class ConflictDetectOutput(StrictModel):
    report: ConflictReport


class ProposalGenerateRequest(StrictModel):
    evidence: tuple[EvidenceObject, ...]
    rules: tuple[RuleCitation, ...]
    calculation: CalculationSheet


class ProposalGenerateOutput(StrictModel):
    proposals: tuple[Proposal, ...]


class DecisionAuditRequest(StrictModel):
    proposals: tuple[Proposal, ...]
    evidence: tuple[EvidenceObject, ...]
    rules: tuple[RuleCitation, ...]
    calculation: CalculationSheet
    conflict_report: ConflictReport
    observed_event_types: tuple[str, ...]
    policy_version: str = "audit-policy-v0.1"


class DecisionAuditOutput(StrictModel):
    report: AuditReport


class ApprovalExecuteRequest(StrictModel):
    approval_request: ApprovalRequest
    current_artifact_hash: str


class ApprovalExecuteOutput(StrictModel):
    record: ApprovalRecord


class DocumentPackageRequest(StrictModel):
    proposal: Proposal
    calculation: CalculationSheet
    audit_report: AuditReport
    approval_request: ApprovalRequest
    approval_record: ApprovalRecord
    current_artifact_hash: str
    template_id: str = "controlled-review-draft"
    template_version: str = "0.1.0"


class DocumentPackageOutput(StrictModel):
    manifest: PackageManifest
    draft_markdown: str
    artifacts_json: str


class CompensationParameters(StrictModel):
    employment_start_date: date
    planned_termination_date: date
    monthly_wage_average: Decimal = Field(gt=Decimal("0"))
    local_previous_year_monthly_average_wage: Decimal = Field(gt=Decimal("0"))


class ToolCall(StrictModel):
    """Common REST tool envelope for the synthetic-only reference service."""

    fixture_status: Literal["SYNTHETIC"]


class EvidenceIngestToolArguments(StrictModel):
    document_id: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    declared_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    raw_content_base64: str = Field(json_schema_extra={"contentEncoding": "base64"})

    @field_validator("raw_content_base64")
    @classmethod
    def require_strict_standard_base64(cls, value: str) -> str:
        try:
            b64decode(value, validate=True)
        except (Base64Error, ValueError) as exc:
            raise ValueError("raw_content_base64 must be strict standard Base64") from exc
        return value

    def to_skill_request(self) -> EvidenceIngestRequest:
        return EvidenceIngestRequest(
            document_id=self.document_id,
            media_type=self.media_type,
            declared_sha256=self.declared_sha256,
            raw_content=b64decode(self.raw_content_base64, validate=True),
        )


class EvidenceIngestToolContext(SkillContext):
    caller_identity: Literal["PF-A2"] = "PF-A2"
    actor_kind: Literal[ActorKind.AGENT] = ActorKind.AGENT


class RuleRetrieveToolContext(SkillContext):
    caller_identity: Literal["PF-A3"] = "PF-A3"
    actor_kind: Literal[ActorKind.AGENT] = ActorKind.AGENT


class DeterministicCalculateToolContext(SkillContext):
    caller_identity: Literal["PF-A4"] = "PF-A4"
    actor_kind: Literal[ActorKind.AGENT] = ActorKind.AGENT


class RuleRetrieveToolCall(ToolCall):
    context: RuleRetrieveToolContext
    arguments: RuleRetrieveRequest


class EvidenceIngestToolCall(ToolCall):
    context: EvidenceIngestToolContext
    arguments: EvidenceIngestToolArguments


class DeterministicCalculateToolCall(ToolCall):
    context: DeterministicCalculateToolContext
    arguments: CalculateRequest
