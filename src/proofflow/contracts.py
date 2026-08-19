"""Typed requests and outputs for the eight public Skill contracts."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from pydantic import Field

from proofflow.models import (
    ApprovalRecord,
    ApprovalRequest,
    AuditReport,
    CalculationSheet,
    ConflictReport,
    EvidenceObject,
    PackageManifest,
    Proposal,
    RuleCitation,
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
    issue_codes: tuple[str, ...]
    jurisdiction: str
    as_of_date: date


class RuleRetrieveOutput(StrictModel):
    citations: tuple[RuleCitation, ...]
    missing_issue_codes: tuple[str, ...]
    catalog_version: str


class CalculateRequest(StrictModel):
    evidence: tuple[EvidenceObject, ...]
    rule_citations: tuple[RuleCitation, ...]
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
