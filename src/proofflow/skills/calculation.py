"""Versioned Decimal-only economic-compensation reference calculation."""

from __future__ import annotations

import calendar
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from proofflow.canonical import sha256_digest
from proofflow.contracts import (
    CalculateOutput,
    CalculateRequest,
    CompensationParameters,
    RuleCatalog,
    RuleRecord,
    RuleRetrieveRequest,
)
from proofflow.factories import artifact_meta
from proofflow.models import (
    CalculationLineItem,
    CalculationSheet,
    DataClassification,
    EvidenceObject,
    FactStatus,
    Issue,
    RuleCitation,
    SkillContext,
    SkillResult,
    SkillStatus,
    artifact_ref,
)
from proofflow.skills.common import denied, success
from proofflow.skills.rules import matching_rule_records
from proofflow.trusted_store import TrustedArtifactStore

SUPPORTED_FORMULA = "cn-economic-compensation-v0.1"
REQUIRED_FIELDS = frozenset(
    {
        "employment_start_date",
        "planned_termination_date",
        "monthly_wage_average",
        "local_previous_year_monthly_average_wage",
    }
)
REQUIRED_RULE_ISSUES = frozenset(
    {"economic_compensation_amount", "economic_compensation_wage_basis"}
)


def _add_months(value: date, months: int) -> date:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def _service_coefficient(start: date, end: date) -> Decimal:
    if end < start:
        raise ValueError("planned termination precedes employment start")
    years = end.year - start.year
    anniversary = date(
        end.year, start.month, min(start.day, calendar.monthrange(end.year, start.month)[1])
    )
    if end < anniversary:
        years -= 1
        anniversary = date(
            end.year - 1,
            start.month,
            min(start.day, calendar.monthrange(end.year - 1, start.month)[1]),
        )
    coefficient = Decimal(years)
    if end == anniversary:
        return coefficient
    return coefficient + (Decimal("1") if end >= _add_months(anniversary, 6) else Decimal("0.5"))


def _field_values(request: CalculateRequest) -> tuple[dict[str, str], tuple[str, ...]]:
    grouped: dict[str, set[str]] = {}
    for item in request.evidence:
        grouped.setdefault(item.field_name, set()).add(item.normalized_value)
    conflicts = tuple(sorted(field for field, values in grouped.items() if len(values) > 1))
    values = {field: next(iter(items)) for field, items in grouped.items() if len(items) == 1}
    return values, conflicts


def _seal_is_valid(artifact: EvidenceObject | RuleCitation) -> bool:
    try:
        return artifact.verify_hash()
    except (TypeError, ValueError):
        return False


def _rule_matches_catalog(citation: RuleCitation, catalog: RuleCatalog) -> bool:
    matches = tuple(
        record
        for record in catalog.rules
        if record.rule_id == citation.rule_id and record.version == citation.version
    )
    if len(matches) != 1:
        return False
    record: RuleRecord = matches[0]
    return (
        citation.issue_code == record.issue_code
        and citation.title == record.title
        and citation.jurisdiction == record.jurisdiction
        and citation.effective_from == record.effective_from
        and citation.effective_to == record.effective_to
        and citation.authoritative_source == record.authoritative_source
        and citation.locator == record.locator
        and citation.excerpt == record.statement
        and citation.source_hash == sha256_digest(record)
        and citation.meta.source_refs == (record.authoritative_source,)
    )


def _artifact_boundary_issues(
    context: SkillContext,
    request: CalculateRequest,
    catalog: RuleCatalog,
    trusted_artifacts: TrustedArtifactStore,
) -> tuple[Issue, ...]:
    unverified = False
    untrusted_evidence = False
    cross_context = False
    unresolved = False
    expected_scope = (context.tenant_id, context.case_id, context.trace_id)

    for evidence in request.evidence:
        evidence_unverified = (
            not _seal_is_valid(evidence)
            or evidence.meta.classification != DataClassification.PUBLIC_SYNTHETIC
            or evidence.meta.producer_identity != "PF-A2"
        )
        evidence_cross_context = (
            evidence.meta.tenant_id,
            evidence.meta.case_id,
            evidence.meta.trace_id,
        ) != expected_scope
        evidence_unresolved = evidence.fact_status != FactStatus.VERIFIED
        evidence_registered = trusted_artifacts.contains(context, evidence)
        unverified = unverified or evidence_unverified
        cross_context = cross_context or evidence_cross_context
        unresolved = unresolved or evidence_unresolved
        untrusted_evidence = untrusted_evidence or (
            not evidence_registered
            and not evidence_unverified
            and not evidence_cross_context
            and not evidence_unresolved
        )

    for rule in request.rule_citations:
        unverified = unverified or (
            not _seal_is_valid(rule)
            or rule.meta.classification != DataClassification.PUBLIC_SYNTHETIC
            or rule.meta.producer_identity != "PF-A3"
            or not _rule_matches_catalog(rule, catalog)
        )
        cross_context = (
            cross_context
            or (
                rule.meta.tenant_id,
                rule.meta.case_id,
                rule.meta.trace_id,
            )
            != expected_scope
        )

    issues: list[Issue] = []
    if unverified:
        issues.append(
            Issue(
                code="UNVERIFIED_ARTIFACT",
                severity="BLOCKER",
                message="calculation input contains an unverified or untrusted artifact",
                needs_human=True,
            )
        )
    if cross_context:
        issues.append(
            Issue(
                code="CROSS_TENANT_REFERENCE",
                severity="BLOCKER",
                message="calculation artifacts do not belong to the request context",
            )
        )
    if untrusted_evidence:
        issues.append(
            Issue(
                code="UNTRUSTED_EVIDENCE",
                severity="BLOCKER",
                message="calculation evidence is not registered by this trusted runtime",
                needs_human=True,
            )
        )
    if unresolved:
        issues.append(
            Issue(
                code="UNRESOLVED_PARAMETER",
                severity="BLOCKER",
                message="calculation evidence must be VERIFIED before use",
                needs_human=True,
            )
        )
    return tuple(issues)


def _rule_scope_issue(request: CalculateRequest, catalog: RuleCatalog) -> Issue | None:
    scope = request.rule_scope
    rule_query = RuleRetrieveRequest(
        issue_codes=scope.issue_codes,
        jurisdiction=scope.jurisdiction,
        as_of_date=scope.as_of_date,
    )
    expected_records = tuple(
        record
        for issue_code in rule_query.issue_codes
        for record in matching_rule_records(rule_query, issue_code, catalog)
    )
    has_missing_scope_issue = any(
        not matching_rule_records(rule_query, issue_code, catalog)
        for issue_code in rule_query.issue_codes
    )
    expected_rule_keys = sorted(
        (record.rule_id, record.version, record.issue_code) for record in expected_records
    )
    actual_rule_keys = sorted(
        (citation.rule_id, citation.version, citation.issue_code)
        for citation in request.rule_citations
    )
    if (
        scope.rule_query_input_hash != sha256_digest(rule_query)
        or scope.catalog_version != catalog.catalog_version
        or has_missing_scope_issue
        or actual_rule_keys != expected_rule_keys
    ):
        return Issue(
            code="RULE_SCOPE_MISMATCH",
            severity="BLOCKER",
            message=(
                "rule citations are not a complete result for the declared "
                "jurisdiction, date, issue, and catalog scope"
            ),
            needs_human=True,
        )
    return None


def deterministic_calculate(
    context: SkillContext,
    request: CalculateRequest,
    *,
    catalog: RuleCatalog,
    trusted_artifacts: TrustedArtifactStore,
    now: datetime,
) -> SkillResult[CalculateOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A4",
        result_type=CalculateOutput,
    ):
        return result
    if boundary_issues := _artifact_boundary_issues(context, request, catalog, trusted_artifacts):
        return SkillResult[CalculateOutput](
            status=SkillStatus.BLOCKED,
            issues=boundary_issues,
            input_hash=sha256_digest(request),
        )
    if scope_issue := _rule_scope_issue(request, catalog):
        return SkillResult[CalculateOutput](
            status=SkillStatus.BLOCKED,
            issues=(scope_issue,),
            input_hash=sha256_digest(request),
        )
    if request.formula_version != SUPPORTED_FORMULA:
        return SkillResult[CalculateOutput](
            status=SkillStatus.BLOCKED,
            issues=(
                Issue(
                    code="FORMULA_NOT_FOUND",
                    severity="BLOCKER",
                    message=f"unsupported formula version: {request.formula_version}",
                ),
            ),
            input_hash=sha256_digest(request),
        )

    values, conflicts = _field_values(request)
    missing = tuple(sorted(REQUIRED_FIELDS.difference(values)))
    present_rule_issues = {rule.issue_code for rule in request.rule_citations}
    missing_rules = tuple(sorted(REQUIRED_RULE_ISSUES.difference(present_rule_issues)))
    if conflicts or missing or missing_rules:
        issues = [
            Issue(
                code="CONFLICTING_PARAMETER",
                severity="BLOCKER",
                message=f"multiple verified values for {field}",
                needs_human=True,
            )
            for field in conflicts
        ]
        issues.extend(
            Issue(
                code="MISSING_PARAMETER",
                severity="BLOCKER",
                message=f"required calculation parameter is missing: {field}",
                needs_human=True,
            )
            for field in missing
        )
        issues.extend(
            Issue(
                code="MISSING_RULE",
                severity="BLOCKER",
                message=f"required calculation rule is missing: {issue}",
                needs_human=True,
            )
            for issue in missing_rules
        )
        return SkillResult[CalculateOutput](
            status=SkillStatus.BLOCKED,
            issues=tuple(issues),
            input_hash=sha256_digest(request),
        )

    try:
        parameters = CompensationParameters(
            employment_start_date=date.fromisoformat(values["employment_start_date"]),
            planned_termination_date=date.fromisoformat(values["planned_termination_date"]),
            monthly_wage_average=Decimal(values["monthly_wage_average"]),
            local_previous_year_monthly_average_wage=Decimal(
                values["local_previous_year_monthly_average_wage"]
            ),
        )
        coefficient = _service_coefficient(
            parameters.employment_start_date, parameters.planned_termination_date
        )
    except (ValueError, InvalidOperation) as exc:
        return SkillResult[CalculateOutput](
            status=SkillStatus.BLOCKED,
            issues=(
                Issue(
                    code="INVALID_PARAMETER",
                    severity="BLOCKER",
                    message=str(exc),
                    needs_human=True,
                ),
            ),
            input_hash=sha256_digest(request),
        )

    wage_cap = parameters.local_previous_year_monthly_average_wage * Decimal("3")
    high_wage_cap_applied = parameters.monthly_wage_average > wage_cap
    effective_wage = min(parameters.monthly_wage_average, wage_cap)
    effective_coefficient = (
        min(coefficient, Decimal("12")) if high_wage_cap_applied else coefficient
    )
    amount = (effective_wage * effective_coefficient).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    reproducibility_hash = sha256_digest(
        {
            "formula_version": request.formula_version,
            "parameters": parameters,
            "coefficient": coefficient,
            "effective_wage": effective_wage,
            "effective_coefficient": effective_coefficient,
        }
    )
    line_item = CalculationLineItem(
        item_code="economic_compensation_reference",
        formula_id="PRC-LCL-47",
        formula_version=request.formula_version,
        parameters={
            "employment_start_date": parameters.employment_start_date.isoformat(),
            "planned_termination_date": parameters.planned_termination_date.isoformat(),
            "monthly_wage_average": parameters.monthly_wage_average,
            "local_previous_year_monthly_average_wage": (
                parameters.local_previous_year_monthly_average_wage
            ),
        },
        intermediate_values={
            "service_coefficient": coefficient,
            "wage_cap": wage_cap,
            "high_wage_cap_applied": str(high_wage_cap_applied).lower(),
            "effective_wage": effective_wage,
            "effective_coefficient": effective_coefficient,
        },
        amount=amount,
    )
    sheet = CalculationSheet(
        meta=artifact_meta(
            prefix="calculation",
            identity="PF-A4",
            context=context,
            now=now,
            payload_for_id={
                "formula_version": request.formula_version,
                "reproducibility_hash": reproducibility_hash,
            },
            source_refs=tuple(
                [artifact_ref(item) for item in request.evidence]
                + [artifact_ref(rule) for rule in request.rule_citations]
            ),
        ),
        line_items=(line_item,),
        total=amount,
        reproducibility_hash=reproducibility_hash,
    ).seal()
    output = CalculateOutput(sheet=sheet)
    return success(request, output, (artifact_ref(sheet),))
