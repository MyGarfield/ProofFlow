"""Versioned Decimal-only economic-compensation reference calculation."""

from __future__ import annotations

import calendar
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from proofflow.canonical import sha256_digest
from proofflow.contracts import CalculateOutput, CalculateRequest, CompensationParameters
from proofflow.factories import artifact_meta
from proofflow.models import (
    CalculationLineItem,
    CalculationSheet,
    Issue,
    SkillContext,
    SkillResult,
    SkillStatus,
    artifact_ref,
)
from proofflow.skills.common import denied, success

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


def deterministic_calculate(
    context: SkillContext,
    request: CalculateRequest,
    *,
    now: datetime,
) -> SkillResult[CalculateOutput]:
    if result := denied(
        context=context,
        request=request,
        expected_identity="PF-A4",
        result_type=CalculateOutput,
    ):
        return result
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
