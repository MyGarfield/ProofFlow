import json
from datetime import UTC, date, datetime
from pathlib import Path

from proofflow.canonical import sha256_file
from proofflow.contracts import (
    CalculateRequest,
    CaseManifest,
    ConflictDetectRequest,
    DecisionAuditRequest,
    EvidenceIngestRequest,
    ProposalGenerateRequest,
    RuleCatalog,
    RuleRetrieveRequest,
)
from proofflow.models import (
    AuditVerdict,
    EvidenceObject,
    SkillContext,
    SkillStatus,
)
from proofflow.skills import (
    conflict_detect,
    decision_audit,
    deterministic_calculate,
    evidence_ingest,
    rule_retrieve,
)
from proofflow.strategy import create_candidate_proposals

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "examples/cases/happy_path"
RULES = ROOT / "data/rules/cn_labor_contract_law.catalog.json"
NOW = datetime(2026, 8, 20, 3, 0, tzinfo=UTC)


def context(identity: str, key: str = "test") -> SkillContext:
    return SkillContext(
        tenant_id="tenant-public-demo",
        case_id="case-happy-001",
        caller_identity=identity,
        trace_id="trace-test",
        idempotency_key=key,
        expected_state_version=0,
    )


def load_manifest() -> CaseManifest:
    return CaseManifest.model_validate_json((FIXTURE / "manifest.json").read_text())


def load_rules() -> RuleCatalog:
    return RuleCatalog.model_validate_json(RULES.read_text())


def evidence_and_rules() -> tuple[tuple[EvidenceObject, ...], tuple]:
    manifest = load_manifest()
    evidence: list[EvidenceObject] = []
    for document in manifest.documents:
        path = FIXTURE / document.path
        result = evidence_ingest(
            context("PF-A2", document.document_id),
            EvidenceIngestRequest(
                document_id=document.document_id,
                media_type=document.media_type,
                declared_sha256=document.sha256,
                raw_content=path.read_bytes(),
            ),
            now=NOW,
        )
        assert result.value is not None
        evidence.extend(result.value.evidence_objects)
    rules = rule_retrieve(
        context("PF-A3"),
        RuleRetrieveRequest(
            issue_codes=manifest.issue_codes,
            jurisdiction=manifest.jurisdiction,
            as_of_date=manifest.as_of_date,
        ),
        catalog=load_rules(),
        now=NOW,
    )
    assert rules.value is not None
    return tuple(evidence), rules.value.citations


def test_prompt_injection_field_remains_ignored_data() -> None:
    manifest = load_manifest()
    document = next(item for item in manifest.documents if item.path == "termination_notice.json")
    path = FIXTURE / document.path

    result = evidence_ingest(
        context("PF-A2"),
        EvidenceIngestRequest(
            document_id=document.document_id,
            media_type=document.media_type,
            declared_sha256=document.sha256,
            raw_content=path.read_bytes(),
        ),
        now=NOW,
    )

    assert result.status == SkillStatus.SUCCESS
    assert result.value is not None
    assert "untrusted_document_text" in result.value.ignored_fields
    assert all(
        item.field_name != "untrusted_document_text" for item in result.value.evidence_objects
    )


def test_source_hash_mismatch_blocks_without_evidence() -> None:
    path = FIXTURE / "contract.json"
    result = evidence_ingest(
        context("PF-A2"),
        EvidenceIngestRequest(
            document_id="doc-contract-001",
            media_type="application/json",
            declared_sha256="sha256:" + "0" * 64,
            raw_content=path.read_bytes(),
        ),
        now=NOW,
    )

    assert result.status == SkillStatus.BLOCKED
    assert result.value is None
    assert result.issues[0].code == "SOURCE_HASH_MISMATCH"


def test_rule_filter_rejects_wrong_jurisdiction_or_inactive_date() -> None:
    result = rule_retrieve(
        context("PF-A3"),
        RuleRetrieveRequest(
            issue_codes=("economic_compensation_amount",),
            jurisdiction="US-CA",
            as_of_date=date(2010, 1, 1),
        ),
        catalog=load_rules(),
        now=NOW,
    )

    assert result.status == SkillStatus.NEEDS_HUMAN
    assert result.value is not None
    assert result.value.citations == ()
    assert result.issues[0].code == "INSUFFICIENT_AUTHORITY"


def test_calculation_is_repeatable_and_uses_decimal_formula() -> None:
    evidence, rules = evidence_and_rules()
    request = CalculateRequest(evidence=evidence, rule_citations=rules)

    first = deterministic_calculate(context("PF-A4", "calc-1"), request, now=NOW)
    second = deterministic_calculate(context("PF-A4", "calc-2"), request, now=NOW)

    assert first.status == SkillStatus.SUCCESS
    assert second.status == SkillStatus.SUCCESS
    assert first.value is not None and second.value is not None
    assert str(first.value.sheet.total) == "60000.00"
    assert first.value.sheet.reproducibility_hash == second.value.sheet.reproducibility_hash


def test_missing_wage_parameter_blocks_before_total() -> None:
    evidence, rules = evidence_and_rules()
    filtered = tuple(item for item in evidence if item.field_name != "monthly_wage_average")

    result = deterministic_calculate(
        context("PF-A4"),
        CalculateRequest(evidence=filtered, rule_citations=rules),
        now=NOW,
    )

    assert result.status == SkillStatus.BLOCKED
    assert result.value is None
    assert any(issue.code == "MISSING_PARAMETER" for issue in result.issues)


def test_conflict_detection_marks_but_does_not_resolve_values() -> None:
    evidence, rules = evidence_and_rules()
    wage = next(item for item in evidence if item.field_name == "monthly_wage_average")
    conflicting = wage.model_copy(
        update={
            "meta": wage.meta.model_copy(
                update={"artifact_id": "evidence-conflicting", "content_hash": None}
            ),
            "normalized_value": "15000.00",
        }
    ).seal()
    calculation = deterministic_calculate(
        context("PF-A4"),
        CalculateRequest(evidence=evidence, rule_citations=rules),
        now=NOW,
    )
    assert calculation.value is not None

    result = conflict_detect(
        context("PF-A6"),
        ConflictDetectRequest(
            evidence=(*evidence, conflicting),
            rules=rules,
            calculation=calculation.value.sheet,
        ),
        now=NOW,
    )

    assert result.value is not None
    assert result.value.report.blocker_ids
    assert wage.normalized_value == "12000.00"
    assert conflicting.normalized_value == "15000.00"


def test_missing_trace_forces_audit_block() -> None:
    evidence, rules = evidence_and_rules()
    calculation_result = deterministic_calculate(
        context("PF-A4"),
        CalculateRequest(evidence=evidence, rule_citations=rules),
        now=NOW,
    )
    assert calculation_result.value is not None
    calculation = calculation_result.value.sheet
    proposal_result = create_candidate_proposals(
        context("PF-A5"),
        ProposalGenerateRequest(evidence=evidence, rules=rules, calculation=calculation),
        now=NOW,
    )
    assert proposal_result.value is not None
    conflict_result = conflict_detect(
        context("PF-A6"),
        ConflictDetectRequest(evidence=evidence, rules=rules, calculation=calculation),
        now=NOW,
    )
    assert conflict_result.value is not None

    audit = decision_audit(
        context("PF-A6"),
        DecisionAuditRequest(
            proposals=proposal_result.value.proposals,
            evidence=evidence,
            rules=rules,
            calculation=calculation,
            conflict_report=conflict_result.value.report,
            observed_event_types=(),
        ),
        now=NOW,
    )

    assert audit.value is not None
    assert audit.value.report.verdict == AuditVerdict.BLOCK
    assert any("trace events" in finding.message for finding in audit.value.report.findings)


def test_fixture_manifest_hashes_match_actual_files() -> None:
    manifest = load_manifest()
    for document in manifest.documents:
        assert sha256_file(FIXTURE / document.path) == document.sha256
    assert json.loads((FIXTURE / "contract.json").read_text())["fixture_status"] == "SYNTHETIC"
