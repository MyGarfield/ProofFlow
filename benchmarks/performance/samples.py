"""Build frozen synthetic HTTP samples from the reference fixture.

The HTTP load loop does not call these functions. Each request body is built
once, serialized once, and then reused byte-for-byte for warmup and measured
requests.
"""

from __future__ import annotations

import json
from base64 import b64encode
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from proofflow.contracts import (
    CaseManifest,
    DeterministicCalculateToolCall,
    EvidenceIngestRequest,
    EvidenceIngestToolCall,
    RuleCatalog,
    RuleRetrieveRequest,
    RuleRetrieveToolCall,
)
from proofflow.models import EvidenceObject, SkillContext, SkillStatus
from proofflow.skills import evidence_ingest, rule_retrieve
from proofflow.tool_server import (
    DETERMINISTIC_CALCULATE_PATH,
    EVIDENCE_INGEST_PATH,
    HEALTH_PATH,
    RULE_RETRIEVE_PATH,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "examples/cases/happy_path"
RULE_CATALOG_PATH = ROOT / "data/rules/cn_labor_contract_law.catalog.json"
FIXED_NOW = datetime(2026, 8, 20, 4, 0, tzinfo=UTC)


class SampleBuildError(RuntimeError):
    """Raised when checked-in synthetic inputs cannot build a valid sample."""


@dataclass(frozen=True, slots=True)
class RequestSample:
    """One immutable request used for every benchmark repetition."""

    name: str
    method: str
    path: str
    body: bytes | None
    expected_skill_status: str | None
    expected_service_status: str | None


def _context(identity: str, idempotency_key: str) -> SkillContext:
    return SkillContext(
        tenant_id="tenant-public-demo",
        case_id="case-happy-001",
        caller_identity=identity,
        trace_id="trace-performance-fixed-001",
        idempotency_key=idempotency_key,
        expected_state_version=0,
    )


def _fixture_evidence(manifest: CaseManifest) -> tuple[EvidenceObject, ...]:
    evidence: list[EvidenceObject] = []
    for document in manifest.documents:
        document_path = FIXTURE_DIR / document.path
        result = evidence_ingest(
            _context("PF-A2", f"performance-{document.document_id}"),
            EvidenceIngestRequest(
                document_id=document.document_id,
                media_type=document.media_type,
                declared_sha256=document.sha256,
                raw_content=document_path.read_bytes(),
            ),
            now=FIXED_NOW,
        )
        if result.status != SkillStatus.SUCCESS or result.value is None:
            raise SampleBuildError(f"synthetic evidence setup failed for {document.document_id}")
        evidence.extend(result.value.evidence_objects)
    return tuple(evidence)


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def build_evidence_setup_samples() -> tuple[RequestSample, ...]:
    """Return fixed, non-measured calls that seed the synthetic trust registry."""
    manifest = CaseManifest.model_validate_json((FIXTURE_DIR / "manifest.json").read_bytes())
    samples = []
    for document in manifest.documents:
        raw_content = (FIXTURE_DIR / document.path).read_bytes()
        call = EvidenceIngestToolCall(
            fixture_status="SYNTHETIC",
            context=_context("PF-A2", f"performance-{document.document_id}").model_dump(
                mode="json"
            ),
            arguments={
                "document_id": document.document_id,
                "media_type": document.media_type,
                "declared_sha256": document.sha256,
                "raw_content_base64": b64encode(raw_content).decode("ascii"),
            },
        )
        samples.append(
            RequestSample(
                name=f"prepare_{document.document_id}",
                method="POST",
                path=EVIDENCE_INGEST_PATH,
                body=_json_bytes(call.model_dump(mode="json")),
                expected_skill_status=SkillStatus.SUCCESS.value,
                expected_service_status=None,
            )
        )
    return tuple(samples)


def build_fixed_samples(
    *,
    trusted_evidence: tuple[EvidenceObject, ...] | None = None,
) -> tuple[RequestSample, ...]:
    """Return health, rule, and calculation samples with no random input."""
    manifest = CaseManifest.model_validate_json((FIXTURE_DIR / "manifest.json").read_bytes())
    catalog = RuleCatalog.model_validate_json(RULE_CATALOG_PATH.read_bytes())
    rule_arguments = RuleRetrieveRequest(
        issue_codes=(
            "economic_compensation_amount",
            "economic_compensation_wage_basis",
        ),
        jurisdiction=manifest.jurisdiction,
        as_of_date=manifest.as_of_date,
    )
    rule_context = _context("PF-A3", "performance-rule-fixed-001")
    rule_call = RuleRetrieveToolCall(
        fixture_status="SYNTHETIC",
        context=rule_context.model_dump(mode="json"),
        arguments=rule_arguments,
    )
    rule_result = rule_retrieve(rule_context, rule_arguments, catalog=catalog, now=FIXED_NOW)
    if rule_result.status != SkillStatus.SUCCESS or rule_result.value is None:
        raise SampleBuildError("synthetic rule setup did not produce a successful result")

    calculate_call = DeterministicCalculateToolCall(
        fixture_status="SYNTHETIC",
        context=_context("PF-A4", "performance-calculate-fixed-001").model_dump(mode="json"),
        arguments={
            "evidence": (
                trusted_evidence if trusted_evidence is not None else _fixture_evidence(manifest)
            ),
            "rule_citations": rule_result.value.citations,
            "rule_scope": rule_result.value.rule_scope,
            "formula_version": "cn-economic-compensation-v0.1",
        },
    )
    return (
        RequestSample(
            name="health",
            method="GET",
            path=HEALTH_PATH,
            body=None,
            expected_skill_status=None,
            expected_service_status="ok",
        ),
        RequestSample(
            name="rule_retrieve",
            method="POST",
            path=RULE_RETRIEVE_PATH,
            body=_json_bytes(rule_call.model_dump(mode="json")),
            expected_skill_status=SkillStatus.SUCCESS.value,
            expected_service_status=None,
        ),
        RequestSample(
            name="deterministic_calculate",
            method="POST",
            path=DETERMINISTIC_CALCULATE_PATH,
            body=_json_bytes(calculate_call.model_dump(mode="json")),
            expected_skill_status=SkillStatus.SUCCESS.value,
            expected_service_status=None,
        ),
    )
