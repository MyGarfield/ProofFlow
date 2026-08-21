#!/usr/bin/env python3
"""Export deterministic JSON Schemas for the public ProofFlow contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from proofflow.contracts import (
    CalculateOutput,
    DeterministicCalculateToolCall,
    EvidenceIngestOutput,
    EvidenceIngestToolCall,
    RuleRetrieveOutput,
    RuleRetrieveToolCall,
)
from proofflow.models import (
    ApprovalRecord,
    ApprovalRequest,
    AuditReport,
    CalculationSheet,
    CaseRecord,
    ConflictReport,
    EvidenceObject,
    HumanDecision,
    PackageManifest,
    Proposal,
    RuleCitation,
    SkillContext,
    SkillResult,
    TimelineEvent,
    TraceEvent,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "schemas"
MODELS: dict[str, type[BaseModel]] = {
    "approval-record": ApprovalRecord,
    "approval-request": ApprovalRequest,
    "audit-report": AuditReport,
    "calculation-sheet": CalculationSheet,
    "case-record": CaseRecord,
    "conflict-report": ConflictReport,
    "evidence-object": EvidenceObject,
    "human-decision": HumanDecision,
    "package-manifest": PackageManifest,
    "proposal": Proposal,
    "rule-citation": RuleCitation,
    "skill-context": SkillContext,
    "skill-result": SkillResult[dict[str, Any]],
    "timeline-event": TimelineEvent,
    "trace-event": TraceEvent,
    "tool-deterministic-calculate-call": DeterministicCalculateToolCall,
    "tool-deterministic-calculate-result": SkillResult[CalculateOutput],
    "tool-evidence-ingest-call": EvidenceIngestToolCall,
    "tool-evidence-ingest-result": SkillResult[EvidenceIngestOutput],
    "tool-rule-retrieve-call": RuleRetrieveToolCall,
    "tool-rule-retrieve-result": SkillResult[RuleRetrieveOutput],
}


def render(model: type[BaseModel]) -> str:
    return (
        json.dumps(model.model_json_schema(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    errors: list[str] = []
    if not args.check:
        OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, model in MODELS.items():
        path = OUTPUT / f"{name}.schema.json"
        expected = render(model)
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                errors.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(expected, encoding="utf-8")
    if errors:
        print("stale or missing schemas: " + ", ".join(errors))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
