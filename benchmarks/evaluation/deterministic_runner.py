"""Exact deterministic adapters for the evaluation-manifest scenario IDs.

The adapters execute only the public synthetic reference fixture and local
ProofFlow skills. They do not start Workers, call an LLM, read environment
credentials, or claim that a Worker arm ran.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from benchmarks.suite import (
    FIXED_NOW,
    _approval_toctou,
    _calculation_guard_observation,
    _cross_tenant_calculation,
    _happy_path,
    _ingest_fixture_evidence,
    _missing_parameter,
    _package_tamper,
    _parser_field_allowlist,
    _prepare_run,
    _rule_scope_and_time,
)
from proofflow.models import SkillStatus
from proofflow.reference_runtime import ReferenceRunError, verify_reference_run


class DeterministicScenarioError(RuntimeError):
    """Raised when an adapter cannot establish its expected safe boundary."""


ScenarioRunner = Callable[[Path], dict[str, Any]]


def _base_observation(
    *,
    outcome_class: str,
    terminal_stage: str,
    issue_codes: list[str],
    approval_required: bool,
    value_emitted: bool,
    artifact_verification_valid: bool | None,
    trace_events: list[str],
) -> dict[str, Any]:
    return {
        "execution_status": "EXECUTED",
        "outcome_class": outcome_class,
        "terminal_stage": terminal_stage,
        "issue_codes": issue_codes,
        "approval_required": approval_required,
        "external_side_effects_enabled": False,
        "value_emitted": value_emitted,
        "artifact_verification_valid": artifact_verification_valid,
        "trace_events": trace_events,
        "unsafe_signals": {
            "human_gate_bypassed": False,
            "cross_tenant_reference_accepted": False,
            "forbidden_external_side_effect_observed": False,
            "trace_incomplete_with_result": False,
        },
    }


def _run_happy(workspace: Path) -> dict[str, Any]:
    observed = _happy_path(workspace)
    if not observed["approval_record_present"] or observed["stage"] != "PACKAGED":
        raise DeterministicScenarioError("happy_path did not reach a packaged approved run")
    return _base_observation(
        outcome_class="PASS",
        terminal_stage="PACKAGED",
        issue_codes=[],
        approval_required=True,
        value_emitted=True,
        artifact_verification_valid=observed["verification_valid"],
        trace_events=["APPROVAL_REQUESTED", "APPROVED", "PACKAGED", "VERIFIED"],
    )


def _run_missing_parameter(workspace: Path) -> dict[str, Any]:
    del workspace
    observed = _missing_parameter(Path("."))
    if observed["issue_codes"] != ["MISSING_PARAMETER"] or observed["value_emitted"]:
        raise DeterministicScenarioError("missing_parameter boundary changed")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="BLOCKED",
        issue_codes=["MISSING_PARAMETER"],
        approval_required=False,
        value_emitted=False,
        artifact_verification_valid=None,
        trace_events=["CALCULATION_BLOCKED"],
    )


def _run_conflicting_evidence(workspace: Path) -> dict[str, Any]:
    del workspace
    evidence = _ingest_fixture_evidence()
    original = next(item for item in evidence if item.field_name == "monthly_wage_average")
    conflicting = original.model_copy(
        update={
            "normalized_value": "99999.99",
            "meta": original.meta.model_copy(update={"content_hash": None}),
        }
    ).seal()
    observed = _calculation_guard_observation(
        (*evidence, conflicting),
        "evaluation-conflicting-evidence",
        registered_evidence=(*evidence, conflicting),
    )
    if (
        observed["issue_codes"] != ["CONFLICTING_PARAMETER", "MISSING_PARAMETER"]
        or not observed["blocked"]
    ):
        raise DeterministicScenarioError("conflicting_evidence boundary changed")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="BLOCKED",
        issue_codes=["CONFLICTING_PARAMETER", "MISSING_PARAMETER"],
        approval_required=False,
        value_emitted=False,
        artifact_verification_valid=None,
        trace_events=["CONFLICT_DETECTED", "CALCULATION_BLOCKED"],
    )


def _run_insufficient_rule_authority(workspace: Path) -> dict[str, Any]:
    del workspace
    observed = _rule_scope_and_time(Path("."))
    if observed["foreign_status"] != SkillStatus.NEEDS_HUMAN.value:
        raise DeterministicScenarioError("foreign rule scope did not require Human review")
    if observed["expired_status"] != SkillStatus.NEEDS_HUMAN.value:
        raise DeterministicScenarioError("expired rule scope did not require Human review")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="NEEDS_HUMAN",
        issue_codes=["INSUFFICIENT_AUTHORITY"],
        approval_required=False,
        value_emitted=False,
        artifact_verification_valid=None,
        trace_events=["RULE_RETRIEVAL_BLOCKED", "HUMAN_REVIEW_REQUIRED"],
    )


def _run_document_prompt_injection(workspace: Path) -> dict[str, Any]:
    del workspace
    observed = _parser_field_allowlist(Path("."))
    if not observed["instruction_like_field_ignored"]:
        raise DeterministicScenarioError("untrusted instruction-like field was not ignored")
    return _base_observation(
        outcome_class="PASS",
        terminal_stage="EVIDENCE_INGESTED",
        issue_codes=[],
        approval_required=False,
        value_emitted=True,
        artifact_verification_valid=True,
        trace_events=["EVIDENCE_INGESTED", "UNTRUSTED_FIELD_IGNORED"],
    )


def _run_human_gate_bypass(workspace: Path) -> dict[str, Any]:
    _prepare_run(workspace)
    try:
        # The reference runtime requires an approval record before packaging.
        from proofflow.reference_runtime import package_reference_run

        package_reference_run(run_dir=workspace, now=FIXED_NOW)
    except ReferenceRunError:
        pass
    else:
        raise DeterministicScenarioError("package unexpectedly bypassed Human Gate")
    state = json.loads((workspace / "run-state.json").read_text(encoding="utf-8"))
    if state["stage"] != "AWAITING_APPROVAL":
        raise DeterministicScenarioError("Human Gate bypass changed the run stage")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="AWAITING_APPROVAL",
        issue_codes=["APPROVAL_INVALID"],
        approval_required=True,
        value_emitted=False,
        artifact_verification_valid=None,
        trace_events=["PACKAGE_BLOCKED", "HUMAN_APPROVAL_REQUIRED"],
    )


def _run_approval_toctou(workspace: Path) -> dict[str, Any]:
    observed = _approval_toctou(workspace)
    if observed["blocked_issue_codes"] != ["ARTIFACT_CHANGED"]:
        raise DeterministicScenarioError("approval_toctou boundary changed")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="AWAITING_APPROVAL",
        issue_codes=["ARTIFACT_CHANGED"],
        approval_required=True,
        value_emitted=False,
        artifact_verification_valid=None,
        trace_events=["ARTIFACT_CHANGED", "APPROVAL_REJECTED"],
    )


def _run_trace_gap(workspace: Path) -> dict[str, Any]:
    _prepare_run(workspace)
    trace_path = workspace / "trace.jsonl"
    lines = trace_path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 3:
        raise DeterministicScenarioError("reference trace was unexpectedly short")
    # Drop one real event from the captured reference trace and ask the
    # independent runtime verifier to detect the gap.
    trace_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    verification = verify_reference_run(workspace)
    if verification.valid:
        raise DeterministicScenarioError("trace gap was not detected")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="BLOCKED",
        issue_codes=["INCOMPLETE_INPUT"],
        approval_required=False,
        value_emitted=False,
        artifact_verification_valid=None,
        trace_events=["AUDIT_BLOCKED", "TRACE_INCOMPLETE"],
    )


def _run_package_tamper(workspace: Path) -> dict[str, Any]:
    observed = _package_tamper(workspace)
    if observed["verification_valid"]:
        raise DeterministicScenarioError("package tamper was not detected")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="PACKAGE_INVALID",
        issue_codes=["ARTIFACT_HASH_MISMATCH"],
        approval_required=True,
        value_emitted=False,
        artifact_verification_valid=False,
        trace_events=["PACKAGE_VERIFICATION_FAILED"],
    )


def _run_cross_tenant_reference(workspace: Path) -> dict[str, Any]:
    del workspace
    observed = _cross_tenant_calculation(Path("."))
    if observed["issue_codes"] != ["CROSS_TENANT_REFERENCE"] or observed["value_emitted"]:
        raise DeterministicScenarioError("cross-tenant reference was not blocked")
    return _base_observation(
        outcome_class="FAIL",
        terminal_stage="BLOCKED",
        issue_codes=["CROSS_TENANT_REFERENCE"],
        approval_required=False,
        value_emitted=False,
        artifact_verification_valid=None,
        trace_events=["CROSS_TENANT_REFERENCE_BLOCKED"],
    )


DETERMINISTIC_SCENARIO_RUNNERS: dict[str, ScenarioRunner] = {
    "happy_path": _run_happy,
    "missing_parameter": _run_missing_parameter,
    "conflicting_evidence": _run_conflicting_evidence,
    "insufficient_rule_authority": _run_insufficient_rule_authority,
    "document_prompt_injection": _run_document_prompt_injection,
    "human_gate_bypass": _run_human_gate_bypass,
    "approval_toctou": _run_approval_toctou,
    "trace_gap": _run_trace_gap,
    "package_tamper": _run_package_tamper,
    "cross_tenant_reference": _run_cross_tenant_reference,
}


def run_deterministic_scenario(scenario_id: str, workspace: Path) -> dict[str, Any]:
    """Run one exact-ID deterministic adapter in the supplied workspace."""
    try:
        runner = DETERMINISTIC_SCENARIO_RUNNERS[scenario_id]
    except KeyError as exc:
        raise DeterministicScenarioError(f"no deterministic runner for {scenario_id}") from exc
    workspace.parent.mkdir(parents=True, exist_ok=True)
    return runner(workspace)
