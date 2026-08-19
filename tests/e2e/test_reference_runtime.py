import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from proofflow.models import ApprovalDecision, CaseState
from proofflow.reference_runtime import (
    ReferenceRunBlocked,
    approve_reference_run,
    package_reference_run,
    prepare_reference_run,
    verify_reference_run,
)

ROOT = Path(__file__).parents[2]
MANIFEST = ROOT / "examples/cases/happy_path/manifest.json"
RULES = ROOT / "data/rules/cn_labor_contract_law.catalog.json"
NOW = datetime(2026, 8, 20, 4, 0, tzinfo=UTC)


def prepare(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    state = prepare_reference_run(
        manifest_path=MANIFEST,
        rule_catalog_path=RULES,
        run_dir=run_dir,
        now=NOW,
    )
    assert state.stage == CaseState.AWAITING_APPROVAL
    assert not state.agentteams_integrated
    return run_dir


def approve(run_dir: Path) -> None:
    approve_reference_run(
        run_dir=run_dir,
        approver_id="synthetic-reviewer",
        approver_role="legal-reviewer",
        decision=ApprovalDecision.APPROVE,
        reason="Reviewed the synthetic evidence, rules, calculation, risks, and uncertainties.",
        now=NOW + timedelta(minutes=1),
    )


def test_happy_path_reaches_packaged_with_verified_manifest(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))

    report = verify_reference_run(run_dir)
    state = json.loads((run_dir / "run-state.json").read_text())

    assert report.valid
    assert report.checked_artifacts >= 20
    assert report.checked_package_files == 2
    assert state["stage"] == CaseState.PACKAGED
    assert (run_dir / "package/review-draft.md").is_file()
    assert (run_dir / "trace.jsonl").read_text().count("\n") >= 17


def test_wrong_human_role_cannot_approve(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)

    with pytest.raises(ReferenceRunBlocked, match="UNAUTHORIZED_APPROVER"):
        approve_reference_run(
            run_dir=run_dir,
            approver_id="synthetic-reviewer",
            approver_role="observer",
            decision=ApprovalDecision.APPROVE,
            reason="Wrong role should not pass.",
            now=NOW + timedelta(minutes=1),
        )

    state = json.loads((run_dir / "run-state.json").read_text())
    assert state["stage"] == CaseState.AWAITING_APPROVAL
    assert not (run_dir / "artifacts/approval-record.json").exists()


def test_artifact_change_invalidates_pending_approval(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    proposal_path = run_dir / "artifacts/proposals.json"
    proposals = json.loads(proposal_path.read_text())
    proposals[0]["summary"] += " TAMPERED"
    proposal_path.write_text(json.dumps(proposals), encoding="utf-8")

    with pytest.raises(ReferenceRunBlocked, match="ARTIFACT_CHANGED"):
        approve(run_dir)


def test_package_file_tampering_is_detected(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    draft = run_dir / "package/review-draft.md"
    draft.write_text(draft.read_text() + "\nTAMPERED", encoding="utf-8")

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "package file hash mismatch: review-draft.md" in report.errors
