import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from proofflow.canonical import sha256_digest
from proofflow.contracts import ApprovalExecuteOutput, DocumentPackageOutput
from proofflow.models import (
    ApprovalDecision,
    ApprovalRecord,
    CaseState,
    DataClassification,
    PackageManifest,
)
from proofflow.reference_runtime import (
    ReferenceRunBlocked,
    ReferenceRunError,
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


@pytest.mark.parametrize(
    ("field", "value", "approver_role"),
    [
        ("request_id", "approval-request-forged", "legal-reviewer"),
        ("required_role", "observer", "observer"),
        ("audit_report_ref", "AuditReport:forged", "legal-reviewer"),
        ("artifact_ref", "ApprovalSubject:forged", "legal-reviewer"),
        ("created_at", "2026-08-20T03:59:00Z", "legal-reviewer"),
        ("expires_at", "2026-08-23T04:00:00Z", "legal-reviewer"),
    ],
)
def test_pending_approval_request_policy_cannot_be_tampered(
    tmp_path: Path,
    field: str,
    value: str,
    approver_role: str,
) -> None:
    run_dir = prepare(tmp_path)
    request_path = run_dir / "artifacts/approval-request.json"
    request = json.loads(request_path.read_text())
    request[field] = value
    request_path.write_text(json.dumps(request), encoding="utf-8")

    with pytest.raises(ReferenceRunError, match="approval request binding mismatch"):
        approve_reference_run(
            run_dir=run_dir,
            approver_id="synthetic-reviewer",
            approver_role=approver_role,
            decision=ApprovalDecision.APPROVE,
            reason="A modified approval request must fail closed.",
            now=NOW + timedelta(minutes=1),
        )

    state = json.loads((run_dir / "run-state.json").read_text())
    assert state["stage"] == CaseState.AWAITING_APPROVAL
    assert not (run_dir / "artifacts/approval-record.json").exists()


@pytest.mark.parametrize(
    "relative_path",
    [
        "input/manifest.json",
        "artifacts/timeline.json",
        "skill-results.json",
        "trace.jsonl",
    ],
)
def test_approval_subject_binds_manifest_timeline_results_and_trace(
    tmp_path: Path,
    relative_path: str,
) -> None:
    run_dir = prepare(tmp_path)
    path = run_dir / relative_path
    if relative_path == "input/manifest.json":
        payload = json.loads(path.read_text())
        payload["disclaimer"] += " TAMPERED"
        path.write_text(json.dumps(payload), encoding="utf-8")
    elif relative_path == "artifacts/timeline.json":
        payload = json.loads(path.read_text())
        payload[0]["description"] += " TAMPERED"
        path.write_text(json.dumps(payload), encoding="utf-8")
    elif relative_path == "skill-results.json":
        payload = json.loads(path.read_text())
        payload[0]["status"] = "BLOCKED"
        path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        events = [json.loads(line) for line in path.read_text().splitlines()]
        events[0]["status"] = "BLOCKED"
        path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

    with pytest.raises(ReferenceRunBlocked, match="ARTIFACT_CHANGED"):
        approve(run_dir)


def test_package_rejects_tampered_approval_request_after_approval(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    request_path = run_dir / "artifacts/approval-request.json"
    request = json.loads(request_path.read_text())
    request["audit_report_ref"] = "AuditReport:forged"
    request_path.write_text(json.dumps(request), encoding="utf-8")

    with pytest.raises(ReferenceRunError, match="approval request binding mismatch"):
        package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))


def test_verify_rejects_tampered_approval_request_after_package(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    request_path = run_dir / "artifacts/approval-request.json"
    request = json.loads(request_path.read_text())
    request["required_role"] = "observer"
    request_path.write_text(json.dumps(request), encoding="utf-8")

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "approval request does not match deterministic policy" in report.errors


def test_resealed_approval_record_cannot_change_required_role(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    record_path = run_dir / "artifacts/approval-record.json"
    record = ApprovalRecord.model_validate_json(record_path.read_text())
    forged = record.model_copy(update={"approver_role": "observer"}).seal()
    record_path.write_text(forged.model_dump_json(), encoding="utf-8")

    with pytest.raises(ReferenceRunError, match="approval record binding mismatch"):
        package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))


@pytest.mark.parametrize(
    ("approver_id", "reason"),
    [
        ("", "Reviewed the synthetic record."),
        ("synthetic-reviewer", ""),
    ],
)
def test_approval_requires_non_empty_actor_and_reason(
    tmp_path: Path,
    approver_id: str,
    reason: str,
) -> None:
    run_dir = prepare(tmp_path)

    with pytest.raises(ValueError):
        approve_reference_run(
            run_dir=run_dir,
            approver_id=approver_id,
            approver_role="legal-reviewer",
            decision=ApprovalDecision.APPROVE,
            reason=reason,
            now=NOW + timedelta(minutes=1),
        )


@pytest.mark.parametrize("escaped_path", ["../outside-trace.jsonl", "/tmp/outside-trace.jsonl"])
def test_run_state_paths_cannot_escape_run_directory(
    tmp_path: Path,
    escaped_path: str,
) -> None:
    run_dir = prepare(tmp_path)
    state_path = run_dir / "run-state.json"
    state = json.loads(state_path.read_text())
    state["artifact_paths"]["trace"] = escaped_path
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ReferenceRunError, match="unsafe run artifact path"):
        approve(run_dir)


def test_run_state_paths_cannot_follow_outside_symlink(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "trace.jsonl").write_text("must-not-be-overwritten", encoding="utf-8")
    (run_dir / "escape").symlink_to(outside, target_is_directory=True)
    state_path = run_dir / "run-state.json"
    state = json.loads(state_path.read_text())
    state["artifact_paths"]["trace"] = "escape/trace.jsonl"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ReferenceRunError, match="escapes run directory"):
        approve(run_dir)

    assert (outside / "trace.jsonl").read_text() == "must-not-be-overwritten"


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("status", "BLOCKED", "approval trace event is not a clean success"),
        ("error_code", "FORGED", "approval trace event is not a clean success"),
        ("occurred_at", "2026-08-20T05:00:00Z", "approval trace time does not match"),
        ("input_hash", "sha256:" + "0" * 64, "approval trace input does not match"),
    ],
)
def test_verify_rejects_tampered_human_approval_trace(
    tmp_path: Path,
    field: str,
    value: str,
    expected_error: str,
) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    event = next(item for item in events if item["event_type"] == "skill.human_approval")
    event[field] = value
    trace_path.write_text(
        "\n".join(json.dumps(item) for item in events) + "\n",
        encoding="utf-8",
    )

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert any(expected_error in error for error in report.errors)


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("actor_identity", "PF-A6", "package trace actor mismatch"),
        ("status", "BLOCKED", "package trace event is not a clean success"),
        ("occurred_at", "2026-08-20T05:00:00Z", "package trace time does not match"),
        ("output_hash", "sha256:" + "0" * 64, "package trace output does not match"),
    ],
)
def test_verify_rejects_tampered_package_trace(
    tmp_path: Path,
    field: str,
    value: str,
    expected_error: str,
) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    event = next(item for item in events if item["event_type"] == "skill.document_package")
    event[field] = value
    trace_path.write_text(
        "\n".join(json.dumps(item) for item in events) + "\n",
        encoding="utf-8",
    )

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert any(expected_error in error for error in report.errors)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", CaseState.APPROVED),
        ("status", "PRODUCTION_READY_WITH_AGENTTEAMS"),
        ("agentteams_integrated", True),
        ("external_side_effects_enabled", True),
    ],
)
def test_reference_run_state_cannot_claim_unverified_capabilities(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    run_dir = prepare(tmp_path)
    state_path = run_dir / "run-state.json"
    state = json.loads(state_path.read_text())
    state[field] = value
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ReferenceRunError, match="run state is missing or invalid"):
        verify_reference_run(run_dir)


def test_verify_rejects_unknown_post_approval_trace_event(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    insertion_index = next(
        index
        for index, event in enumerate(events)
        if event["event_type"] == "skill.document_package"
    )
    events.insert(
        insertion_index,
        {
            "sequence": 0,
            "trace_id": events[0]["trace_id"],
            "tenant_id": events[0]["tenant_id"],
            "case_id": events[0]["case_id"],
            "actor_identity": "SYSTEM",
            "actor_kind": "SYSTEM",
            "event_type": "unaccounted.post_approval_side_effect",
            "input_hash": None,
            "output_hash": None,
            "status": "SUCCESS",
            "occurred_at": "2026-08-20T04:01:30Z",
            "error_code": None,
        },
    )
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
    trace_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "trace event sequence or actor contract mismatch" in report.errors


def test_approval_time_cannot_precede_request_creation(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)

    with pytest.raises(ReferenceRunError, match="approval time cannot precede"):
        approve_reference_run(
            run_dir=run_dir,
            approver_id="synthetic-reviewer",
            approver_role="legal-reviewer",
            decision=ApprovalDecision.APPROVE,
            reason="A decision cannot be recorded before its request exists.",
            now=NOW - timedelta(seconds=1),
        )


def test_package_time_cannot_precede_approval(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)

    with pytest.raises(ReferenceRunError, match="package time cannot precede"):
        package_reference_run(run_dir=run_dir, now=NOW + timedelta(seconds=30))

    assert not (run_dir / "package").exists()


def test_verify_rejects_nonmonotonic_trace_timestamps(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    approval_transition = next(
        event
        for index, event in enumerate(events)
        if event["event_type"] == "case.state_transition"
        and index > 0
        and events[index - 1]["event_type"] == "skill.human_approval"
    )
    approval_transition["occurred_at"] = "2026-08-20T03:59:59Z"
    trace_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "trace timestamps are not monotonic" in report.errors


@pytest.mark.parametrize(
    ("decision", "expected_stage"),
    [
        (ApprovalDecision.REJECT, CaseState.REJECTED),
        (ApprovalDecision.REVISE, CaseState.REVISION_REQUIRED),
    ],
)
def test_non_approve_decisions_have_a_verified_terminal_stage(
    tmp_path: Path,
    decision: ApprovalDecision,
    expected_stage: CaseState,
) -> None:
    run_dir = prepare(tmp_path)
    approve_reference_run(
        run_dir=run_dir,
        approver_id="synthetic-reviewer",
        approver_role="legal-reviewer",
        decision=decision,
        reason="The synthetic record is not approved for packaging.",
        now=NOW + timedelta(minutes=1),
    )

    state = json.loads((run_dir / "run-state.json").read_text())
    report = verify_reference_run(run_dir)

    assert state["stage"] == expected_stage
    assert report.valid, report.errors


def test_verify_rejects_resealed_decision_stage_mismatch(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    record_path = run_dir / "artifacts/approval-record.json"
    record = ApprovalRecord.model_validate_json(record_path.read_text())
    forged = record.model_copy(update={"decision": ApprovalDecision.REJECT}).seal()
    record_path.write_text(forged.model_dump_json(), encoding="utf-8")
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    approval_event = next(
        event for event in events if event["event_type"] == "skill.human_approval"
    )
    approval_event["output_hash"] = sha256_digest(ApprovalExecuteOutput(record=forged))
    trace_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "approval decision does not match the current stage" in report.errors


def test_package_fails_closed_on_damaged_approval_trace(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    approval_event = next(
        event for event in events if event["event_type"] == "skill.human_approval"
    )
    approval_event["actor_identity"] = "forged-reviewer"
    trace_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ReferenceRunError, match="pre-package trace integrity failed"):
        package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))

    assert not (run_dir / "package").exists()


def test_verify_rejects_resealed_package_manifest_semantic_mismatch(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    manifest_path = run_dir / "package/package-manifest.json"
    manifest = PackageManifest.model_validate_json(manifest_path.read_text())
    forged = manifest.model_copy(
        update={"included_artifact_refs": (*manifest.included_artifact_refs, "Evidence:forged")}
    ).seal()
    manifest_path.write_text(forged.model_dump_json(), encoding="utf-8")
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    package_event = next(
        event for event in events if event["event_type"] == "skill.document_package"
    )
    package_event["output_hash"] = sha256_digest(
        DocumentPackageOutput(
            manifest=forged,
            draft_markdown=(run_dir / "package/review-draft.md").read_text(),
            artifacts_json=(run_dir / "package/artifacts.json").read_text(),
        )
    )
    trace_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "package manifest included references mismatch" in report.errors


def test_package_manifest_is_rejected_outside_packaged_stage(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    state_path = run_dir / "run-state.json"
    state = json.loads(state_path.read_text())
    state["stage"] = CaseState.APPROVED
    state["case"]["state"] = CaseState.APPROVED
    state["case"]["state_version"] -= 1
    state["updated_at"] = (NOW + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    state_path.write_text(json.dumps(state), encoding="utf-8")
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()][:-2]
    trace_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "package manifest is only valid for PACKAGED state" in report.errors


def test_run_state_update_time_cannot_precede_creation(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    state_path = run_dir / "run-state.json"
    state = json.loads(state_path.read_text())
    state["updated_at"] = (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ReferenceRunError, match="run state is missing or invalid"):
        verify_reference_run(run_dir)


def test_verify_binds_run_creation_to_the_first_trace_event(tmp_path: Path) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))
    state_path = run_dir / "run-state.json"
    state = json.loads(state_path.read_text())
    state["created_at"] = (NOW + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    state_path.write_text(json.dumps(state), encoding="utf-8")

    report = verify_reference_run(run_dir)

    assert not report.valid
    assert "run creation time does not match the first trace event" in report.errors


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_id", "approval-forged"),
        ("classification", DataClassification.INTERNAL),
        ("schema_version", "9.9.9"),
    ],
)
def test_package_rejects_resealed_approval_metadata(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    run_dir = prepare(tmp_path)
    approve(run_dir)
    record_path = run_dir / "artifacts/approval-record.json"
    record = ApprovalRecord.model_validate_json(record_path.read_text())
    forged = record.model_copy(
        update={"meta": record.meta.model_copy(update={field: value})}
    ).seal()
    record_path.write_text(forged.model_dump_json(), encoding="utf-8")
    trace_path = run_dir / "trace.jsonl"
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    approval_event = next(
        event for event in events if event["event_type"] == "skill.human_approval"
    )
    approval_event["output_hash"] = sha256_digest(ApprovalExecuteOutput(record=forged))
    trace_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ReferenceRunError, match="approval record binding mismatch"):
        package_reference_run(run_dir=run_dir, now=NOW + timedelta(minutes=2))

    assert not (run_dir / "package").exists()
