from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest

from scripts.semifinal_submission import (
    MANIFEST_NAME,
    STATUS_CANDIDATE,
    SubmissionBuildError,
    _collect_artifacts,
    _gate,
    _normalize_config,
    _scan_bytes,
    build_package,
    validate_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "submission/semifinal/submission-config.json"


def _build(tmp_path: Path, *, mode: str = "candidate") -> tuple[Path, dict]:
    output = tmp_path / "candidate.zip"
    report = build_package(config_path=CONFIG, output=output, mode=mode)
    return output, report


def test_candidate_build_is_deterministic_and_manifest_valid(tmp_path: Path) -> None:
    first, first_report = _build(tmp_path / "one")
    second, second_report = _build(tmp_path / "two")
    assert first.read_bytes() == second.read_bytes()
    assert first_report["artifact_status"] == STATUS_CANDIDATE
    assert second_report["zip_sha256"] == first_report["zip_sha256"]
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert MANIFEST_NAME in names
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_bytes(archive.read(MANIFEST_NAME))
    assert validate_manifest(manifest_path) == []


def test_candidate_gate_lists_all_current_missing_proofs(tmp_path: Path) -> None:
    _, report = _build(tmp_path)
    assert report["artifact_status"] == STATUS_CANDIDATE
    assert {
        "demo_url_missing",
        "eligibility_not_unlocked",
        "real_agent_collaboration_evidence_missing",
        "official_dynamic_config_not_rechecked",
        "agent_collaboration_evidence_artifact_missing",
    }.issubset(report["gate"]["reasons"])


def test_submit_ready_never_passes_without_gates(tmp_path: Path) -> None:
    output = tmp_path / "submit-ready.zip"
    report = build_package(config_path=CONFIG, output=output, mode="submit-ready")
    assert report["artifact_status"] == STATUS_CANDIDATE


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("demo_url", "", "public HTTPS URL"),
        ("repository_url", "http://example.com", "public HTTPS URL"),
    ],
)
def test_bad_public_urls_fail_closed(tmp_path: Path, key: str, value: str, message: str) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config[key] = value
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(SubmissionBuildError, match=message):
        _normalize_config(config)


def test_modified_or_untracked_drift_is_rejected(tmp_path: Path) -> None:
    drift = ROOT / "submission/semifinal/.drift-test"
    try:
        drift.write_text("not for release", encoding="utf-8")
        with pytest.raises(SubmissionBuildError, match="worktree is not clean"):
            build_package(config_path=CONFIG, output=tmp_path / "drift.zip")
    finally:
        drift.unlink(missing_ok=True)


def test_symlink_and_private_allowlist_are_rejected(tmp_path: Path) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["allowlist"] = ["submission/private/nope.txt"]
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(SubmissionBuildError, match="private/cache path"):
        _normalize_config(config)


def test_context_mapping_must_use_official_four_options(tmp_path: Path) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["context_mapping"]["selected"] = ["rag", "agent_memory"]
    with pytest.raises(SubmissionBuildError, match="shared_state"):
        _normalize_config(config)


def test_true_flags_without_bound_evidence_remain_candidate(tmp_path: Path) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config.update(
        {
            "demo_url": "https://demo.example.invalid/proofflow",
            "eligibility_unlocked": True,
            "real_agent_collaboration_evidence": True,
            "official_config_rechecked": True,
        }
    )
    config["gate_evidence"]["official_config_recheck"]["observed_at"] = datetime.now(
        UTC
    ).isoformat()
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps(config), encoding="utf-8")
    normalized = _normalize_config(config)
    artifacts = _collect_artifacts(ROOT, normalized)
    gate = _gate(ROOT, normalized, artifacts, "submit-ready")
    assert gate.status == STATUS_CANDIDATE
    assert "eligibility_not_unlocked" in gate.reasons
    assert "real_agent_collaboration_evidence_missing" in gate.reasons


def test_stale_recheck_is_not_fresh(tmp_path: Path) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["official_config_rechecked"] = True
    config["gate_evidence"]["official_config_recheck"]["observed_at"] = (
        datetime.now(UTC) - timedelta(hours=25)
    ).isoformat()
    normalized = _normalize_config(config)
    artifacts = _collect_artifacts(ROOT, normalized)
    gate = _gate(ROOT, normalized, artifacts, "submit-ready")
    assert "official_dynamic_config_not_rechecked" in gate.reasons


def test_future_and_huge_recheck_values_fail_closed() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["gate_evidence"]["official_config_recheck"].update(
        {"observed_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(), "max_age_hours": 25}
    )
    with pytest.raises(SubmissionBuildError, match="between 1 and 24"):
        _normalize_config(config)


def test_pptx_member_pii_is_scanned() -> None:
    payload = BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("ppt/slides/slide1.xml", "synthetic@example.com")
    with pytest.raises(SubmissionBuildError, match="PII-like"):
        _scan_bytes("fake.pptx", payload.getvalue())


def test_manifest_inventory_tampering_is_rejected(tmp_path: Path) -> None:
    output, _ = _build(tmp_path)
    with zipfile.ZipFile(output) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    manifest["artifact_inventory"][0]["sha256"] = "sha256:" + "f" * 64
    forged = tmp_path / "forged-manifest.json"
    forged.write_text(json.dumps(manifest), encoding="utf-8")
    assert any(
        "subject binding digest mismatch" in message for message in validate_manifest(forged)
    )


def test_strict_json_rejects_duplicate_keys_and_non_finite(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"project":"ProofFlow","project":"forged"}', encoding="utf-8")
    with pytest.raises(SubmissionBuildError, match="duplicate JSON key"):
        from scripts.semifinal_submission import load_config

        load_config(duplicate)
    non_finite = tmp_path / "nan.json"
    non_finite.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(SubmissionBuildError, match="non-finite"):
        from scripts.semifinal_submission import load_config

        load_config(non_finite)
