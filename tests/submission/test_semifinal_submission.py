from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from proofflow.semifinal_submission import (
    MANIFEST_NAME,
    STATUS_CANDIDATE,
    SubmissionBuildError,
    _normalize_config,
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
