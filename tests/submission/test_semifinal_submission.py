from __future__ import annotations

import inspect
import json
import stat
import subprocess
import sys
import zipfile
from copy import deepcopy
from io import BytesIO
from pathlib import Path

import pytest

from scripts.semifinal_submission import (
    MANIFEST_NAME,
    STATUS_CANDIDATE,
    Artifact,
    SubmissionBuildError,
    _canonical_json,
    _collect_artifacts,
    _gate,
    _load_bound_evidence,
    _load_trusted_blobs,
    _normalize_config,
    _scan_bytes,
    _subject_binding_payload,
    build_package,
    commit_pinned_trust_digests,
    load_config,
    sha256_bytes,
    validate_manifest,
    validate_zip,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "submission/semifinal/submission-config.json"
ELIGIBILITY_SCHEMA = ROOT / "schemas/semifinal-eligibility-evidence.schema.json"


def _config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _build(tmp_path: Path, *, mode: str = "candidate") -> tuple[Path, dict]:
    output = tmp_path / "candidate.zip"
    report = build_package(config_path=CONFIG, output=output, mode=mode)
    return output, report


@pytest.fixture(scope="module")
def trust_context() -> tuple[str, dict[str, str]]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    return commit, commit_pinned_trust_digests(ROOT, commit)


def _validate_zip(
    path: Path,
    trust_context: tuple[str, dict[str, str]],
    *,
    smoke: bool = False,
) -> list[str]:
    commit, digests = trust_context
    return validate_zip(
        path,
        expected_repository_commit=commit,
        trusted_root=ROOT,
        trusted_file_digests=digests,
        run_extracted_smoke=smoke,
    )


@pytest.fixture(scope="module")
def candidate_package(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    return _build(tmp_path_factory.mktemp("semifinal-candidate"))


def _zip_info(name: str, *, symlink: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    mode = (stat.S_IFLNK | 0o777) if symlink else (stat.S_IFREG | 0o644)
    info.external_attr = mode << 16
    info.flag_bits = 0x800
    return info


def _mutate_zip(
    source: Path,
    destination: Path,
    *,
    replace: dict[str, bytes] | None = None,
    omit: set[str] | None = None,
    extras: list[tuple[str, bytes, bool]] | None = None,
) -> None:
    replace = replace or {}
    omit = omit or set()
    extras = extras or []
    with (
        zipfile.ZipFile(source) as original,
        zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as forged,
    ):
        for name in original.namelist():
            if name in omit:
                continue
            forged.writestr(_zip_info(name), replace.get(name, original.read(name)))
        for name, data, symlink in extras:
            forged.writestr(_zip_info(name, symlink=symlink), data)


def _reseal_manifest(manifest: dict) -> bytes:
    manifest["integrity"]["subject_binding_sha256"] = sha256_bytes(
        _canonical_json(_subject_binding_payload(manifest))
    )
    return _canonical_json(manifest)


def _minimal_fake_pptx() -> bytes:
    payload = BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("_rels/.rels", "<Relationships/>")
        archive.writestr("ppt/presentation.xml", "<presentation/>")
    return payload.getvalue()


def test_candidate_build_is_deterministic_and_full_zip_valid(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    first, first_report = candidate_package
    second, second_report = _build(tmp_path / "two")
    assert first.read_bytes() == second.read_bytes()
    assert first_report["artifact_status"] == STATUS_CANDIDATE
    assert second_report["zip_sha256"] == first_report["zip_sha256"]
    assert _validate_zip(first, trust_context, smoke=True) == []
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_bytes(archive.read(MANIFEST_NAME))
        assert "benchmarks/suite.py" in names
        assert "tests/e2e/test_demo_server.py" in names
        assert "deploy/tool-service/README.md" in names
    assert validate_manifest(manifest_path) == []


def test_authoritative_zip_validator_requires_external_commit_pinned_trust() -> None:
    parameters = inspect.signature(validate_zip).parameters
    assert parameters["expected_repository_commit"].default is inspect.Signature.empty
    assert parameters["trusted_root"].default is inspect.Signature.empty
    assert parameters["trusted_file_digests"].default is inspect.Signature.empty


def test_candidate_gate_discloses_every_real_submission_blocker(
    candidate_package: tuple[Path, dict],
) -> None:
    _, report = candidate_package
    assert report["artifact_status"] == STATUS_CANDIDATE
    assert {
        "demo_url_missing",
        "eligibility_evidence_missing_or_stale",
        "official_dynamic_config_evidence_missing_stale_or_mismatched",
        "public_demo_access_evidence_missing_stale_or_mismatched",
        "real_agent_collaboration_evidence_missing",
        "evaluation_v2_verifier_missing",
        "agent_collaboration_evidence_artifact_missing",
    }.issubset(report["gate"]["reasons"])


def test_submit_ready_mode_remains_candidate_without_portal_evidence(tmp_path: Path) -> None:
    output = tmp_path / "submit-ready.zip"
    report = build_package(config_path=CONFIG, output=output, mode="submit-ready")
    assert report["artifact_status"] == STATUS_CANDIDATE
    assert "eligibility_evidence_missing_or_stale" in report["gate"]["reasons"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("demo_url", ""),
        ("repository_url", "http://example.com"),
        ("demo_url", "https://demo.example.invalid/proofflow"),
    ],
)
def test_bad_or_reserved_public_urls_fail_closed(key: str, value: str) -> None:
    config = _config()
    config[key] = value
    with pytest.raises(SubmissionBuildError, match=r"schema validation|public HTTPS URL"):
        _normalize_config(config)


def test_legacy_self_declared_flags_and_counts_are_schema_rejected() -> None:
    config = _config()
    config["eligibility_unlocked"] = True
    config["real_agent_collaboration_evidence"] = True
    config["official_config_rechecked"] = True
    config["gate_evidence"]["real_agent_collaboration"]["counts"] = {
        "worker_execution": 999,
        "task_event": 999,
    }
    with pytest.raises(SubmissionBuildError, match="schema validation"):
        _normalize_config(config)


def test_three_field_fake_evidence_cannot_satisfy_dedicated_schema(tmp_path: Path) -> None:
    evidence = tmp_path / "fake.json"
    data = json.dumps(
        {
            "schema_version": "forged/v1",
            "evidence_type": "authenticated_portal_eligibility",
            "status": "UNLOCKED",
        }
    ).encode()
    evidence.write_bytes(data)
    ref = {"path": "fake.json", "sha256": sha256_bytes(data)}
    artifacts = (
        Artifact(
            path="fake.json",
            category="eligibility_evidence",
            size_bytes=len(data),
            sha256=sha256_bytes(data),
        ),
    )
    with pytest.raises(SubmissionBuildError, match="schema validation"):
        _load_bound_evidence(
            tmp_path,
            ref,
            category="eligibility_evidence",
            artifacts=artifacts,
            schema_path=ELIGIBILITY_SCHEMA,
        )


@pytest.mark.parametrize(
    ("category", "target"),
    [
        ("agentteams_workers", "deploy/agentteams/01-workers-stopped.yaml"),
        ("agentteams_mcp", "deploy/agentteams/mcp/mcp-proof-calc.yaml"),
        ("agentteams_skills", "deploy/agentteams/skills/conflict_detect/SKILL.md"),
        ("tool_service", "deploy/tool-service/Dockerfile"),
        ("demo_benchmarks", "benchmarks/suite.py"),
    ],
)
def test_deleting_fixed_runtime_artifact_is_rejected(category: str, target: str) -> None:
    config = _config()
    config["required_artifacts"][category].remove(target)
    config["allowlist"].remove(target)
    with pytest.raises(SubmissionBuildError, match=r"schema validation|fixed release contract"):
        _normalize_config(config)


def test_deck_categories_require_real_extensions() -> None:
    config = _config()
    config["required_artifacts"]["deck_pptx"] = ["submission/public/README.md"]
    config["required_artifacts"]["deck_pdf"] = ["NOTICE"]
    with pytest.raises(SubmissionBuildError, match=r"exactly one \.pptx"):
        _normalize_config(config)


def test_invalid_official_date_is_rejected_by_format_checker() -> None:
    config = _config()
    config["official"]["snapshot"]["opens_at"] = "NOT-A-DATE"
    with pytest.raises(SubmissionBuildError, match="date-time"):
        _normalize_config(config)


def test_modified_or_untracked_drift_is_rejected(tmp_path: Path) -> None:
    drift = ROOT / "submission/semifinal/.drift-test"
    try:
        drift.write_text("not for release", encoding="utf-8")
        with pytest.raises(SubmissionBuildError, match="worktree is not clean"):
            build_package(config_path=CONFIG, output=tmp_path / "drift.zip")
    finally:
        drift.unlink(missing_ok=True)


def test_generated_invalid_manifest_aborts_before_writing_zip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.semifinal_submission as semifinal

    original = semifinal.build_manifest

    def forged_manifest(**kwargs: object) -> dict:
        manifest = original(**kwargs)  # type: ignore[arg-type]
        manifest["unexpected"] = True
        return manifest

    monkeypatch.setattr(semifinal, "build_manifest", forged_manifest)
    output = tmp_path / "must-not-exist.zip"
    with pytest.raises(SubmissionBuildError, match="generated manifest failed validation"):
        build_package(config_path=CONFIG, output=output)
    assert not output.exists()


def test_private_allowlist_is_rejected() -> None:
    config = _config()
    config["allowlist"] = ["submission/private/nope.txt"]
    with pytest.raises(SubmissionBuildError, match=r"schema validation|private/cache path"):
        _normalize_config(config)


def test_context_mapping_must_use_official_four_options() -> None:
    config = _config()
    config["context_mapping"]["selected"] = ["rag", "agent_memory"]
    with pytest.raises(SubmissionBuildError, match=r"schema validation|shared_state"):
        _normalize_config(config)


def test_pptx_xml_member_pii_and_fake_documents_are_rejected() -> None:
    payload = BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("_rels/.rels", "<Relationships/>")
        archive.writestr("ppt/presentation.xml", "<presentation/>")
        archive.writestr("ppt/slides/slide1.xml", "<text>synthetic@example.com</text>")
    with pytest.raises(SubmissionBuildError, match="PII-like"):
        _scan_bytes("fake.pptx", payload.getvalue())
    with pytest.raises(SubmissionBuildError, match="invalid office container"):
        _scan_bytes("renamed.pptx", b"not a presentation")
    with pytest.raises(SubmissionBuildError, match="invalid PDF"):
        _scan_bytes("renamed.pdf", b"not a PDF")


def test_structural_pptx_stub_must_render_with_soffice() -> None:
    with pytest.raises(SubmissionBuildError, match="PPTX failed soffice headless conversion"):
        _scan_bytes("structural-stub.pptx", _minimal_fake_pptx())


def test_manifest_inventory_tampering_is_rejected(
    tmp_path: Path, candidate_package: tuple[Path, dict]
) -> None:
    output, _ = candidate_package
    with zipfile.ZipFile(output) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    manifest["artifact_inventory"][0]["sha256"] = "sha256:" + "f" * 64
    forged = tmp_path / "forged-manifest.json"
    forged.write_text(json.dumps(manifest), encoding="utf-8")
    assert any("subject binding digest mismatch" in item for item in validate_manifest(forged))


def test_forged_pre_submit_ready_manifest_without_evidence_is_rejected(
    tmp_path: Path, candidate_package: tuple[Path, dict]
) -> None:
    output, _ = candidate_package
    with zipfile.ZipFile(output) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    manifest["artifact_status"] = "PRE_SUBMIT_READY"
    manifest["gate"]["status"] = "PRE_SUBMIT_READY"
    manifest["gate"]["reasons"] = []
    forged = tmp_path / "forged-ready-manifest.json"
    forged.write_text(json.dumps(manifest), encoding="utf-8")
    errors = validate_manifest(forged)
    assert "gate_evidence: PRE_SUBMIT_READY requires every evidence ref" in errors
    assert "demo_url: PRE_SUBMIT_READY requires a public Demo URL" in errors


def test_zip_validator_reconstructs_gate_instead_of_trusting_readme_refs(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
        readme_digest = sha256_bytes(archive.read("README.md"))
    fake_ref = {"path": "README.md", "sha256": readme_digest}
    manifest["demo_url"] = "https://demo.proofflow.ai"
    manifest["gate_evidence"]["eligibility"]["evidence_ref"] = fake_ref
    manifest["gate_evidence"]["official_config_recheck"]["evidence_ref"] = fake_ref
    manifest["gate_evidence"]["real_agent_collaboration"]["evaluation_ledger_ref"] = fake_ref
    manifest["gate_evidence"]["demo_access"]["evidence_ref"] = fake_ref
    manifest["artifact_status"] = "PRE_SUBMIT_READY"
    manifest["gate"] = {
        "status": "PRE_SUBMIT_READY",
        "reasons": [],
        "warnings": manifest["gate"]["warnings"],
    }
    forged = tmp_path / "readme-ref-ready.zip"
    _mutate_zip(
        original,
        forged,
        replace={MANIFEST_NAME: _reseal_manifest(manifest)},
    )
    errors = _validate_zip(forged, trust_context, smoke=True)
    assert errors
    assert any(
        "disagrees with trusted ZIP bytes/config" in item
        or "independently reconstructed gate" in item
        for item in errors
    )


def test_zip_validator_rejects_packaged_schema_replacement_even_when_resealed(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    schema_path = "schemas/semifinal-submission-manifest.schema.json"
    replacement = b"{}\n"
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    inventory_item = next(
        item for item in manifest["artifact_inventory"] if item["path"] == schema_path
    )
    inventory_item["size_bytes"] = len(replacement)
    inventory_item["sha256"] = sha256_bytes(replacement)
    forged = tmp_path / "empty-schema.zip"
    _mutate_zip(
        original,
        forged,
        replace={
            schema_path: replacement,
            MANIFEST_NAME: _reseal_manifest(manifest),
        },
    )
    errors = _validate_zip(forged, trust_context)
    assert ("commit-pinned trusted file bytes mismatch or missing: " + schema_path) in errors


def test_zip_validator_rejects_resealed_source_commit_substitution(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    manifest["source_commit"] = "0" * 40
    forged = tmp_path / "wrong-source-commit.zip"
    _mutate_zip(
        original,
        forged,
        replace={MANIFEST_NAME: _reseal_manifest(manifest)},
    )
    errors = _validate_zip(forged, trust_context)
    assert "source_commit: external expected commit mismatch" in errors


def test_zip_validator_binds_every_payload_to_the_expected_source_commit(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    replacement = b"resealed but not committed\n"
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    inventory_item = next(
        item for item in manifest["artifact_inventory"] if item["path"] == "README.md"
    )
    inventory_item["size_bytes"] = len(replacement)
    inventory_item["sha256"] = sha256_bytes(replacement)
    forged = tmp_path / "resealed-payload.zip"
    _mutate_zip(
        original,
        forged,
        replace={
            "README.md": replacement,
            MANIFEST_NAME: _reseal_manifest(manifest),
        },
    )
    errors = _validate_zip(forged, trust_context)
    assert "ZIP artifact bytes disagree with expected source commit: README.md" in errors


def test_zip_validator_rejects_resealed_non_renderable_pptx(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    deck_path = "submission/public/ProofFlow_GOAI_复赛答辩_v2.0.pptx"
    replacement = _minimal_fake_pptx()
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    inventory_item = next(
        item for item in manifest["artifact_inventory"] if item["path"] == deck_path
    )
    inventory_item["size_bytes"] = len(replacement)
    inventory_item["sha256"] = sha256_bytes(replacement)
    forged = tmp_path / "structural-stub-deck.zip"
    _mutate_zip(
        original,
        forged,
        replace={
            deck_path: replacement,
            MANIFEST_NAME: _reseal_manifest(manifest),
        },
    )
    errors = _validate_zip(forged, trust_context)
    assert any("PPTX failed soffice headless conversion" in item for item in errors)


def test_zip_validation_is_not_bypassed_by_python_optimization(
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    package, _ = candidate_package
    commit, _ = trust_context
    program = """
import json
import sys
from pathlib import Path
from scripts.semifinal_submission import commit_pinned_trust_digests, validate_zip

root = Path(sys.argv[1])
commit = sys.argv[2]
package = Path(sys.argv[3])
errors = validate_zip(
    package,
    expected_repository_commit=commit,
    trusted_root=root,
    trusted_file_digests=commit_pinned_trust_digests(root, commit),
    run_extracted_smoke=True,
)
print(json.dumps(errors, sort_keys=True))
raise SystemExit(1 if errors else 0)
"""
    completed = subprocess.run(
        [sys.executable, "-O", "-c", program, str(ROOT), commit, str(package)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert completed.stdout.strip() == "[]"


@pytest.mark.parametrize("attack", ["payload", "extra", "missing", "traversal", "symlink"])
def test_final_zip_reopen_rejects_archive_mutations(
    tmp_path: Path,
    attack: str,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    forged = tmp_path / f"{attack}.zip"
    kwargs: dict = {}
    if attack == "payload":
        kwargs["replace"] = {"README.md": b"mutated\n"}
    elif attack == "extra":
        kwargs["extras"] = [("EXTRA.txt", b"extra", False)]
    elif attack == "missing":
        kwargs["omit"] = {"README.md"}
    elif attack == "traversal":
        kwargs["extras"] = [("../escape.txt", b"escape", False)]
    else:
        kwargs["extras"] = [("unsafe-link", b"README.md", True)]
    _mutate_zip(original, forged, **kwargs)
    assert _validate_zip(forged, trust_context)


def test_final_zip_reopen_rejects_duplicate_member(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    forged = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _mutate_zip(original, forged, extras=[("README.md", b"duplicate", False)])
    assert "ZIP contains duplicate entry names" in _validate_zip(forged, trust_context)


def test_final_zip_without_decks_is_rejected(
    tmp_path: Path,
    candidate_package: tuple[Path, dict],
    trust_context: tuple[str, dict[str, str]],
) -> None:
    original, _ = candidate_package
    forged = tmp_path / "no-decks.zip"
    _mutate_zip(
        original,
        forged,
        omit={
            "submission/public/ProofFlow_GOAI_复赛答辩_v2.0.pptx",
            "submission/public/ProofFlow_GOAI_复赛答辩_v2.0.pdf",
        },
    )
    errors = _validate_zip(forged, trust_context)
    assert any("exact config-derived inventory mismatch" in item for item in errors)


def test_strict_json_rejects_duplicate_keys_and_non_finite(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"project":"ProofFlow","project":"forged"}', encoding="utf-8")
    with pytest.raises(SubmissionBuildError, match="duplicate JSON key"):
        load_config(duplicate)
    non_finite = tmp_path / "nan.json"
    non_finite.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(SubmissionBuildError, match="non-finite"):
        load_config(non_finite)


def test_current_gate_cannot_import_unmerged_evaluation_v2(
    trust_context: tuple[str, dict[str, str]],
) -> None:
    config = _normalize_config(_config())
    artifacts = _collect_artifacts(ROOT, config)
    commit, digests = trust_context
    trusted_blobs = _load_trusted_blobs(
        trusted_root=ROOT,
        expected_repository_commit=commit,
        trusted_file_digests=digests,
    )
    gate = _gate(
        ROOT,
        config,
        artifacts,
        "submit-ready",
        expected_repository_commit=commit,
        trusted_blobs=trusted_blobs,
    )
    assert gate.status == STATUS_CANDIDATE
    assert "evaluation_v2_verifier_missing" in gate.reasons


def test_config_copy_does_not_hide_required_categories() -> None:
    config = deepcopy(_config())
    del config["required_artifacts"]["agentteams_skills"]
    with pytest.raises(SubmissionBuildError, match="schema validation"):
        _normalize_config(config)
