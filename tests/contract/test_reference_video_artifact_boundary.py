from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

EVIDENCE = Path(__file__).parents[2] / "reference-video/evidence"
sys.path.insert(0, str(EVIDENCE))

from validate_manifest import (  # noqa: E402
    GIT_UNTRUSTED_ENV,
    git_command,
    git_environment,
    snapshot_artifact_tree,
    stable_read_bytes,
)

VIDEO_ROOT = EVIDENCE.parent
MANIFEST = VIDEO_ROOT / "manifest.json"
SCHEMA = EVIDENCE / "manifest.schema.json"
VALIDATOR = EVIDENCE / "validate_manifest.py"
GIT_BINARY = Path("/usr/bin/git")
OLD_ARTIFACT_COMMIT = "34bbf914b0dcd35d5a3a25519623a234c708bfbc"
OLD_VALIDATOR_SHA256 = "sha256:9286b832252ee59143c0de327fdc489b610c4a6de12fac202ac53c8c8548f642"


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validator_command(*, expected_validator: str, expected_commit: str) -> list[str]:
    return [
        sys.executable,
        "-O",
        str(VALIDATOR),
        "--manifest",
        str(MANIFEST),
        "--video-root",
        str(VIDEO_ROOT),
        "--expected-schema-sha256",
        sha256(SCHEMA),
        "--expected-validator-sha256",
        expected_validator,
        "--expected-artifact-commit",
        expected_commit,
        "--trusted-git-root",
        str(VIDEO_ROOT.parent),
        "--git-binary",
        str(GIT_BINARY),
        "--ffprobe",
        "/usr/local/bin/ffprobe",
        "--ffmpeg",
        "/usr/local/bin/ffmpeg",
        "--tesseract",
        "/usr/local/bin/tesseract",
    ]


def current_artifact_commit() -> str:
    return subprocess.check_output(
        [str(GIT_BINARY), "-C", str(VIDEO_ROOT.parent), "rev-parse", "HEAD"], text=True
    ).strip()


def expect_boundary_error(tmp_path: Path, setup) -> None:
    source = tmp_path / "package"
    source.mkdir()
    setup(source)
    destination = tmp_path / "snapshot"
    destination.mkdir()
    with pytest.raises(ValueError, match=r"(?:symlink|hardlink|special) artifact"):
        snapshot_artifact_tree(source, destination)


def test_current_reference_package_can_be_snapshotted_without_following_links(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "snapshot"
    destination.mkdir()
    snapshot_artifact_tree(VIDEO_ROOT, destination)
    for relative in (
        "manifest.json",
        "evidence/manifest.schema.json",
        "evidence/validate_manifest.py",
        "renders/reference-runtime-evidence.mp4",
    ):
        original = VIDEO_ROOT / relative
        copied = destination / relative
        assert copied.is_file()
        assert copied.read_bytes() == original.read_bytes()
        assert not copied.is_symlink()
        assert copied.stat().st_nlink == 1


def test_package_artifact_symlink_is_rejected(tmp_path: Path) -> None:
    expect_boundary_error(
        tmp_path,
        lambda source: (source / "artifact").symlink_to(source / "outside-target"),
    )


def test_package_directory_symlink_is_rejected(tmp_path: Path) -> None:
    expect_boundary_error(
        tmp_path,
        lambda source: (source / "nested").symlink_to(source, target_is_directory=True),
    )


def test_package_hardlink_is_rejected(tmp_path: Path) -> None:
    def setup(source: Path) -> None:
        original = source / "original"
        original.write_bytes(b"immutable fixture")
        os.link(original, source / "hardlink")

    expect_boundary_error(tmp_path, setup)


def test_package_special_file_is_rejected(tmp_path: Path) -> None:
    def setup(source: Path) -> None:
        os.mkfifo(source / "fifo")

    expect_boundary_error(tmp_path, setup)


def test_stable_read_rejects_content_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "artifact"
    path.write_bytes(b"stable bytes")
    original_read = os.read
    changed = False

    def read_then_replace(fd: int, size: int) -> bytes:
        nonlocal changed
        data = original_read(fd, size)
        if not changed:
            changed = True
            path.write_bytes(b"replacement with a different size")
        return data

    monkeypatch.setattr(os, "read", read_then_replace)
    with pytest.raises(ValueError, match="changed during stable read"):
        stable_read_bytes(path)


def test_stable_read_rejects_metadata_change_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "artifact"
    path.write_bytes(b"stable bytes")
    original_read = os.read
    changed = False

    def read_then_touch(fd: int, size: int) -> bytes:
        nonlocal changed
        data = original_read(fd, size)
        if not changed:
            changed = True
            os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        return data

    monkeypatch.setattr(os, "read", read_then_touch)
    with pytest.raises(ValueError, match="changed during stable read"):
        stable_read_bytes(path)


def test_git_environment_cannot_inherit_repository_redirection() -> None:
    environment = git_environment()
    assert not GIT_UNTRUSTED_ENV.intersection(environment)
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert "--no-replace-objects" in git_command(Path("/usr/bin/git"), Path("/repo"), "status")


def test_git_output_uses_minimal_environment_and_safe_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import validate_manifest

    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="/repo\n", stderr="")

    monkeypatch.setattr(validate_manifest.subprocess, "run", fake_run)
    result = validate_manifest.git_output(
        Path("/usr/bin/git"), Path("/repo"), "rev-parse", "--show-toplevel"
    )
    assert result == "/repo"
    assert "--no-replace-objects" in captured["command"]
    assert not GIT_UNTRUSTED_ENV.intersection(captured["env"])


def test_resealed_manifest_passes_with_current_external_pins() -> None:
    result = subprocess.run(
        validator_command(
            expected_validator=sha256(VALIDATOR),
            expected_commit=current_artifact_commit(),
        ),
        env={**os.environ, "PYTHONPATH": str(EVIDENCE)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_old_validator_pin_is_rejected_after_reseal() -> None:
    result = subprocess.run(
        validator_command(
            expected_validator=OLD_VALIDATOR_SHA256,
            expected_commit=current_artifact_commit(),
        ),
        env={**os.environ, "PYTHONPATH": str(EVIDENCE)},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "validator source is not externally pinned" in result.stderr


def test_old_artifact_commit_is_rejected_after_reseal() -> None:
    result = subprocess.run(
        validator_command(
            expected_validator=sha256(VALIDATOR),
            expected_commit=OLD_ARTIFACT_COMMIT,
        ),
        env={**os.environ, "PYTHONPATH": str(EVIDENCE)},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "package bytes are not bound to artifact commit" in result.stderr


def test_reseal_did_not_change_claim_or_media_contracts() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["recorded_source_commit"] == "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4"
    assert manifest["claims"] == {
        "benchmark_11_of_11": "STRUCTURE_COMPLETE_ONLY",
        "calculation_60000": "PUBLIC_SYNTHETIC_REFERENCE_VALUE_NOT_LEGAL_CONCLUSION",
        "evaluation_scores": None,
        "legal_accuracy": "UNKNOWN",
        "worker_llm_evaluation": "UNKNOWN",
    }
    assert manifest["frame_commitment"]["video_framemd5_sha256"] == (
        "sha256:d7f1593cc4acccf2c630a878384952e547f281a508129c31c170450c6f13c1c0"
    )
    assert manifest["frame_commitment"]["audio_framemd5_sha256"] == (
        "sha256:8da4d8edd6db8e97691d40f33c7cf6bd71936b7545f36564484bca7d88dd23fb"
    )
    assert manifest["artifact_hashes"]["renders/reference-runtime-evidence.mp4"] == (
        "sha256:9083e55e359d56a85c727d825545ad45a264b74f90b19dcff54a81348e4bf619"
    )
    assert manifest["artifact_hashes"]["silent-aac.m4a"] == (
        "sha256:3908ad37b0207f786c47e344615be8a9012713b1797a90ce24e329257a2d6b42"
    )
