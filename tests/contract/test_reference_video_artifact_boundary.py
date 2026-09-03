from __future__ import annotations

import os
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
