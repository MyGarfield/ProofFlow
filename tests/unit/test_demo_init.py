from __future__ import annotations

import json
from pathlib import Path

import pytest

import proofflow.demo_init as demo_init
from proofflow.demo_init import (
    DEMO_ASSET_FILES,
    DemoInitializationError,
    initialize_demo,
)

ROOT = Path(__file__).parents[2]


def test_initialize_demo_copies_the_frozen_public_synthetic_bundle(tmp_path: Path) -> None:
    output = tmp_path / "demo"

    receipt = initialize_demo(output)

    assert receipt.classification == "PUBLIC_SYNTHETIC"
    assert receipt.files == tuple(sorted(DEMO_ASSET_FILES))
    assert {
        path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()
    } == (set(DEMO_ASSET_FILES))
    manifest = json.loads((output / "case/manifest.json").read_text(encoding="utf-8"))
    assert manifest["fixture_status"] == "SYNTHETIC"
    rules = json.loads(
        (output / "rules/cn_labor_contract_law.catalog.json").read_text(encoding="utf-8")
    )
    assert rules["status"] == "CURATED_REFERENCE_ONLY"
    assert rules["legal_advice"] is False


@pytest.mark.parametrize("target_kind", ["directory", "file", "symlink"])
def test_initialize_demo_refuses_to_overwrite_any_existing_target(
    tmp_path: Path,
    target_kind: str,
) -> None:
    output = tmp_path / "demo"
    if target_kind == "directory":
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
    elif target_kind == "file":
        output.write_text("keep", encoding="utf-8")
        sentinel = output
    else:
        destination = tmp_path / "destination"
        destination.mkdir()
        sentinel = destination / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        output.symlink_to(destination, target_is_directory=True)

    with pytest.raises(DemoInitializationError) as rejected:
        initialize_demo(output)

    assert rejected.value.code == "DEMO_OUTPUT_EXISTS"
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_packaged_assets_match_the_repository_reference_fixture() -> None:
    mappings = {
        "case/contract.json": "examples/cases/happy_path/contract.json",
        "case/manifest.json": "examples/cases/happy_path/manifest.json",
        "case/payroll.json": "examples/cases/happy_path/payroll.json",
        "case/termination_notice.json": "examples/cases/happy_path/termination_notice.json",
        "rules/cn_labor_contract_law.catalog.json": (
            "data/rules/cn_labor_contract_law.catalog.json"
        ),
    }
    for packaged, reference in mappings.items():
        assert (ROOT / "src/proofflow/demo_assets" / packaged).read_bytes() == (
            ROOT / reference
        ).read_bytes()


def test_demo_asset_integrity_failure_happens_before_output_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("proofflow.demo_init._resource_bytes", lambda _path: b"tampered")
    output = tmp_path / "demo"

    with pytest.raises(DemoInitializationError) as rejected:
        initialize_demo(output)

    assert rejected.value.code == "DEMO_ASSET_INVALID"
    assert not output.exists()


def test_initialize_demo_rejects_rename_symlink_race_without_writing_attacker_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "demo"
    moved_owned_directory = tmp_path / "moved-owned-demo"
    attacker_target = tmp_path / "attacker-target"
    attacker_target.mkdir()
    sentinel = attacker_target / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    original_write = demo_init._write_all_assets

    def race_after_directory_is_pinned(
        root: demo_init._PinnedDirectory,
        payloads: dict[str, bytes],
        child_directories: dict[str, demo_init._PinnedDirectory],
        written_files: list[demo_init._PinnedFile],
    ) -> None:
        output.rename(moved_owned_directory)
        output.symlink_to(attacker_target, target_is_directory=True)
        original_write(root, payloads, child_directories, written_files)

    monkeypatch.setattr(demo_init, "_write_all_assets", race_after_directory_is_pinned)

    with pytest.raises(DemoInitializationError) as rejected:
        initialize_demo(output)

    assert rejected.value.code == "DEMO_OUTPUT_RACE_DETECTED"
    assert output.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert {path.name for path in attacker_target.iterdir()} == {"sentinel"}
    assert moved_owned_directory.is_dir()
    assert list(moved_owned_directory.iterdir()) == []


def test_initialize_demo_rejects_rename_symlink_race_before_first_directory_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "demo"
    moved_owned_directory = tmp_path / "moved-before-open"
    attacker_target = tmp_path / "attacker-before-open"
    attacker_target.mkdir()
    sentinel = attacker_target / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    original_open = demo_init._open_pinned_directory
    raced = False

    def race_before_open(parent_fd: int, name: str) -> demo_init._PinnedDirectory:
        nonlocal raced
        if name == output.name and not raced:
            raced = True
            output.rename(moved_owned_directory)
            output.symlink_to(attacker_target, target_is_directory=True)
        return original_open(parent_fd, name)

    monkeypatch.setattr(demo_init, "_open_pinned_directory", race_before_open)

    with pytest.raises(DemoInitializationError) as rejected:
        initialize_demo(output)

    assert raced
    assert rejected.value.code == "DEMO_OUTPUT_RACE_DETECTED"
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert {path.name for path in attacker_target.iterdir()} == {"sentinel"}
    assert moved_owned_directory.is_dir()
    assert list(moved_owned_directory.iterdir()) == []
