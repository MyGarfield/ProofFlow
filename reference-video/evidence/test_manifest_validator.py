from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from validate_manifest import aggregate_hash, digest, strict_load


EVIDENCE = Path(__file__).resolve().parent
VIDEO_ROOT = EVIDENCE.parent
MANIFEST = VIDEO_ROOT / "manifest.json"
SCHEMA = EVIDENCE / "manifest.schema.json"
VALIDATOR = EVIDENCE / "validate_manifest.py"
EXPECTED_SCHEMA = digest(SCHEMA)
EXPECTED_VALIDATOR = digest(VALIDATOR)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def command_for(manifest_path: Path, root: Path) -> list[str]:
    return [
        sys.executable,
        "-O",
        str(VALIDATOR),
        "--manifest",
        str(manifest_path),
        "--video-root",
        str(root),
        "--expected-schema-sha256",
        EXPECTED_SCHEMA,
        "--expected-validator-sha256",
        EXPECTED_VALIDATOR,
    ]


def clone_package(root: Path) -> None:
    root.mkdir()
    for item in VIDEO_ROOT.iterdir():
        if item.name != "manifest.json":
            os.symlink(item, root / item.name, target_is_directory=item.is_dir())


def materialize_file(root: Path, relative: str) -> Path:
    destination = root / relative
    parent = destination.parent
    top = root / relative.split("/", 1)[0]
    if top.is_symlink():
        top.unlink()
        source = VIDEO_ROOT / top.name
        if source.is_dir():
            shutil.copytree(source, top)
        else:
            shutil.copy2(source, top)
    if destination.is_symlink():
        destination.unlink()
        shutil.copy2(VIDEO_ROOT / relative, destination)
    return destination


def refresh_hashes(manifest: dict, root: Path, *relatives: str) -> None:
    for relative in relatives:
        manifest["artifact_hashes"][relative] = digest(root / relative)
        if relative in manifest["render_input_hashes"]:
            manifest["render_input_hashes"][relative] = digest(root / relative)
    manifest["render_input_digest"] = aggregate_hash(manifest["render_input_hashes"])


def run_mutation(name: str, mutate) -> None:
    with tempfile.TemporaryDirectory(prefix=f"manifest-attack-{name}-") as directory:
        root = Path(directory) / "reference-video"
        clone_package(root)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutate(manifest, root)
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(EVIDENCE)
        result = subprocess.run(command_for(manifest_path, root), env=environment, capture_output=True, text=True)
        require(result.returncode != 0, f"{name} attack was accepted: {result.stdout} {result.stderr}")


def test_duplicate_key_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "duplicate.json"
        path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
        try:
            strict_load(path)
        except ValueError as error:
            require("duplicate JSON key" in str(error), "wrong duplicate-key error")
        else:
            raise AssertionError("duplicate key was accepted")


def test_non_finite_number_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "nonfinite.json"
        path.write_text('{"a": NaN}', encoding="utf-8")
        try:
            strict_load(path)
        except ValueError as error:
            require("non-finite JSON number" in str(error), "wrong non-finite error")
        else:
            raise AssertionError("NaN was accepted")


def test_optimized_valid_manifest_passes() -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(EVIDENCE)
    result = subprocess.run(command_for(MANIFEST, VIDEO_ROOT), env=environment, capture_output=True, text=True)
    require(result.returncode == 0, f"optimized validator rejected valid manifest: {result.stderr}")


def test_fake_commit_is_rejected() -> None:
    run_mutation("fake-commit", lambda value, _root: value.update(recorded_source_commit="0" * 40))


def test_overclaim_field_is_rejected() -> None:
    run_mutation("overclaim-field", lambda value, _root: value["claims"].update(benchmark_11_of_11="ACCURACY_MEASURED"))


def test_overclaim_visible_text_is_rejected_even_after_rehash() -> None:
    def mutate(value, root):
        path = materialize_file(root, "index.html")
        path.write_text(path.read_text(encoding="utf-8") + "\nSIX AGENT LIVE / LEGAL ACCURACY 100%\n", encoding="utf-8")
        refresh_hashes(value, root, "index.html")
        lint = materialize_file(root, "evidence/lint-summary.json")
        lint_value = json.loads(lint.read_text(encoding="utf-8"))
        lint_value["index_sha256"] = digest(path)
        lint.write_text(json.dumps(lint_value), encoding="utf-8")
        refresh_hashes(value, root, "evidence/lint-summary.json")

    run_mutation("visible-overclaim", mutate)


def test_package_schema_cannot_define_truth() -> None:
    def mutate(value, root):
        schema = materialize_file(root, "evidence/manifest.schema.json")
        schema.write_text(schema.read_text(encoding="utf-8").replace("Structural envelope only", "forged semantic truth"), encoding="utf-8")
        value["schema_sha256"] = digest(schema)
        value["artifact_hashes"]["evidence/manifest.schema.json"] = digest(schema)

    run_mutation("schema-circular-trust", mutate)


def test_path_fake_ffprobe_is_ignored_and_rejected() -> None:
    def mutate(value, root):
        value["ffprobe"]["format"]["duration"] = "1.000000"
        fake = root.parent / "fake-bin"
        fake.mkdir()
        (fake / "ffprobe").write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
        (fake / "ffprobe").chmod(0o755)

    with tempfile.TemporaryDirectory(prefix="manifest-attack-fake-path-") as directory:
        fake_path = Path(directory) / "fake-bin"
        root = Path(directory) / "reference-video"
        clone_package(root)
        fake_path.mkdir()
        fake = fake_path / "ffprobe"
        fake.write_text("#!/bin/sh\nprintf '{\"format\":{\"duration\":\"1.000000\"},\"streams\":[]}'\n", encoding="utf-8")
        fake.chmod(0o755)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["ffprobe"]["format"]["duration"] = "1.000000"
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(EVIDENCE)
        environment["PATH"] = str(fake_path)
        result = subprocess.run(command_for(manifest_path, root), env=environment, capture_output=True, text=True)
        require(result.returncode != 0, "PATH fake ffprobe was trusted")


def test_deleted_video_hash_is_rejected() -> None:
    run_mutation("deleted-video-hash", lambda value, _root: value["artifact_hashes"].pop("renders/reference-runtime-evidence.mp4"))


def test_deleted_render_input_is_rejected() -> None:
    run_mutation("deleted-render-input", lambda value, _root: value["render_input_hashes"].pop("snapshots/frame-06-at-84s.png"))


def test_fake_keyframe_is_rejected() -> None:
    run_mutation("fake-keyframe", lambda value, _root: value["keyframe_probes"][0].update(key_frame=0))


def test_slowstart_flag_is_rejected() -> None:
    run_mutation("slowstart", lambda value, _root: value.update(faststart=False, moov_atom_before_mdat=False))


def test_hash_tamper_is_rejected() -> None:
    run_mutation("hash-tamper", lambda value, _root: value["artifact_hashes"].update({"index.html": "sha256:" + "0" * 64}))


def test_frame_swap_is_rejected_after_hash_recalculation() -> None:
    def mutate(value, root):
        snapshots = root / "snapshots"
        if snapshots.is_symlink():
            snapshots.unlink()
            shutil.copytree(VIDEO_ROOT / "snapshots", snapshots)
        shutil.copy2(snapshots / "frame-00-at-5s.png", snapshots / "frame-01-at-18s.png")
        refresh_hashes(value, root, "snapshots/frame-01-at-18s.png")

    run_mutation("frame-swap", mutate)


def test_privacy_is_recomputed_not_read_from_stale_summary() -> None:
    def mutate(value, root):
        path = materialize_file(root, "index.html")
        leaked = "/" + "Users/attacker/private"
        path.write_text(path.read_text(encoding="utf-8") + f"\nconst leaked = '{leaked}';\n", encoding="utf-8")
        refresh_hashes(value, root, "index.html")
        lint = materialize_file(root, "evidence/lint-summary.json")
        lint_value = json.loads(lint.read_text(encoding="utf-8"))
        lint_value["index_sha256"] = digest(path)
        lint.write_text(json.dumps(lint_value), encoding="utf-8")
        refresh_hashes(value, root, "evidence/lint-summary.json")

    run_mutation("stale-privacy", mutate)


def test_slowstart_and_frame_chain_cannot_be_forged_together() -> None:
    def mutate(value, root):
        value.update(faststart=False, moov_atom_before_mdat=False)
        value["frame_bindings"][0]["video_sample_sha256"] = value["frame_bindings"][1]["video_sample_sha256"]

    run_mutation("forged-media-chain", mutate)


def test_external_validator_pin_rejects_replaced_package_validator() -> None:
    def mutate(value, root):
        path = materialize_file(root, "evidence/validate_manifest.py")
        path.write_text(path.read_text(encoding="utf-8") + "\n# replaced package validator\n", encoding="utf-8")
        value["artifact_hashes"]["evidence/validate_manifest.py"] = digest(path)

    run_mutation("validator-replacement", mutate)
