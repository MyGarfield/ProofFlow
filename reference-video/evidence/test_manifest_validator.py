from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from validate_manifest import strict_load


EVIDENCE = Path(__file__).resolve().parent
VIDEO_ROOT = EVIDENCE.parent
MANIFEST = VIDEO_ROOT / "manifest.json"
VALIDATOR = EVIDENCE / "validate_manifest.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


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


def run_mutation(name: str, mutate) -> None:
    with tempfile.TemporaryDirectory(prefix=f"manifest-attack-{name}-") as directory:
        root = Path(directory) / "reference-video"
        root.mkdir()
        for item in VIDEO_ROOT.iterdir():
            if item.name != "manifest.json":
                os.symlink(item, root / item.name, target_is_directory=item.is_dir())
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutate(manifest)
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(EVIDENCE)
        result = subprocess.run(
            [sys.executable, "-O", str(VALIDATOR), "--manifest", str(manifest_path), "--video-root", str(root)],
            env=environment,
            capture_output=True,
            text=True,
        )
        require(result.returncode != 0, f"{name} attack was accepted: {result.stdout} {result.stderr}")


def test_optimized_valid_manifest_passes() -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(EVIDENCE)
    result = subprocess.run(
        [sys.executable, "-O", str(VALIDATOR)],
        env=environment,
        capture_output=True,
        text=True,
    )
    require(result.returncode == 0, f"optimized validator rejected valid manifest: {result.stderr}")


def test_fake_commit_is_rejected() -> None:
    run_mutation("fake-commit", lambda value: value.update(recorded_source_commit="0" * 40))


def test_overclaim_is_rejected() -> None:
    run_mutation("overclaim", lambda value: value["claims"].update(benchmark_11_of_11="ACCURACY_MEASURED"))


def test_pseudo_ffprobe_is_rejected() -> None:
    def mutate(value):
        value["ffprobe"]["streams"][0]["width"] = 1

    run_mutation("pseudo-ffprobe", mutate)


def test_deleted_video_hash_is_rejected() -> None:
    run_mutation("deleted-video-hash", lambda value: value["artifact_hashes"].pop("renders/reference-runtime-evidence.mp4"))


def test_deleted_render_input_is_rejected() -> None:
    run_mutation("deleted-render-input", lambda value: value["render_input_hashes"].pop("snapshots/frame-06-at-84s.png"))


def test_fake_keyframe_is_rejected() -> None:
    run_mutation("fake-keyframe", lambda value: value["keyframe_probes"][0].update(key_frame=0))


def test_slowstart_flag_is_rejected() -> None:
    run_mutation("slowstart", lambda value: value.update(faststart=False, moov_atom_before_mdat=False))


def test_hash_tamper_is_rejected() -> None:
    run_mutation("hash-tamper", lambda value: value["artifact_hashes"].update({"index.html": "sha256:" + "0" * 64}))
