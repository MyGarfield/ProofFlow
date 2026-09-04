from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import validate_manifest
from validate_manifest import aggregate_hash, claim_scan, digest, strict_load

EVIDENCE = Path(__file__).resolve().parent
VIDEO_ROOT = EVIDENCE.parent
MANIFEST = VIDEO_ROOT / "manifest.json"
SCHEMA = EVIDENCE / "manifest.schema.json"
VALIDATOR = EVIDENCE / "validate_manifest.py"
EXPECTED_SCHEMA = digest(SCHEMA)
EXPECTED_VALIDATOR = digest(VALIDATOR)
GIT_ROOT = VIDEO_ROOT.parent
GIT_BINARY = Path(shutil.which("git") or "/usr/local/bin/git").resolve()
EXPECTED_ARTIFACT_COMMIT = subprocess.check_output(
    [str(GIT_BINARY), "-C", str(GIT_ROOT), "rev-parse", "HEAD"], text=True
).strip()
TOOL_PATHS = {
    name: Path(json.loads(MANIFEST.read_text(encoding="utf-8"))["tooling"][name]["path"])
    for name in ("ffprobe", "ffmpeg", "tesseract")
}
TEXT2IMAGE = TOOL_PATHS["tesseract"].with_name("text2image")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def command_for(
    manifest_path: Path, root: Path, tool_overrides: dict[str, Path] | None = None
) -> list[str]:
    tools = dict(TOOL_PATHS)
    tools.update(tool_overrides or {})
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
        "--expected-artifact-commit",
        EXPECTED_ARTIFACT_COMMIT,
        "--trusted-git-root",
        str(GIT_ROOT),
        "--git-binary",
        str(GIT_BINARY),
        "--ffprobe",
        str(tools["ffprobe"]),
        "--ffmpeg",
        str(tools["ffmpeg"]),
        "--tesseract",
        str(tools["tesseract"]),
    ]


def clone_package(root: Path) -> None:
    root.mkdir()
    for item in VIDEO_ROOT.iterdir():
        if item.name != "manifest.json":
            os.symlink(item, root / item.name, target_is_directory=item.is_dir())


def materialize_file(root: Path, relative: str) -> Path:
    destination = root / relative
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
        result = subprocess.run(
            command_for(manifest_path, root), env=environment, capture_output=True, text=True
        )
        require(
            result.returncode != 0, f"{name} attack was accepted: {result.stdout} {result.stderr}"
        )


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
    result = subprocess.run(
        command_for(MANIFEST, VIDEO_ROOT), env=environment, capture_output=True, text=True
    )
    require(result.returncode == 0, f"optimized validator rejected valid manifest: {result.stderr}")


def test_fake_commit_is_rejected() -> None:
    run_mutation("fake-commit", lambda value, _root: value.update(recorded_source_commit="0" * 40))


def test_overclaim_field_is_rejected() -> None:
    run_mutation(
        "overclaim-field",
        lambda value, _root: value["claims"].update(benchmark_11_of_11="ACCURACY_MEASURED"),
    )


def test_overclaim_visible_text_is_rejected_even_after_rehash() -> None:
    def mutate(value, root):
        path = materialize_file(root, "index.html")
        path.write_text(
            path.read_text(encoding="utf-8") + "\nSIX AGENT LIVE / LEGAL ACCURACY 100%\n",
            encoding="utf-8",
        )
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
        schema.write_text(
            schema.read_text(encoding="utf-8").replace(
                '"additionalProperties": false', '"additionalProperties": true', 1
            ),
            encoding="utf-8",
        )
        value["schema_sha256"] = digest(schema)
        value["artifact_hashes"]["evidence/manifest.schema.json"] = digest(schema)

    run_mutation("schema-circular-trust", mutate)


def test_path_fake_ffprobe_is_ignored_and_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="manifest-attack-fake-path-") as directory:
        fake_path = Path(directory) / "fake-bin"
        root = Path(directory) / "reference-video"
        clone_package(root)
        fake_path.mkdir()
        fake = fake_path / "ffprobe"
        fake.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-version" ]; then '
            "echo 'ffprobe version 9.9.9'; exit 0; fi\n"
            'printf \'{"format":{"duration":"1.000000"},"streams":[]}\'\n',
            encoding="utf-8",
        )
        fake.chmod(0o755)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["ffprobe"]["format"]["duration"] = "1.000000"
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(EVIDENCE)
        result = subprocess.run(
            command_for(manifest_path, root, {"ffprobe": fake}),
            env=environment,
            capture_output=True,
            text=True,
        )
        require(result.returncode != 0, "caller-supplied fake ffprobe was trusted")


def test_deleted_video_hash_is_rejected() -> None:
    run_mutation(
        "deleted-video-hash",
        lambda value, _root: value["artifact_hashes"].pop("renders/reference-runtime-evidence.mp4"),
    )


def test_deleted_render_input_is_rejected() -> None:
    run_mutation(
        "deleted-render-input",
        lambda value, _root: value["render_input_hashes"].pop("snapshots/frame-06-at-84s.png"),
    )


def test_fake_keyframe_is_rejected() -> None:
    run_mutation(
        "fake-keyframe", lambda value, _root: value["keyframe_probes"][0].update(key_frame=0)
    )


def test_slowstart_flag_is_rejected() -> None:
    run_mutation(
        "slowstart", lambda value, _root: value.update(faststart=False, moov_atom_before_mdat=False)
    )


def test_hash_tamper_is_rejected() -> None:
    run_mutation(
        "hash-tamper",
        lambda value, _root: value["artifact_hashes"].update({"index.html": "sha256:" + "0" * 64}),
    )


def test_snapshot_duplicate_is_rejected_after_hash_recalculation() -> None:
    def mutate(value, root):
        snapshots = root / "snapshots"
        if snapshots.is_symlink():
            snapshots.unlink()
            shutil.copytree(VIDEO_ROOT / "snapshots", snapshots)
        shutil.copy2(snapshots / "frame-00-at-5s.png", snapshots / "frame-01-at-18s.png")
        refresh_hashes(value, root, "snapshots/frame-01-at-18s.png")

    run_mutation("snapshot-duplicate", mutate)


def test_srt_timing_tamper_is_rejected_after_hash_recalculation() -> None:
    def mutate(value, root):
        path = materialize_file(root, "subtitles.srt")
        text = path.read_text(encoding="utf-8").replace("00:00:09,800", "00:00:11,000", 1)
        path.write_text(text, encoding="utf-8")
        refresh_hashes(value, root, "subtitles.srt")

    run_mutation("srt-timing-tamper", mutate)


def test_full_decoded_frame_commitment_tamper_is_rejected_after_rehash() -> None:
    def mutate(value, root):
        path = materialize_file(root, "evidence/video-frames.framemd5")
        lines = path.read_text(encoding="utf-8").splitlines()
        row = next(index for index, line in enumerate(lines) if line.startswith("0,"))
        fields = lines[row].split(",")
        fields[-1] = "0" * 32
        lines[row] = ",".join(fields)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        refresh_hashes(value, root, "evidence/video-frames.framemd5")

    run_mutation("full-frame-commitment-tamper", mutate)


def test_qa_6_to_7_second_overclaim_injection_is_caught_by_live_ocr() -> None:
    with tempfile.TemporaryDirectory(prefix="manifest-attack-qa-overclaim-") as directory:
        root = Path(directory) / "reference-video"
        clone_package(root)
        snapshot = materialize_file(root, "snapshots/frame-00-at-5s.png")
        text_file = Path(directory) / "qa-overclaim.txt"
        text_file.write_text("SIX AGENTS LIVE LEGAL ACCURACY 100%\n", encoding="utf-8")
        outputbase = Path(directory) / "qa-overclaim"
        require(
            TEXT2IMAGE.is_file(),
            f"missing explicit text2image helper beside tesseract: {TEXT2IMAGE}",
        )

        subprocess.run(
            [
                str(TEXT2IMAGE),
                "--text",
                str(text_file),
                "--outputbase",
                str(outputbase),
                "--max_pages",
                "1",
                "--xsize",
                "6000",
                "--ysize",
                "1080",
                "--ptsize",
                "80",
                "--margin",
                "50",
                "--degrade_image",
                "false",
                "--rotate_image",
                "false",
                "--invert",
                "false",
                "--white_noise",
                "false",
                "--smooth_noise",
                "false",
                "--blur",
                "false",
            ],
            cwd=directory,
            check=True,
        )
        injected = Path(directory) / "qa-injected.png"
        subprocess.run(
            [
                str(TOOL_PATHS["ffmpeg"]),
                "-y",
                "-hide_banner",
                "-loglevel",
                "error",
                "-i",
                str(outputbase) + ".tif",
                "-frames:v",
                "1",
                str(injected),
            ],
            check=True,
        )
        shutil.copy2(injected, snapshot)
        shutil.copy2(MANIFEST, root / "manifest.json")
        matches, _digest = claim_scan(root, TOOL_PATHS["tesseract"])
        patterns = {item["pattern"] for item in matches}
        require(
            {"six_agents_live", "legal_accuracy_100"}.issubset(patterns),
            f"live OCR missed QA overclaim: {matches}",
        )


def test_live_ocr_timeout_is_45_seconds(monkeypatch) -> None:
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(validate_manifest.subprocess, "run", fake_run)
    assert (
        validate_manifest.ocr_snapshot(Path("/tmp/snapshot.png"), Path("/usr/bin/tesseract")) == ""
    )
    assert captured["timeout"] == 45


def test_privacy_is_recomputed_not_read_from_stale_summary() -> None:
    def mutate(value, root):
        path = materialize_file(root, "index.html")
        leaked = "/" + "Users/attacker/private"
        path.write_text(
            path.read_text(encoding="utf-8") + f"\nconst leaked = '{leaked}';\n", encoding="utf-8"
        )
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
        value["frame_bindings"][0]["video_sample_sha256"] = value["frame_bindings"][1][
            "video_sample_sha256"
        ]

    run_mutation("forged-media-chain", mutate)


def test_external_validator_pin_rejects_replaced_package_validator() -> None:
    def mutate(value, root):
        path = materialize_file(root, "evidence/validate_manifest.py")
        path.write_text(
            path.read_text(encoding="utf-8") + "\n# replaced package validator\n", encoding="utf-8"
        )
        value["artifact_hashes"]["evidence/validate_manifest.py"] = digest(path)

    run_mutation("validator-replacement", mutate)
