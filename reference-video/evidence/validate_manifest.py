"""Fail-closed schema and semantic validator for the published evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from artifact_spec import ARTIFACT_PATHS, RENDER_INPUT_PATHS
from capture_sequence import FIXED_SEQUENCE, NETWORK_POLICY


ROOT = Path(__file__).resolve().parents[2]
VIDEO = ROOT / "reference-video"
RECORDED_SOURCE_COMMIT = "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4"
TARGETS = (0, 15, 30, 42, 60, 72, 89)
SECRET_PATTERN = re.compile(r"(?i)(sk-[a-z0-9]|bearer\s+[a-z0-9]|cookie\s*:|authorization\s*:)")
SRT_TIMESTAMP = re.compile(r"^(\d{2}):(\d{2}):(\d{2}),(\d{3})$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def fail(condition: bool, message: str) -> None:
    """Raise instead of using assertions so -O cannot disable a check."""
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def aggregate_hash(entries: dict[str, str]) -> str:
    payload = "".join(f"{path}\t{entries[path]}\n" for path in sorted(entries)).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def strict_load(path: Path):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"non-finite JSON number: {value}")

    def parse_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"non-finite JSON number: {value}")
        return number

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
        parse_float=parse_float,
    )


def safe_path(root: Path, relative: str) -> Path:
    posix = PurePosixPath(relative)
    fail(not posix.is_absolute() and ".." not in posix.parts, f"unsafe artifact path: {relative}")
    path = root / relative
    fail(path.is_file(), f"missing artifact: {relative}")
    return path


def ffprobe(path: Path, *args: str) -> dict:
    raw = subprocess.check_output(["ffprobe", "-v", "error", *args, "-of", "json", str(path)], text=True)
    return json.loads(raw)


def atom_positions(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    positions: dict[str, int] = {}
    offset = 0
    while offset + 8 <= len(data):
        size = int.from_bytes(data[offset : offset + 4], "big")
        atom_type = data[offset + 4 : offset + 8].decode("latin1")
        header = 8
        if size == 1:
            fail(offset + 16 <= len(data), "truncated extended MP4 atom header")
            size = int.from_bytes(data[offset + 8 : offset + 16], "big")
            header = 16
        elif size == 0:
            size = len(data) - offset
        fail(size >= header and offset + size <= len(data), f"invalid MP4 atom: {atom_type}")
        positions.setdefault(atom_type, offset)
        offset += size
    fail(offset == len(data), "MP4 atom scan did not consume the file")
    return positions


def keyframe_probes(path: Path) -> list[dict]:
    frames = ffprobe(
        path,
        "-select_streams",
        "v:0",
        "-show_frames",
        "-show_entries",
        "frame=best_effort_timestamp_time,key_frame,pict_type",
    ).get("frames", [])
    fail(bool(frames), "video has no decoded frames")
    output = []
    for target in TARGETS:
        nearest = min(frames, key=lambda frame: abs(float(frame["best_effort_timestamp_time"]) - target))
        nearest_time = float(nearest["best_effort_timestamp_time"])
        output.append(
            {
                "target_seconds": target,
                "nearest_frame_seconds": nearest_time,
                "key_frame": int(nearest.get("key_frame", 0)),
                "pict_type": nearest.get("pict_type"),
                "within_one_frame": abs(nearest_time - target) <= (1 / 30),
            }
        )
    return output


def parse_srt(path: Path) -> list[tuple[float, float, str]]:
    blocks = re.split(r"\n\s*\n", path.read_text(encoding="utf-8").strip())
    cues = []
    for block in blocks:
        lines = block.splitlines()
        fail(len(lines) >= 3 and lines[0].isdigit(), "invalid SRT cue header")
        parts = [part.strip() for part in lines[1].split("-->")]
        fail(len(parts) == 2, "invalid SRT cue timing")
        values = []
        for stamp in parts:
            match = SRT_TIMESTAMP.fullmatch(stamp)
            fail(match is not None, f"invalid SRT timestamp: {stamp}")
            hour, minute, second, millis = (int(value) for value in match.groups())
            values.append(hour * 3600 + minute * 60 + second + millis / 1000)
        start, end = values
        fail(0 <= start < end <= 92.0, "SRT cue falls outside the 92-second timeline")
        text = " ".join(lines[2:]).strip()
        fail(bool(text), "SRT cue has no text")
        cues.append((start, end, text))
    fail(bool(cues), "SRT has no cues")
    for previous, current in zip(cues, cues[1:]):
        fail(previous[1] <= current[0], "SRT cues overlap")
    return cues


def validate_manifest(manifest_path: Path, video_root: Path) -> None:
    manifest = strict_load(manifest_path)
    schema_path = video_root / "evidence/manifest.schema.json"
    schema = strict_load(schema_path)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)

    expected_manifest_keys = set(schema["properties"])
    fail(set(manifest) == expected_manifest_keys, "manifest key set drifted")
    fail(manifest["schema"] == schema["$id"], "manifest schema id mismatch")
    fail(manifest["recorded_source_commit"] == RECORDED_SOURCE_COMMIT, "recorded source commit is not the pinned full commit")
    resolved_commit = subprocess.check_output(
        ["git", "rev-parse", f"{RECORDED_SOURCE_COMMIT}^{{commit}}"], cwd=ROOT, text=True
    ).strip()
    fail(resolved_commit == RECORDED_SOURCE_COMMIT, "recorded source commit does not exist")
    fail("source_commit" not in manifest and "artifact_commit" not in manifest, "legacy commit field present")
    fail("artifact_payload_commit" not in manifest, "self-referential artifact commit field present")
    fail(manifest["sequence"] == FIXED_SEQUENCE, "sequence claim drifted from capture generator")
    fail(manifest["network_policy"] == NETWORK_POLICY, "manifest network policy differs from capture generator")

    artifact_hashes = manifest["artifact_hashes"]
    fail(set(artifact_hashes) == set(ARTIFACT_PATHS), "artifact hash key set drifted")
    for relative, expected in artifact_hashes.items():
        fail(re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is not None, f"invalid artifact digest: {relative}")
        fail(digest(safe_path(video_root, relative)) == expected, f"artifact hash mismatch: {relative}")

    render_hashes = manifest["render_input_hashes"]
    fail(set(render_hashes) == set(RENDER_INPUT_PATHS), "render input key set drifted")
    for relative, expected in render_hashes.items():
        fail(digest(safe_path(video_root, relative)) == expected, f"render input hash mismatch: {relative}")
    fail(manifest["render_input_digest"] == aggregate_hash(render_hashes), "render input aggregate digest mismatch")

    network = strict_load(video_root / "evidence/network-ledger.json")
    fail(network["policy"] == NETWORK_POLICY, "network ledger policy differs from generator")
    fail(network["non_loopback_requests_sent"] == 0, "capture client sent a non-loopback request")
    fail(
        network["redirect_regression"]
        == {"location_observed": True, "redirect_followed": False, "sink_requests": 0, "status": 302},
        "redirect regression evidence drifted",
    )
    fail(len(network["requests"]) == 11, "network request count drifted")
    for item in network["requests"]:
        parsed = urlsplit(item["url"])
        if item["decision"] == "ALLOW_LOOPBACK":
            fail(parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}, "non-loopback allow decision")
        elif item["decision"] == "BLOCK_BEFORE_SOCKET":
            fail(item["url"] == "https://external.invalid/blocked-by-loopback-policy", "unexpected blocked target")
        else:
            fail(False, "unknown network decision")

    action = strict_load(video_root / "evidence/action-ledger.json")
    expected_actions = ["PREPARE", "PACKAGE", "APPROVE", "PACKAGE", "VERIFY", "BENCHMARK"]
    fail([item["action"] for item in action["actions"]] == expected_actions, "action sequence drifted")
    fail([item["http_status"] for item in action["actions"]] == [200, 409, 200, 200, 200, 200], "action statuses drifted")
    fail(all(item["evidence"] == "PASS" for item in action["actions"]), "action ledger contains a failed evidence row")
    fail(action["actions"][1]["code"] == "HUMAN_GATE_REQUIRED", "fail-closed code drifted")
    fail(action["benchmark_contract_pass_fraction"] == "11/11", "benchmark fraction drifted")
    fail(action["benchmark_accuracy_claim"] == "NOT_MEASURED", "benchmark accuracy claim drifted")

    dom = strict_load(video_root / "evidence/dom-states.json")
    fail(dom["fixed_sequence"] == FIXED_SEQUENCE, "DOM fixed sequence drifted")
    fail([item["action"] for item in dom["states"]] == expected_actions, "DOM action states drifted")
    for item in dom["states"]:
        boundaries = item["state"]["boundaries"]
        fail(boundaries["classification"] == "PUBLIC_SYNTHETIC", "DOM classification overclaim")
        fail(boundaries["llm_enabled"] is False, "DOM LLM boundary overclaim")
        fail(boundaries["workers"] == "Stopped" and boundaries["readyWorkers"] == 0, "DOM worker boundary overclaim")
        fail(boundaries["external_side_effects_enabled"] is False, "DOM side-effect boundary overclaim")

    lint = strict_load(video_root / "evidence/lint-summary.json")
    fail(lint["schema"] == "proofflow.reference-runtime.lint-summary.v1", "lint summary schema mismatch")
    fail(lint["tool"] == "hyperframes" and VERSION_PATTERN.fullmatch(lint["tool_version"] or "") is not None, "lint tool version missing")
    fail(lint["index_sha256"] == digest(safe_path(video_root, "index.html")), "lint summary is not bound to final index")
    fail(lint["ok"] is True and lint["errorCount"] == 0 and lint["paths_redacted"] is True, "lint summary is not passing")

    privacy = strict_load(video_root / "evidence/privacy-scan.json")
    fail(privacy["matches"] == [], "privacy scan contains matches")
    for relative in ("evidence/action-ledger.json", "evidence/network-ledger.json", "evidence/dom-states.json", "index.html", "STORYBOARD.md"):
        fail(SECRET_PATTERN.search(safe_path(video_root, relative).read_text(encoding="utf-8")) is None, f"secret-shaped text in {relative}")

    video = safe_path(video_root, "renders/reference-runtime-evidence.mp4")
    media = ffprobe(
        video,
        "-show_entries",
        "format=duration,format_name:stream=index,codec_name,codec_type,width,height,pix_fmt,r_frame_rate,channels,sample_rate",
    )
    fail(media == manifest["ffprobe"], "manifest ffprobe does not match the delivered MP4")
    fail(float(media["format"]["duration"]) == 92.0, "delivered MP4 duration is not 92 seconds")
    fail(manifest["actual_duration_seconds"] == 92.0, "manifest actual duration drifted")
    atoms = atom_positions(video)
    fail("moov" in atoms and "mdat" in atoms and atoms["moov"] < atoms["mdat"], "MP4 is not faststart moov<mdat")
    fail(manifest["faststart"] is True and manifest["moov_atom_before_mdat"] is True, "manifest faststart flags drifted")

    actual_keyframes = keyframe_probes(video)
    declared_keyframes = manifest["keyframe_probes"]
    fail([item["target_seconds"] for item in declared_keyframes] == list(TARGETS), "keyframe target set drifted")
    for declared, actual in zip(declared_keyframes, actual_keyframes):
        fail(declared["key_frame"] == actual["key_frame"] == 1, "declared keyframe is not an actual I-frame")
        fail(declared["pict_type"] == actual["pict_type"] == "I", "declared keyframe picture type drifted")
        fail(declared["within_one_frame"] is True and actual["within_one_frame"] is True, "keyframe is outside one frame")
        fail(math.isclose(declared["nearest_frame_seconds"], actual["nearest_frame_seconds"], abs_tol=1e-9), "keyframe timestamp was forged")

    parse_srt(safe_path(video_root, "subtitles.srt"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=VIDEO / "manifest.json")
    parser.add_argument("--video-root", type=Path, default=VIDEO)
    args = parser.parse_args()
    try:
        validate_manifest(args.manifest, args.video_root)
    except Exception as error:
        print(f"manifest validation FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print("manifest schema + semantic validation: PASS")


if __name__ == "__main__":
    main()
