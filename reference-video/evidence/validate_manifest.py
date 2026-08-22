"""Fail-closed validation for the published reference-runtime evidence.

The schema shipped with the package is only a structural envelope.  A caller
must provide SHA-256 values for the trusted validator and schema.  Release
claims, artifact membership, tool identity, live privacy scanning, and frame
provenance are checked here as independent semantic contracts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VIDEO_ROOT = ROOT / "reference-video"
GIT_ARTIFACT_PREFIX = "reference-video"
SCHEMA_ID = "proofflow.reference-runtime-evidence-video.manifest.v2"
RECORDED_SOURCE_COMMIT = "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4"
NETWORK_POLICY = (
    "capture client uses direct http.client connections to 127.0.0.1/localhost only; "
    "reject all other targets before socket creation; no proxy env and no redirects"
)
FIXED_SEQUENCE = [
    "PREPARE",
    "409_FAIL_CLOSED",
    "LOCAL_DEMO",
    "PACKAGE",
    "VERIFY",
    "11/11_BENCHMARK",
]
TARGETS = (0, 15, 30, 42, 60, 72, 89)
SNAPSHOT_BINDINGS = (
    ("snapshots/frame-00-at-5s.png", 5.0),
    ("snapshots/frame-01-at-18s.png", 18.0),
    ("snapshots/frame-02-at-33s.png", 33.0),
    ("snapshots/frame-03-at-49s.png", 49.0),
    ("snapshots/frame-04-at-62s.png", 62.0),
    ("snapshots/frame-05-at-70s.png", 70.0),
    ("snapshots/frame-06-at-84s.png", 84.0),
)
SNAPSHOT_PATHS = tuple(path for path, _target in SNAPSHOT_BINDINGS)
RENDER_INPUT_PATHS = SNAPSHOT_PATHS + (
    "silent-aac.m4a",
    "evidence/ffmpeg-image-sequence.txt",
)
FRAME_VIDEO_PATH = "evidence/video-frames.framemd5"
FRAME_AUDIO_PATH = "evidence/audio-pcm.framemd5"
FRAME_VIDEO_FILTER = "scale=96:54:flags=bilinear,format=gray"
FRAME_VIDEO_COUNT = 2760
FRAME_VIDEO_WIDTH = 96
FRAME_VIDEO_HEIGHT = 54
FRAME_VIDEO_SIZE = FRAME_VIDEO_WIDTH * FRAME_VIDEO_HEIGHT
FRAME_AUDIO_SAMPLE_RATE = 48000
FRAME_AUDIO_SAMPLE_COUNT = 4416512
FRAME_COMMITMENT_COMMAND = (
    "$FFMPEG_BIN -hide_banner -loglevel error -i renders/reference-runtime-evidence.mp4 "
    "-map 0:v:0 -an -vf scale=96:54:flags=bilinear,format=gray -f framemd5 pipe:1; "
    "$FFMPEG_BIN -hide_banner -loglevel error -i renders/reference-runtime-evidence.mp4 "
    "-map 0:a:0 -vn -af aformat=sample_fmts=s16:sample_rates=48000:channel_layouts=stereo "
    "-f framemd5 pipe:1"
)
FRAME_SEGMENTS = (
    {"segment": 1, "start_seconds": 0, "end_seconds": 10, "start_frame": 0, "end_frame_exclusive": 300, "snapshot": SNAPSHOT_PATHS[0]},
    {"segment": 2, "start_seconds": 10, "end_seconds": 26, "start_frame": 300, "end_frame_exclusive": 780, "snapshot": SNAPSHOT_PATHS[1]},
    {"segment": 3, "start_seconds": 26, "end_seconds": 41, "start_frame": 780, "end_frame_exclusive": 1230, "snapshot": SNAPSHOT_PATHS[2]},
    {"segment": 4, "start_seconds": 41, "end_seconds": 58, "start_frame": 1230, "end_frame_exclusive": 1740, "snapshot": SNAPSHOT_PATHS[3]},
    {"segment": 5, "start_seconds": 58, "end_seconds": 66, "start_frame": 1740, "end_frame_exclusive": 1980, "snapshot": SNAPSHOT_PATHS[4]},
    {"segment": 6, "start_seconds": 66, "end_seconds": 75, "start_frame": 1980, "end_frame_exclusive": 2250, "snapshot": SNAPSHOT_PATHS[5]},
    {"segment": 7, "start_seconds": 75, "end_seconds": 92, "start_frame": 2250, "end_frame_exclusive": 2760, "snapshot": SNAPSHOT_PATHS[6]},
)
ARTIFACT_PATHS = (
    "DESIGN.md",
    "SCRIPT.md",
    "STORYBOARD.md",
    "index.html",
    "subtitles.srt",
    "silent-aac.m4a",
    "renders/reference-runtime-evidence.mp4",
    "capture/meta.json",
    "capture/extracted/animations.json",
    "capture/extracted/design-styles.json",
    "capture/extracted/fonts-manifest.json",
    "capture/extracted/page.html",
    "capture/extracted/tokens.json",
    "capture/extracted/visible-text.txt",
    "capture/screenshots/full-page.png",
    "capture/screenshots/scroll-000.png",
    "capture/screenshots/contact-sheet.jpg",
    "evidence/action-ledger.json",
    "evidence/network-ledger.json",
    "evidence/dom-states.json",
    FRAME_VIDEO_PATH,
    FRAME_AUDIO_PATH,
    "evidence/capture_sequence.py",
    "evidence/ffmpeg-image-sequence.txt",
    "evidence/artifact_spec.py",
    "evidence/manifest.schema.json",
    "evidence/validate_manifest.py",
    "evidence/finalize_manifest.py",
    "evidence/run_final_lint.py",
    "evidence/lint-summary.json",
    "evidence/run_privacy_scan.py",
    "evidence/privacy-scan.json",
    "evidence/test_manifest_validator.py",
    *SNAPSHOT_PATHS,
)
EXPECTED_MANIFEST_KEYS = {
    "actual_duration_seconds",
    "artifact_hashes",
    "audio",
    "audio_role",
    "benchmark_report_hash",
    "benchmark_report_hash_provenance",
    "benchmark_report_hash_reproducible",
    "capture",
    "claim_provenance",
    "claims",
    "classification",
    "duration_seconds",
    "external_side_effects_enabled",
    "faststart",
    "ffprobe",
    "fps",
    "frame_bindings",
    "frame_commitment",
    "keyframe_probes",
    "ledgers",
    "lint_summary",
    "llm",
    "moov_atom_before_mdat",
    "network_ledger_non_loopback_requests_sent",
    "network_policy",
    "pixel_format",
    "privacy_provenance",
    "readyWorkers",
    "recorded_source_commit",
    "render_input_digest",
    "render_input_hashes",
    "render_method",
    "resolution",
    "schema",
    "schema_sha256",
    "sequence",
    "source_url",
    "status",
    "subtitles",
    "tooling",
    "validator_sha256",
    "video",
    "voiceover_status",
    "workers",
}

TOOL_NAMES = ("ffprobe", "ffmpeg", "tesseract")

SRT_TIMESTAMP = re.compile(r"^(\d{2}):(\d{2}):(\d{2}),(\d{3})$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
REPORT_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_PATTERNS = {
    "absolute_path": re.compile(r"/(?:Users|private)/[A-Za-z0-9_.-]+"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{8,}\b"),
    "api_key": re.compile(r"(?i)\bsk-[A-Za-z0-9]{12,}\b"),
    "authorization": re.compile(r"(?i)\bauthorization\s*:\s*[^\s,;]{8,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
FORBIDDEN_CLAIM_PATTERNS = {
    "six_agents_live": re.compile(r"(?i)\b(?:six|6)\s+agents?\s+(?:live|running|active)\b"),
    "legal_accuracy_100": re.compile(r"(?i)\blegal\s+accuracy\s*[:=]?\s*100\s*%"),
    "production_ready": re.compile(r"(?i)\bproduction_ready\b"),
    "real_case": re.compile(r"(?i)\breal_case\b"),
    "llm_on": re.compile(r"(?i)\bllm\s+(?:on|enabled)\b"),
    "workers_running": re.compile(r"(?i)\bworkers?\s+running\b"),
    "ready_workers_positive": re.compile(r"(?i)\breadyWorkers\s*[=:]\s*[1-9][0-9]*\b"),
    "external_side_effects_true": re.compile(r"(?i)\bexternal_side_effects_enabled\s*[=:]\s*true\b"),
    "chinese_legal_accuracy_100": re.compile(r"法律(?:准确率|正确率)\s*[:：=]?\s*100\s*%"),
}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".m4a", ".wav", ".woff", ".woff2", ".pyc"}
PRIVACY_EXCLUDED = {"manifest.json", "evidence/privacy-scan.json"}
CLAIM_TEXT_PATHS = ("index.html", "subtitles.srt")
CLAIM_SCANNER_NAME = "trusted-validator-live+tesseract"
PRIVACY_SCANNER_NAME = "trusted-validator-live"
REPORT_HASH_PROVENANCE = (
    "server-generated synthetic report digest observed by the capture client; "
    "a replay does not independently reproduce this field"
)
RENDER_CONTRACT_TEXT = "\n".join(
    [
        "schema=proofflow.reference-runtime.render-contract.v2",
        "method=ffmpeg_filter_concat",
        "fps=30",
        "pixel_format=yuv420p",
        "segment=0-10s frames=0-299 snapshot=snapshots/frame-00-at-5s.png",
        "segment=10-26s frames=300-779 snapshot=snapshots/frame-01-at-18s.png",
        "segment=26-41s frames=780-1229 snapshot=snapshots/frame-02-at-33s.png",
        "segment=41-58s frames=1230-1739 snapshot=snapshots/frame-03-at-49s.png",
        "segment=58-66s frames=1740-1979 snapshot=snapshots/frame-04-at-62s.png",
        "segment=66-75s frames=1980-2249 snapshot=snapshots/frame-05-at-70s.png",
        "segment=75-92s frames=2250-2759 snapshot=snapshots/frame-06-at-84s.png",
        "input=snapshots/frame-00-at-5s.png",
        "input=snapshots/frame-01-at-18s.png",
        "input=snapshots/frame-02-at-33s.png",
        "input=snapshots/frame-03-at-49s.png",
        "input=snapshots/frame-04-at-62s.png",
        "input=snapshots/frame-05-at-70s.png",
        "input=snapshots/frame-06-at-84s.png",
        "input=silent-aac.m4a role=AAC_PLACEHOLDER_SILENCE_NOT_NARRATION",
        "render_command=$FFMPEG_BIN -y -hide_banner -loglevel error -loop 1 -t 10 -i snapshots/frame-00-at-5s.png -loop 1 -t 16 -i snapshots/frame-01-at-18s.png -loop 1 -t 15 -i snapshots/frame-02-at-33s.png -loop 1 -t 17 -i snapshots/frame-03-at-49s.png -loop 1 -t 8 -i snapshots/frame-04-at-62s.png -loop 1 -t 9 -i snapshots/frame-05-at-70s.png -loop 1 -t 17 -i snapshots/frame-06-at-84s.png -i silent-aac.m4a -filter_complex [0:v][1:v][2:v][3:v][4:v][5:v][6:v]concat=n=7:v=1:a=0[v] -map [v] -map 7:a:0 -t 92 -r 30 -c:v libx264 -pix_fmt yuv420p -force_key_frames 0,15,30,42,60,72,89 -c:a aac -ar 48000 -ac 2 -movflags +faststart renders/reference-runtime-evidence.mp4",
        "frame_commitment_video=$FFMPEG_BIN -hide_banner -loglevel error -i renders/reference-runtime-evidence.mp4 -map 0:v:0 -an -vf scale=96:54:flags=bilinear,format=gray -f framemd5 pipe:1",
        "frame_commitment_audio=$FFMPEG_BIN -hide_banner -loglevel error -i renders/reference-runtime-evidence.mp4 -map 0:a:0 -vn -af aformat=sample_fmts=s16:sample_rates=48000:channel_layouts=stereo -f framemd5 pipe:1",
    ]
) + "\n"


def fail(condition: bool, message: str) -> None:
    """Raise a validation error whenever a contract is not met."""
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


def absolute_directory(value: str, name: str) -> Path:
    path = Path(value)
    fail(path.is_absolute(), f"{name} must be an absolute path")
    fail(path.is_dir(), f"{name} is not a directory: {path}")
    return path.resolve()


def git_output(git_binary: Path, trusted_git_root: Path, *args: str) -> str:
    completed = subprocess.run(
        [str(git_binary), "-C", str(trusted_git_root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    fail(completed.returncode == 0, f"git command failed: {' '.join(args)}")
    return completed.stdout.strip()


def validate_commit_binding(
    video_root: Path,
    manifest_path: Path,
    expected_artifact_commit: str,
    trusted_git_root: Path,
    git_binary: Path,
) -> None:
    fail(COMMIT_SHA_PATTERN.fullmatch(expected_artifact_commit) is not None, "expected artifact commit must be a full 40-character SHA")
    top_level = Path(git_output(git_binary, trusted_git_root, "rev-parse", "--show-toplevel")).resolve()
    fail(top_level == trusted_git_root.resolve(), "trusted git root does not match the git worktree")
    resolved = git_output(git_binary, trusted_git_root, "rev-parse", f"{expected_artifact_commit}^{{commit}}")
    fail(resolved == expected_artifact_commit, "expected artifact commit is not an exact commit object")

    package_paths = ("manifest.json", *ARTIFACT_PATHS)
    for relative in package_paths:
        package_path = manifest_path if relative == "manifest.json" else safe_path(video_root, relative)
        git_path = f"{GIT_ARTIFACT_PREFIX}/{relative}"
        completed = subprocess.run(
            [str(git_binary), "-C", str(trusted_git_root), "cat-file", "blob", f"{expected_artifact_commit}:{git_path}"],
            check=False,
            capture_output=True,
        )
        fail(completed.returncode == 0, f"artifact commit is missing {git_path}")
        fail(package_path.read_bytes() == completed.stdout, f"package bytes are not bound to artifact commit: {relative}")


def normalize_sha(value: str) -> str:
    if value.startswith("sha256:"):
        normalized = value
    else:
        normalized = "sha256:" + value
    fail(SHA256_PATTERN.fullmatch(normalized) is not None, "expected a SHA-256 digest")
    return normalized


def absolute_tool_path(value: str, name: str) -> Path:
    path = Path(value)
    fail(path.is_absolute(), f"{name} path must be absolute; PATH lookup is forbidden")
    fail(path.is_file(), f"{name} path is not a regular file: {path}")
    fail(path.stat().st_mode & stat.S_IXUSR != 0, f"{name} path is not executable: {path}")
    return path


def tool_version(name: str, path: Path) -> str:
    flag = "--version" if name == "tesseract" else "-version"
    output = subprocess.check_output([str(path), flag], stderr=subprocess.STDOUT, text=True)
    first = next((line for line in output.splitlines() if line.strip()), "")
    match = re.search(r"(?:version\s+|tesseract\s+)(\d+\.\d+\.\d+)", first, flags=re.IGNORECASE)
    fail(match is not None, f"cannot parse {name} version from {path}")
    return match.group(1)


def inspect_tool(name: str, path: Path) -> dict[str, str]:
    path = absolute_tool_path(str(path), name)
    stat_result = path.stat()
    actual = {
        "path": str(path),
        "sha256": digest(path),
        "version": tool_version(name, path),
        "owner": pwd.getpwuid(stat_result.st_uid).pw_name,
        "mode": stat.filemode(stat_result.st_mode),
    }
    return actual


def inspect_tooling(tool_paths: dict[str, Path]) -> dict[str, dict[str, str]]:
    fail(set(tool_paths) == set(TOOL_NAMES), "tool path set drifted")
    return {name: inspect_tool(name, tool_paths[name]) for name in TOOL_NAMES}


def parse_tool_json(raw: str):
    return json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite ffprobe value: {value}")))


def ffprobe(path: Path, ffprobe_path: Path, *args: str) -> dict:
    raw = subprocess.check_output(
        [str(ffprobe_path), "-v", "error", *args, "-of", "json", str(path)],
        text=True,
    )
    return parse_tool_json(raw)


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


def keyframe_probes(path: Path, ffprobe_path: Path) -> list[dict]:
    frames = ffprobe(
        path,
        ffprobe_path,
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


def raw_rgb(path: Path, ffmpeg_path: Path, target_seconds: float | None = None) -> bytes:
    args = [str(ffmpeg_path), "-v", "error", "-i", str(path)]
    if target_seconds is not None:
        args.extend(["-ss", f"{target_seconds:.6f}"])
    args.extend(["-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"])
    return subprocess.check_output(args)


def sampled_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw[::97]).hexdigest()


def compare_frame(video: Path, snapshot: Path, target_seconds: float, ffmpeg_path: Path) -> dict[str, object]:
    snapshot_raw = raw_rgb(snapshot, ffmpeg_path)
    video_raw = raw_rgb(video, ffmpeg_path, target_seconds)
    fail(len(snapshot_raw) == len(video_raw), f"frame dimensions differ at {target_seconds:g}s")
    sampled_snapshot = snapshot_raw[::97]
    sampled_video = video_raw[::97]
    differences = [abs(left - right) for left, right in zip(sampled_snapshot, sampled_video)]
    mae = sum(differences) / len(differences)
    equal_ratio = sum(value == 0 for value in differences) / len(differences)
    fail(mae <= 18.0 and equal_ratio >= 0.80, f"snapshot is not bound to MP4 frame at {target_seconds:g}s")
    return {
        "snapshot": "",
        "target_seconds": target_seconds,
        "width": 1920,
        "height": 1080,
        "snapshot_sample_sha256": sampled_digest(snapshot_raw),
        "video_sample_sha256": sampled_digest(video_raw),
        "sampled_mae": round(mae, 6),
        "sampled_equal_ratio": round(equal_ratio, 6),
    }


def privacy_inventory(root: Path) -> list[str]:
    paths = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() in BINARY_SUFFIXES or "__pycache__" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        if relative in PRIVACY_EXCLUDED:
            continue
        paths.append(relative)
    return paths


def scan_secret_text(root: Path, relative_paths: list[str]) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    paths = list(relative_paths)
    for relative in ("manifest.json", "evidence/privacy-scan.json"):
        if (root / relative).is_file() and relative not in paths:
            paths.append(relative)
    for relative in paths:
        text = safe_path(root, relative).read_text(encoding="utf-8", errors="replace")
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                matches.append({"file": relative, "pattern": name})
    return matches


def privacy_provenance(root: Path, validator_sha256: str) -> tuple[list[str], str, list[dict[str, str]]]:
    paths = privacy_inventory(root)
    hashes = {relative: digest(safe_path(root, relative)) for relative in paths}
    matches = scan_secret_text(root, paths)
    return paths, aggregate_hash(hashes), matches


def claim_text_inputs(root: Path) -> list[str]:
    paths = list(CLAIM_TEXT_PATHS)
    paths.extend(SNAPSHOT_PATHS)
    return paths


def claim_input_digest(root: Path) -> str:
    paths = claim_text_inputs(root)
    hashes = {relative: digest(safe_path(root, relative)) for relative in paths if not relative.endswith(".png")}
    for relative in SNAPSHOT_PATHS:
        hashes[relative] = digest(safe_path(root, relative))
    return aggregate_hash(hashes)


def ocr_snapshot(path: Path, tesseract_path: Path) -> str:
    completed = subprocess.run(
        [str(tesseract_path), str(path), "stdout", "--psm", "6"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    fail(completed.returncode == 0, f"tesseract failed for {path.name}")
    return completed.stdout


def claim_scan(root: Path, tesseract_path: Path) -> tuple[list[dict[str, str]], str]:
    matches: list[dict[str, str]] = []
    for relative in CLAIM_TEXT_PATHS + ("manifest.json",):
        text = safe_path(root, relative).read_text(encoding="utf-8", errors="replace")
        for name, pattern in FORBIDDEN_CLAIM_PATTERNS.items():
            if pattern.search(text):
                matches.append({"file": relative, "pattern": name})
    for relative in SNAPSHOT_PATHS:
        text = ocr_snapshot(safe_path(root, relative), tesseract_path)
        for name, pattern in FORBIDDEN_CLAIM_PATTERNS.items():
            if pattern.search(text):
                matches.append({"file": relative, "pattern": name})
    return matches, claim_input_digest(root)


def run_framemd5(ffmpeg_path: Path, video: Path, args: list[str]) -> bytes:
    completed = subprocess.run(
        [str(ffmpeg_path), "-hide_banner", "-loglevel", "error", "-i", str(video), *args, "-f", "framemd5", "pipe:1"],
        check=False,
        capture_output=True,
    )
    fail(completed.returncode == 0, f"ffmpeg framemd5 failed: {completed.stderr.decode('utf-8', errors='replace')[:300]}")
    return completed.stdout


def parse_framemd5(raw: bytes, media: str) -> list[tuple[int, int, int, int, str]]:
    lines = raw.decode("utf-8").splitlines()
    fail(lines[:3] == ["#format: frame checksums", "#version: 2", "#hash: MD5"], f"{media} framemd5 header drifted")
    fail(any(line.startswith("#software: ") for line in lines[:6]), f"{media} framemd5 has no software provenance")
    if media == "video":
        required = ["#tb 0: 1/30", "#media_type 0: video", "#codec_id 0: rawvideo", "#dimensions 0: 96x54", "#sar 0: 0/1"]
    else:
        required = ["#tb 0: 1/48000", "#media_type 0: audio", "#codec_id 0: pcm_s16le", "#sample_rate 0: 48000", "#channel_layout_name 0: stereo"]
    for prefix in required:
        fail(prefix in lines, f"{media} framemd5 is missing {prefix}")
    try:
        header_index = lines.index("#stream#, dts,        pts, duration,     size, hash")
    except ValueError as error:
        raise ValueError(f"{media} framemd5 row header drifted") from error
    rows = []
    for line in lines[header_index + 1 :]:
        fail(line and not line.startswith("#"), f"{media} framemd5 has an unexpected comment")
        fields = [field.strip() for field in line.split(",")]
        fail(len(fields) == 6, f"{media} framemd5 row has the wrong column count")
        stream, dts, pts, duration, size = (int(field) for field in fields[:5])
        checksum = fields[5]
        fail(re.fullmatch(r"[0-9a-f]{32}", checksum) is not None, f"{media} framemd5 checksum is invalid")
        rows.append((stream, dts, pts, duration, size, checksum))
    if media == "video":
        fail(len(rows) == FRAME_VIDEO_COUNT, "decoded video frame count is not exactly 2760")
        for index, (stream, dts, pts, duration, size, _checksum) in enumerate(rows):
            fail((stream, dts, pts, duration, size) == (0, index, index, 1, FRAME_VIDEO_SIZE), f"video frame timeline drifted at {index}")
    else:
        fail(len(rows) == 4313, "decoded audio packet count drifted")
        for index, (stream, dts, pts, duration, size, _checksum) in enumerate(rows):
            fail((stream, dts, pts, duration, size) == (0, index * 1024, index * 1024, 1024, 4096), f"audio PCM timeline drifted at {index}")
        fail((rows[-1][1] + rows[-1][3]) == FRAME_AUDIO_SAMPLE_COUNT, "decoded audio sample count drifted")
    return rows


def frame_commitment_payload(video_root: Path) -> dict[str, object]:
    return {
        "video_digest_path": FRAME_VIDEO_PATH,
        "audio_digest_path": FRAME_AUDIO_PATH,
        "video_framemd5_sha256": digest(safe_path(video_root, FRAME_VIDEO_PATH)),
        "audio_framemd5_sha256": digest(safe_path(video_root, FRAME_AUDIO_PATH)),
        "video_filter": FRAME_VIDEO_FILTER,
        "video_codec": "rawvideo",
        "video_frame_count": FRAME_VIDEO_COUNT,
        "video_width": FRAME_VIDEO_WIDTH,
        "video_height": FRAME_VIDEO_HEIGHT,
        "video_pixel_format": "gray",
        "video_time_base": "1/30",
        "audio_sample_rate": FRAME_AUDIO_SAMPLE_RATE,
        "audio_sample_format": "s16",
        "audio_channel_layout": "stereo",
        "audio_sample_count": FRAME_AUDIO_SAMPLE_COUNT,
        "audio_time_base": "1/48000",
        "command": FRAME_COMMITMENT_COMMAND,
        "segments": [dict(segment) for segment in FRAME_SEGMENTS],
    }


def verify_frame_commitment(video_root: Path, video: Path, ffmpeg_path: Path) -> dict[str, object]:
    contract = safe_path(video_root, "evidence/ffmpeg-image-sequence.txt").read_text(encoding="utf-8")
    fail(contract == RENDER_CONTRACT_TEXT, "render contract text drifted from the trusted seven-segment contract")
    generated_video = run_framemd5(
        ffmpeg_path,
        video,
        ["-map", "0:v:0", "-an", "-vf", FRAME_VIDEO_FILTER],
    )
    generated_audio = run_framemd5(
        ffmpeg_path,
        video,
        ["-map", "0:a:0", "-vn", "-af", "aformat=sample_fmts=s16:sample_rates=48000:channel_layouts=stereo"],
    )
    expected_video = safe_path(video_root, FRAME_VIDEO_PATH).read_bytes()
    expected_audio = safe_path(video_root, FRAME_AUDIO_PATH).read_bytes()
    fail(generated_video == expected_video, "decoded video framemd5 does not match the committed 2760-frame evidence")
    fail(generated_audio == expected_audio, "decoded audio PCM framemd5 does not match the committed evidence")
    parse_framemd5(generated_video, "video")
    parse_framemd5(generated_audio, "audio")
    return frame_commitment_payload(video_root)


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
    expected_starts = [0.0, 10.0, 26.0, 41.0, 58.0, 66.0, 75.0]
    expected_ends = [9.8, 25.8, 40.8, 57.8, 65.8, 74.8, 92.0]
    expected_prefixes = ["公开合成参考证据片", "PREPARE", "审批前 PACKAGE", "LOCAL_DEMO", "PACKAGE", "VERIFY", "边界保持不变"]
    fail(len(cues) == len(expected_starts), "subtitle cue count does not match the visible scenes")
    for index, (start, end, text) in enumerate(cues):
        fail(math.isclose(start, expected_starts[index], abs_tol=1e-3), f"subtitle cue {index + 1} starts outside its scene")
        fail(math.isclose(end, expected_ends[index], abs_tol=1e-3), f"subtitle cue {index + 1} ends outside its scene")
        fail(text.startswith(expected_prefixes[index]), f"subtitle cue {index + 1} does not describe its static scene")
    return cues


def validate_manifest(
    manifest_path: Path,
    video_root: Path,
    expected_schema_sha256: str,
    expected_validator_sha256: str,
    expected_artifact_commit: str,
    trusted_git_root: Path,
    git_binary: Path,
    ffprobe_path: Path,
    ffmpeg_path: Path,
    tesseract_path: Path,
) -> None:
    video_root = video_root.resolve()
    manifest_path = manifest_path.resolve()
    trusted_git_root = absolute_directory(str(trusted_git_root), "trusted git root")
    git_binary = absolute_tool_path(str(git_binary), "git")
    ffprobe_path = absolute_tool_path(str(ffprobe_path), "ffprobe")
    ffmpeg_path = absolute_tool_path(str(ffmpeg_path), "ffmpeg")
    tesseract_path = absolute_tool_path(str(tesseract_path), "tesseract")
    fail(manifest_path == video_root / "manifest.json", "manifest must be the package manifest.json")
    validate_commit_binding(video_root, manifest_path, expected_artifact_commit, trusted_git_root, git_binary)
    expected_schema_sha256 = normalize_sha(expected_schema_sha256)
    expected_validator_sha256 = normalize_sha(expected_validator_sha256)
    schema_path = video_root / "evidence/manifest.schema.json"
    fail(digest(schema_path) == expected_schema_sha256, "package schema is not the externally pinned schema")
    fail(digest(Path(__file__).resolve()) == expected_validator_sha256, "validator source is not externally pinned")
    manifest = strict_load(manifest_path)
    schema = strict_load(schema_path)
    Draft202012Validator.check_schema(schema)
    fail(schema.get("$id") == SCHEMA_ID, "schema id drifted")
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)

    fail(set(manifest) == EXPECTED_MANIFEST_KEYS, "manifest key set drifted")
    fail(manifest["schema"] == SCHEMA_ID, "manifest schema id mismatch")
    fail(manifest["schema_sha256"] == expected_schema_sha256, "manifest schema digest is not externally pinned")
    fail(manifest["validator_sha256"] == expected_validator_sha256, "manifest validator digest is not externally pinned")
    fail(manifest["status"] == "REFERENCE_RUNTIME_EVIDENCE_ONLY", "status overclaim")
    fail(manifest["recorded_source_commit"] == RECORDED_SOURCE_COMMIT, "recorded source commit is not the pinned full commit")
    resolved_commit = git_output(git_binary, trusted_git_root, "rev-parse", f"{RECORDED_SOURCE_COMMIT}^{{commit}}")
    fail(resolved_commit == RECORDED_SOURCE_COMMIT, "recorded source commit does not exist")
    fail(manifest["sequence"] == FIXED_SEQUENCE, "sequence claim drifted from the trusted capture contract")
    fail(manifest["network_policy"] == NETWORK_POLICY, "manifest network policy differs from the trusted capture contract")
    fail(manifest["classification"] == "PUBLIC_SYNTHETIC", "classification overclaim")
    fail(manifest["external_side_effects_enabled"] is False, "external side-effects claim overclaim")
    fail(manifest["llm"] == "OFF" and manifest["workers"] == "Stopped" and manifest["readyWorkers"] == 0, "runtime boundary overclaim")
    fail(manifest["audio_role"] == "AAC_PLACEHOLDER_SILENCE_NOT_NARRATION", "silent audio was labelled as narration")
    fail(manifest["claims"] == {
        "benchmark_11_of_11": "STRUCTURE_COMPLETE_ONLY",
        "calculation_60000": "PUBLIC_SYNTHETIC_REFERENCE_VALUE_NOT_LEGAL_CONCLUSION",
        "evaluation_scores": None,
        "legal_accuracy": "UNKNOWN",
        "worker_llm_evaluation": "UNKNOWN",
    }, "claim set overclaim")
    fail("source_commit" not in manifest and "artifact_commit" not in manifest and "artifact_payload_commit" not in manifest, "legacy commit field present")

    tooling = inspect_tooling({"ffprobe": ffprobe_path, "ffmpeg": ffmpeg_path, "tesseract": tesseract_path})
    fail(manifest["tooling"] == tooling, "manifest tool provenance does not match the independently inspected binaries")

    artifact_hashes = manifest["artifact_hashes"]
    fail(set(artifact_hashes) == set(ARTIFACT_PATHS), "artifact hash key set drifted")
    for relative, expected in artifact_hashes.items():
        fail(SHA256_PATTERN.fullmatch(expected) is not None, f"invalid artifact digest: {relative}")
        fail(digest(safe_path(video_root, relative)) == expected, f"artifact hash mismatch: {relative}")
    fail(artifact_hashes["evidence/manifest.schema.json"] == expected_schema_sha256, "schema artifact digest mismatch")
    fail(artifact_hashes["evidence/validate_manifest.py"] == expected_validator_sha256, "validator artifact digest mismatch")

    render_hashes = manifest["render_input_hashes"]
    fail(set(render_hashes) == set(RENDER_INPUT_PATHS), "render input key set drifted")
    for relative, expected in render_hashes.items():
        fail(digest(safe_path(video_root, relative)) == expected, f"render input hash mismatch: {relative}")
    fail(manifest["render_input_digest"] == aggregate_hash(render_hashes), "render input aggregate digest mismatch")

    network = strict_load(safe_path(video_root, "evidence/network-ledger.json"))
    fail(set(network) == {"schema", "policy", "client", "proxy_env_used", "redirects_followed", "requests", "redirect_regression", "non_loopback_requests_sent"}, "network ledger key set drifted")
    fail(network["policy"] == NETWORK_POLICY and network["client"] == "http.client.HTTPConnection", "network ledger policy differs from generator")
    fail(network["proxy_env_used"] is False and network["redirects_followed"] is False, "capture client transport boundary drifted")
    fail(network["non_loopback_requests_sent"] == 0 and manifest["network_ledger_non_loopback_requests_sent"] == 0, "capture client sent a non-loopback request")
    fail(network["redirect_regression"] == {"location_observed": True, "redirect_followed": False, "sink_requests": 0, "status": 302}, "redirect regression evidence drifted")
    fail(len(network["requests"]) == 11, "network request count drifted")
    for item in network["requests"]:
        fail(set(item) == {"decision", "method", "seq", "status", "url"}, "network request row key set drifted")
        parsed = urlsplit(item["url"])
        if item["decision"] == "ALLOW_LOOPBACK":
            fail(parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}, "non-loopback allow decision")
        elif item["decision"] == "BLOCK_BEFORE_SOCKET":
            fail(item["url"] == "https://external.invalid/blocked-by-loopback-policy", "unexpected blocked target")
        else:
            fail(False, "unknown network decision")

    action = strict_load(safe_path(video_root, "evidence/action-ledger.json"))
    fail(set(action) == {"schema", "captured_at", "runtime_status", "classification", "workers", "readyWorkers", "llm", "fixture_pin", "rule_pin", "actions", "benchmark_contract_pass_fraction", "benchmark_accuracy_claim", "benchmark_report_hash", "benchmark_report_hash_reproducible", "benchmark_report_hash_provenance"}, "action ledger key set drifted")
    expected_actions = ["PREPARE", "PACKAGE", "APPROVE", "PACKAGE", "VERIFY", "BENCHMARK"]
    fail([item["action"] for item in action["actions"]] == expected_actions, "action sequence drifted")
    fail([item["http_status"] for item in action["actions"]] == [200, 409, 200, 200, 200, 200], "action statuses drifted")
    fail(all(item["evidence"] == "PASS" for item in action["actions"]), "action ledger contains a failed evidence row")
    fail(action["actions"][1]["code"] == "HUMAN_GATE_REQUIRED", "fail-closed code drifted")
    fail(action["benchmark_contract_pass_fraction"] == "11/11" and action["benchmark_accuracy_claim"] == "NOT_MEASURED", "benchmark claim drifted")
    fail(REPORT_HASH_PATTERN.fullmatch(action["benchmark_report_hash"]) is not None, "benchmark report hash is not a digest")
    fail(action["benchmark_report_hash_reproducible"] is False and action["benchmark_report_hash_provenance"] == REPORT_HASH_PROVENANCE, "benchmark replay provenance overclaim")

    dom = strict_load(safe_path(video_root, "evidence/dom-states.json"))
    fail(set(dom) == {"fixed_sequence", "page", "schema", "states"}, "DOM ledger key set drifted")
    fail(dom["fixed_sequence"] == FIXED_SEQUENCE and dom["page"] == "http://127.0.0.1:8765", "DOM fixed sequence drifted")
    fail([item["action"] for item in dom["states"]] == expected_actions, "DOM action states drifted")
    for item in dom["states"]:
        boundaries = item["state"]["boundaries"]
        fail(boundaries["classification"] == "PUBLIC_SYNTHETIC", "DOM classification overclaim")
        fail(boundaries["llm_enabled"] is False, "DOM LLM boundary overclaim")
        fail(boundaries["workers"] == "Stopped" and boundaries["readyWorkers"] == 0, "DOM worker boundary overclaim")
        fail(boundaries["external_side_effects_enabled"] is False, "DOM side-effect boundary overclaim")
    benchmark = dom["states"][-1]["state"]["benchmark"]
    fail(benchmark["report_hash"] == action["benchmark_report_hash"], "benchmark report hash is not bound across ledgers")
    fail(benchmark["contract_pass_fraction"] == "11/11" and benchmark["legal_accuracy_measured"] is False and benchmark["performance_measured"] is False, "benchmark semantic boundary drifted")

    lint = strict_load(safe_path(video_root, "evidence/lint-summary.json"))
    fail(lint["schema"] == "proofflow.reference-runtime.lint-summary.v1", "lint summary schema mismatch")
    fail(lint["tool"] == "hyperframes" and VERSION_PATTERN.fullmatch(lint["tool_version"] or "") is not None, "lint tool version missing")
    fail(lint["index_sha256"] == digest(safe_path(video_root, "index.html")), "lint summary is not bound to final index")
    fail(lint["ok"] is True and lint["errorCount"] == 0 and lint["paths_redacted"] is True, "lint summary is not passing")

    live_privacy_paths, live_privacy_digest, live_privacy_matches = privacy_provenance(video_root, expected_validator_sha256)
    privacy = strict_load(safe_path(video_root, "evidence/privacy-scan.json"))
    fail(privacy["schema"] == "proofflow.reference-runtime.privacy-scan.v2", "privacy scan schema mismatch")
    fail(privacy["input_paths"] == live_privacy_paths and privacy["input_digest"] == live_privacy_digest, "privacy scan input inventory is stale")
    fail(live_privacy_matches == [] and privacy["matches"] == [], "live privacy scan found a match")
    fail(manifest["privacy_provenance"] == {
        "scanner": PRIVACY_SCANNER_NAME,
        "scanner_sha256": expected_validator_sha256,
        "input_paths": live_privacy_paths,
        "excluded_from_digest": sorted(PRIVACY_EXCLUDED),
        "input_digest": live_privacy_digest,
        "matches": [],
    }, "manifest privacy provenance is not bound to the live scanner")

    live_claim_matches, live_claim_digest = claim_scan(video_root, tesseract_path)
    claim = manifest["claim_provenance"]
    fail(live_claim_matches == [] and claim["forbidden_matches"] == [], "live visible-claim scan found an overclaim")
    fail(claim["scanner"] == CLAIM_SCANNER_NAME and claim["scanner_sha256"] == expected_validator_sha256, "claim scanner source is not pinned")
    fail(claim["excluded_from_digest"] == ["manifest.json"], "claim scanner self-reference exclusion drifted")
    fail(claim["input_paths"] == claim_text_inputs(video_root) and claim["input_digest"] == live_claim_digest, "claim scanner input inventory is stale")

    video = safe_path(video_root, "renders/reference-runtime-evidence.mp4")
    media = ffprobe(video, ffprobe_path, "-show_entries", "format=duration,format_name:stream=index,codec_name,codec_type,width,height,pix_fmt,r_frame_rate,channels,sample_rate")
    fail(media == manifest["ffprobe"], "manifest ffprobe does not match the independently probed MP4")
    fail(media["format"] == {"duration": "92.000000", "format_name": "mov,mp4,m4a,3gp,3g2,mj2"}, "delivered MP4 format or duration is not pinned")
    fail(media["streams"] == [
        {"codec_name": "h264", "codec_type": "video", "height": 1080, "index": 0, "pix_fmt": "yuv420p", "r_frame_rate": "30/1", "width": 1920},
        {"channels": 2, "codec_name": "aac", "codec_type": "audio", "index": 1, "r_frame_rate": "0/0", "sample_rate": "48000"},
    ], "delivered MP4 stream contract drifted")
    fail(math.isclose(float(media["format"]["duration"]), 92.0, abs_tol=1e-6), "delivered MP4 duration is not 92 seconds")
    fail(math.isclose(manifest["actual_duration_seconds"], 92.0, abs_tol=1e-6) and manifest["duration_seconds"] == 92, "manifest duration drifted")
    atoms = atom_positions(video)
    fail("moov" in atoms and "mdat" in atoms and atoms["moov"] < atoms["mdat"], "MP4 is not faststart moov<mdat")
    fail(manifest["faststart"] is True and manifest["moov_atom_before_mdat"] is True, "manifest faststart flags drifted")

    actual_keyframes = keyframe_probes(video, ffprobe_path)
    declared_keyframes = manifest["keyframe_probes"]
    fail([item["target_seconds"] for item in declared_keyframes] == list(TARGETS), "keyframe target set drifted")
    for declared, actual in zip(declared_keyframes, actual_keyframes):
        fail(declared["key_frame"] == actual["key_frame"] == 1, "declared keyframe is not an actual I-frame")
        fail(declared["pict_type"] == actual["pict_type"] == "I", "declared keyframe picture type drifted")
        fail(declared["within_one_frame"] is True and actual["within_one_frame"] is True, "keyframe is outside one frame")
        fail(math.isclose(declared["nearest_frame_seconds"], actual["nearest_frame_seconds"], abs_tol=1e-9), "keyframe timestamp was forged")

    bindings = manifest["frame_bindings"]
    fail(len(bindings) == len(SNAPSHOT_BINDINGS), "frame binding count drifted")
    seen_snapshots: set[str] = set()
    seen_targets: set[float] = set()
    for declared, (relative, target) in zip(bindings, SNAPSHOT_BINDINGS):
        fail(declared["snapshot"] == relative and declared["target_seconds"] == target, "frame binding order or time drifted")
        fail(relative not in seen_snapshots and target not in seen_targets, "frame binding is duplicated")
        seen_snapshots.add(relative)
        seen_targets.add(target)
        actual = compare_frame(video, safe_path(video_root, relative), target, ffmpeg_path)
        actual["snapshot"] = relative
        for key in ("snapshot_sample_sha256", "video_sample_sha256"):
            fail(declared[key] == actual[key], f"frame binding digest was forged for {relative}")
        fail(math.isclose(declared["sampled_mae"], actual["sampled_mae"], abs_tol=1e-6), f"frame binding MAE was forged for {relative}")
        fail(math.isclose(declared["sampled_equal_ratio"], actual["sampled_equal_ratio"], abs_tol=1e-6), f"frame binding equality was forged for {relative}")

    parse_srt(safe_path(video_root, "subtitles.srt"))
    expected_frame_commitment = verify_frame_commitment(video_root, video, ffmpeg_path)
    fail(manifest["frame_commitment"] == expected_frame_commitment, "frame commitment metadata is not independently bound")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a reference-runtime evidence package with external trust pins.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_VIDEO_ROOT / "manifest.json")
    parser.add_argument("--video-root", type=Path, default=DEFAULT_VIDEO_ROOT)
    parser.add_argument("--expected-schema-sha256", required=True, help="SHA-256 of the trusted manifest schema")
    parser.add_argument("--expected-validator-sha256", required=True, help="SHA-256 of this trusted validator source")
    parser.add_argument("--expected-artifact-commit", required=True, help="full 40-character commit of the trusted artifact tree")
    parser.add_argument("--trusted-git-root", type=Path, required=True, help="absolute trusted worktree containing the expected artifact commit")
    parser.add_argument("--git-binary", type=Path, required=True, help="absolute git executable; PATH lookup is forbidden")
    parser.add_argument("--ffprobe", type=Path, required=True, help="absolute ffprobe executable; PATH lookup is forbidden")
    parser.add_argument("--ffmpeg", type=Path, required=True, help="absolute ffmpeg executable; PATH lookup is forbidden")
    parser.add_argument("--tesseract", type=Path, required=True, help="absolute tesseract executable; PATH lookup is forbidden")
    args = parser.parse_args()
    try:
        validate_manifest(
            args.manifest,
            args.video_root,
            args.expected_schema_sha256,
            args.expected_validator_sha256,
            args.expected_artifact_commit,
            args.trusted_git_root,
            args.git_binary,
            args.ffprobe,
            args.ffmpeg,
            args.tesseract,
        )
    except Exception as error:
        print(f"manifest validation FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print("manifest schema + independent semantic validation: PASS")


if __name__ == "__main__":
    main()
