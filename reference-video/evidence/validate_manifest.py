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
import os
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

FFPROBE_PATH = Path("/usr/local/Cellar/ffmpeg/8.1.2_1/bin/ffprobe")
FFMPEG_PATH = Path("/usr/local/Cellar/ffmpeg/8.1.2_1/bin/ffmpeg")
TESSERACT_PATH = Path("/usr/local/Cellar/tesseract/5.5.2/bin/tesseract")
EXPECTED_TOOLING = {
    "ffprobe": {
        "path": str(FFPROBE_PATH),
        "sha256": "sha256:501ae4034055451cbd993166b43b7764dd69553ccebbcf55c2730b732b82c570",
        "version": "8.1.2",
        "owner": "Zhuanz",
        "mode": "-r-xr-xr-x",
    },
    "ffmpeg": {
        "path": str(FFMPEG_PATH),
        "sha256": "sha256:434a59ef057cf847f497b95dd394208b61f2f1254728344442d3d2ad71f926bb",
        "version": "8.1.2",
        "owner": "Zhuanz",
        "mode": "-r-xr-xr-x",
    },
    "tesseract": {
        "path": str(TESSERACT_PATH),
        "sha256": "sha256:b18c6b66694a47153a27978378c41333bd1fcb0260f2a64c2305450d825764a0",
        "version": "5.5.2",
        "owner": "Zhuanz",
        "mode": "-r-xr-xr-x",
    },
}

SRT_TIMESTAMP = re.compile(r"^(\d{2}):(\d{2}):(\d{2}),(\d{3})$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
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


def normalize_sha(value: str) -> str:
    if value.startswith("sha256:"):
        normalized = value
    else:
        normalized = "sha256:" + value
    fail(SHA256_PATTERN.fullmatch(normalized) is not None, "expected a SHA-256 digest")
    return normalized


def tool_version(path: Path) -> str:
    flag = "--version" if path.name == "tesseract" else "-version"
    output = subprocess.check_output([str(path), flag], stderr=subprocess.STDOUT, text=True)
    first = output.splitlines()[0]
    match = re.search(r"(?:version\s+|tesseract\s+)(\d+\.\d+\.\d+)", first, flags=re.IGNORECASE)
    fail(match is not None, f"cannot parse tool version: {path}")
    return match.group(1)


def inspect_tool(name: str) -> dict[str, str]:
    expected = EXPECTED_TOOLING[name]
    path = Path(expected["path"])
    fail(path.is_file() and not path.is_symlink(), f"trusted {name} binary is missing or symlinked")
    actual = {
        "path": str(path),
        "sha256": digest(path),
        "version": tool_version(path),
        "owner": pwd.getpwuid(path.stat().st_uid).pw_name,
        "mode": stat.filemode(path.stat().st_mode),
    }
    fail(actual == expected, f"trusted {name} binary identity changed")
    return actual


def inspect_tooling() -> dict[str, dict[str, str]]:
    return {name: inspect_tool(name) for name in ("ffprobe", "ffmpeg", "tesseract")}


def parse_tool_json(raw: str):
    return json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite ffprobe value: {value}")))


def ffprobe(path: Path, *args: str) -> dict:
    raw = subprocess.check_output(
        [str(FFPROBE_PATH), "-v", "error", *args, "-of", "json", str(path)],
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


def raw_rgb(path: Path, target_seconds: float | None = None) -> bytes:
    args = [str(FFMPEG_PATH), "-v", "error", "-i", str(path)]
    if target_seconds is not None:
        args.extend(["-ss", f"{target_seconds:.6f}"])
    args.extend(["-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"])
    return subprocess.check_output(args)


def sampled_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw[::97]).hexdigest()


def compare_frame(video: Path, snapshot: Path, target_seconds: float) -> dict[str, object]:
    snapshot_raw = raw_rgb(snapshot)
    video_raw = raw_rgb(video, target_seconds)
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


def ocr_snapshot(path: Path) -> str:
    completed = subprocess.run(
        [str(TESSERACT_PATH), str(path), "stdout", "--psm", "6"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    fail(completed.returncode == 0, f"tesseract failed for {path.name}")
    return completed.stdout


def claim_scan(root: Path) -> tuple[list[dict[str, str]], str]:
    matches: list[dict[str, str]] = []
    for relative in CLAIM_TEXT_PATHS + ("manifest.json",):
        text = safe_path(root, relative).read_text(encoding="utf-8", errors="replace")
        for name, pattern in FORBIDDEN_CLAIM_PATTERNS.items():
            if pattern.search(text):
                matches.append({"file": relative, "pattern": name})
    for relative in SNAPSHOT_PATHS:
        text = ocr_snapshot(safe_path(root, relative))
        for name, pattern in FORBIDDEN_CLAIM_PATTERNS.items():
            if pattern.search(text):
                matches.append({"file": relative, "pattern": name})
    return matches, claim_input_digest(root)


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
) -> None:
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
    resolved_commit = subprocess.check_output(
        ["git", "rev-parse", f"{RECORDED_SOURCE_COMMIT}^{{commit}}"], cwd=ROOT, text=True
    ).strip()
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

    tooling = inspect_tooling()
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

    live_claim_matches, live_claim_digest = claim_scan(video_root)
    claim = manifest["claim_provenance"]
    fail(live_claim_matches == [] and claim["forbidden_matches"] == [], "live visible-claim scan found an overclaim")
    fail(claim["scanner"] == CLAIM_SCANNER_NAME and claim["scanner_sha256"] == expected_validator_sha256, "claim scanner source is not pinned")
    fail(claim["excluded_from_digest"] == ["manifest.json"], "claim scanner self-reference exclusion drifted")
    fail(claim["input_paths"] == claim_text_inputs(video_root) and claim["input_digest"] == live_claim_digest, "claim scanner input inventory is stale")

    video = safe_path(video_root, "renders/reference-runtime-evidence.mp4")
    media = ffprobe(video, "-show_entries", "format=duration,format_name:stream=index,codec_name,codec_type,width,height,pix_fmt,r_frame_rate,channels,sample_rate")
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

    actual_keyframes = keyframe_probes(video)
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
        actual = compare_frame(video, safe_path(video_root, relative), target)
        actual["snapshot"] = relative
        for key in ("snapshot_sample_sha256", "video_sample_sha256"):
            fail(declared[key] == actual[key], f"frame binding digest was forged for {relative}")
        fail(math.isclose(declared["sampled_mae"], actual["sampled_mae"], abs_tol=1e-6), f"frame binding MAE was forged for {relative}")
        fail(math.isclose(declared["sampled_equal_ratio"], actual["sampled_equal_ratio"], abs_tol=1e-6), f"frame binding equality was forged for {relative}")

    parse_srt(safe_path(video_root, "subtitles.srt"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a reference-runtime evidence package with external trust pins.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_VIDEO_ROOT / "manifest.json")
    parser.add_argument("--video-root", type=Path, default=DEFAULT_VIDEO_ROOT)
    parser.add_argument("--expected-schema-sha256", required=True, help="SHA-256 of the trusted manifest schema")
    parser.add_argument("--expected-validator-sha256", required=True, help="SHA-256 of this trusted validator source")
    args = parser.parse_args()
    try:
        validate_manifest(args.manifest, args.video_root, args.expected_schema_sha256, args.expected_validator_sha256)
    except Exception as error:
        print(f"manifest validation FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print("manifest schema + independent semantic validation: PASS")


if __name__ == "__main__":
    main()
