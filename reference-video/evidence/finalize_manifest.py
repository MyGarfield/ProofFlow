"""Recompute final hashes and media probes for the evidence-only delivery."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VIDEO_ROOT = ROOT / "reference-video"
VIDEO = VIDEO_ROOT / "renders/reference-runtime-evidence.mp4"
TARGETS = (0, 15, 30, 42, 60, 72, 89)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def ffprobe(*args: str) -> dict:
    raw = subprocess.check_output(["ffprobe", "-v", "error", *args], text=True)
    return json.loads(raw)


def main() -> None:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "b63eeb60^{commit}"], cwd=ROOT, text=True
    ).strip()
    media = ffprobe(
        "-show_entries",
        "format=duration,format_name:stream=index,codec_name,codec_type,width,height,pix_fmt,r_frame_rate,channels,sample_rate",
        "-of",
        "json",
        str(VIDEO),
    )
    frames = ffprobe(
        "-select_streams",
        "v:0",
        "-show_frames",
        "-show_entries",
        "frame=best_effort_timestamp_time,key_frame,pict_type",
        "-of",
        "json",
        str(VIDEO),
    ).get("frames", [])
    keyframe_probes = []
    for target in TARGETS:
        nearest = min(frames, key=lambda frame: abs(float(frame["best_effort_timestamp_time"]) - target))
        keyframe_probes.append(
            {
                "target_seconds": target,
                "nearest_frame_seconds": float(nearest["best_effort_timestamp_time"]),
                "key_frame": int(nearest.get("key_frame", 0)),
                "pict_type": nearest.get("pict_type"),
                "within_one_frame": abs(float(nearest["best_effort_timestamp_time"]) - target) <= (1 / 30),
            }
        )
    rel_paths = [
        "renders/reference-runtime-evidence.mp4",
        "silent-aac.m4a",
        "subtitles.srt",
        "evidence/action-ledger.json",
        "evidence/network-ledger.json",
        "evidence/dom-states.json",
        "evidence/capture_sequence.py",
        "evidence/ffmpeg-image-sequence.txt",
        "evidence/manifest.schema.json",
        "evidence/validate_manifest.py",
        "evidence/test_manifest_validator.py",
        "evidence/lint-summary.json",
        "capture/meta.json",
        "capture/screenshots/scroll-000.png",
        "index.html",
        "DESIGN.md",
        "SCRIPT.md",
        "STORYBOARD.md",
        "snapshots/frame-00-at-5s.png",
        "snapshots/frame-01-at-18s.png",
        "snapshots/frame-02-at-33s.png",
        "snapshots/frame-03-at-49s.png",
        "snapshots/frame-04-at-62s.png",
        "snapshots/frame-05-at-70s.png",
        "snapshots/frame-06-at-84s.png",
    ]
    manifest = json.loads((VIDEO_ROOT / "manifest.json").read_text(encoding="utf-8"))
    manifest.pop("artifact_commit", None)
    manifest.pop("source_commit", None)
    artifact_commit = sys.argv[1] if len(sys.argv) > 1 else None
    manifest.update(
        {
            "recorded_source_commit": source_commit,
            "artifact_payload_commit": artifact_commit or manifest.get("artifact_payload_commit"),
            "artifact_payload_commit_semantics": "commit that first introduced the rendered payload; final delivery commit is reported separately because embedding a commit hash in its own tree is self-referential",
            "actual_duration_seconds": float(media["format"]["duration"]),
            "ffprobe": media,
            "keyframe_probes": keyframe_probes,
            "artifact_hashes": {path: sha256(VIDEO_ROOT / path) for path in rel_paths},
            "network_ledger_non_loopback_requests_sent": json.loads((VIDEO_ROOT / "evidence/network-ledger.json").read_text(encoding="utf-8"))["non_loopback_requests_sent"],
            "network_policy": "capture client only: direct http.client to 127.0.0.1/localhost; no proxy env; no redirects; not a host-wide browser network observation",
            "voiceover_status": "UNAVAILABLE_LOCAL_TTS",
            "audio_role": "AAC_PLACEHOLDER_SILENCE_NOT_NARRATION",
            "render_method": "FFMPEG_FROM_HYPERFRAMES_SNAPSHOTS",
            "render_input_hashes": {path: sha256(VIDEO_ROOT / path) for path in rel_paths if path.startswith("snapshots/")},
        }
    )
    (VIDEO_ROOT / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
