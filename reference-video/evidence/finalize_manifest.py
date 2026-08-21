"""Recompute the final evidence manifest from the delivered bytes."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from artifact_spec import ARTIFACT_PATHS, RENDER_INPUT_PATHS
from capture_sequence import NETWORK_POLICY


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


def aggregate_hash(entries: dict[str, str]) -> str:
    payload = "".join(f"{path}\t{entries[path]}\n" for path in sorted(entries)).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def ffprobe(*args: str) -> dict:
    raw = subprocess.check_output(["ffprobe", "-v", "error", *args], text=True)
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
            if offset + 16 > len(data):
                break
            size = int.from_bytes(data[offset + 8 : offset + 16], "big")
            header = 16
        elif size == 0:
            size = len(data) - offset
        if size < header or offset + size > len(data):
            break
        positions.setdefault(atom_type, offset)
        offset += size
    return positions


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
        nearest_time = float(nearest["best_effort_timestamp_time"])
        keyframe_probes.append(
            {
                "target_seconds": target,
                "nearest_frame_seconds": nearest_time,
                "key_frame": int(nearest.get("key_frame", 0)),
                "pict_type": nearest.get("pict_type"),
                "within_one_frame": abs(nearest_time - target) <= (1 / 30),
            }
        )

    render_input_hashes = {path: sha256(VIDEO_ROOT / path) for path in RENDER_INPUT_PATHS}
    artifact_hashes = {path: sha256(VIDEO_ROOT / path) for path in ARTIFACT_PATHS}
    ledger = json.loads((VIDEO_ROOT / "evidence/network-ledger.json").read_text(encoding="utf-8"))
    atom_order = atom_positions(VIDEO)
    faststart = "moov" in atom_order and "mdat" in atom_order and atom_order["moov"] < atom_order["mdat"]
    manifest_path = VIDEO_ROOT / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for legacy_key in ("source_commit", "artifact_commit", "artifact_payload_commit", "artifact_payload_commit_semantics"):
        manifest.pop(legacy_key, None)
    manifest.update(
        {
            "schema": "proofflow.reference-runtime-evidence-video.manifest.v2",
            "recorded_source_commit": source_commit,
            "actual_duration_seconds": float(media["format"]["duration"]),
            "ffprobe": media,
            "keyframe_probes": keyframe_probes,
            "artifact_hashes": artifact_hashes,
            "network_ledger_non_loopback_requests_sent": ledger["non_loopback_requests_sent"],
            "network_policy": NETWORK_POLICY,
            "render_method": "FFMPEG_FROM_HYPERFRAMES_SNAPSHOTS",
            "render_input_hashes": render_input_hashes,
            "render_input_digest": aggregate_hash(render_input_hashes),
            "lint_summary": "evidence/lint-summary.json",
            "faststart": faststart,
            "moov_atom_before_mdat": faststart,
        }
    )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
