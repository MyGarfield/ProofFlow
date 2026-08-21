"""Recompute the final evidence manifest from the delivered bytes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact_spec import ARTIFACT_PATHS, RENDER_INPUT_PATHS
from capture_sequence import NETWORK_POLICY
from validate_manifest import (
    CLAIM_SCANNER_NAME,
    FIXED_SEQUENCE,
    REPORT_HASH_PROVENANCE,
    SNAPSHOT_BINDINGS,
    SCHEMA_ID,
    claim_scan,
    compare_frame,
    digest,
    ffprobe,
    inspect_tooling,
    keyframe_probes,
    privacy_provenance,
    atom_positions,
    aggregate_hash,
)


ROOT = Path(__file__).resolve().parents[2]
VIDEO_ROOT = ROOT / "reference-video"
VIDEO = VIDEO_ROOT / "renders/reference-runtime-evidence.mp4"
TARGETS = (0, 15, 30, 42, 60, 72, 89)


def main() -> None:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "b63eeb60^{commit}"], cwd=ROOT, text=True
    ).strip()
    media = ffprobe(
        VIDEO,
        "-show_entries",
        "format=duration,format_name:stream=index,codec_name,codec_type,width,height,pix_fmt,r_frame_rate,channels,sample_rate",
    )
    keyframes = keyframe_probes(VIDEO)
    render_input_hashes = {path: digest(VIDEO_ROOT / path) for path in RENDER_INPUT_PATHS}
    artifact_hashes = {path: digest(VIDEO_ROOT / path) for path in ARTIFACT_PATHS}
    action = json.loads((VIDEO_ROOT / "evidence/action-ledger.json").read_text(encoding="utf-8"))
    network = json.loads((VIDEO_ROOT / "evidence/network-ledger.json").read_text(encoding="utf-8"))
    manifest_path = VIDEO_ROOT / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for legacy_key in ("source_commit", "artifact_commit", "artifact_payload_commit", "artifact_payload_commit_semantics"):
        manifest.pop(legacy_key, None)

    schema_sha256 = digest(VIDEO_ROOT / "evidence/manifest.schema.json")
    validator_sha256 = digest(VIDEO_ROOT / "evidence/validate_manifest.py")
    tooling = inspect_tooling()
    privacy_paths, privacy_digest, privacy_matches = privacy_provenance(VIDEO_ROOT, validator_sha256)
    claim_matches, claim_digest = claim_scan(VIDEO_ROOT)
    frame_bindings = []
    for relative, target in SNAPSHOT_BINDINGS:
        binding = compare_frame(VIDEO, VIDEO_ROOT / relative, target)
        binding["snapshot"] = relative
        frame_bindings.append(binding)
    atom_order = atom_positions(VIDEO)
    faststart = "moov" in atom_order and "mdat" in atom_order and atom_order["moov"] < atom_order["mdat"]
    report_hash = action["benchmark_report_hash"]
    manifest.update(
        {
            "schema": SCHEMA_ID,
            "schema_sha256": schema_sha256,
            "validator_sha256": validator_sha256,
            "recorded_source_commit": source_commit,
            "actual_duration_seconds": float(media["format"]["duration"]),
            "ffprobe": media,
            "keyframe_probes": keyframes,
            "frame_bindings": frame_bindings,
            "artifact_hashes": artifact_hashes,
            "network_ledger_non_loopback_requests_sent": network["non_loopback_requests_sent"],
            "network_policy": NETWORK_POLICY,
            "sequence": FIXED_SEQUENCE,
            "tooling": tooling,
            "render_method": "FFMPEG_FROM_HYPERFRAMES_SNAPSHOTS",
            "render_input_hashes": render_input_hashes,
            "render_input_digest": aggregate_hash(render_input_hashes),
            "lint_summary": "evidence/lint-summary.json",
            "faststart": faststart,
            "moov_atom_before_mdat": faststart,
            "benchmark_report_hash": report_hash,
            "benchmark_report_hash_reproducible": False,
            "benchmark_report_hash_provenance": REPORT_HASH_PROVENANCE,
            "privacy_provenance": {
                "scanner": "trusted-validator-live",
                "scanner_sha256": validator_sha256,
                "input_paths": privacy_paths,
                "excluded_from_digest": ["evidence/privacy-scan.json", "manifest.json"],
                "input_digest": privacy_digest,
                "matches": privacy_matches,
            },
            "claim_provenance": {
                "scanner": CLAIM_SCANNER_NAME,
                "scanner_sha256": validator_sha256,
                "input_paths": ["index.html", "subtitles.srt", *[path for path, _target in SNAPSHOT_BINDINGS]],
                "excluded_from_digest": ["manifest.json"],
                "input_digest": claim_digest,
                "forbidden_matches": claim_matches,
            },
        }
    )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
