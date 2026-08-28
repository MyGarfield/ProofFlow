"""Pinned artifact and render-input sets for the evidence manifest."""

from __future__ import annotations

SNAPSHOT_PATHS = (
    "snapshots/frame-00-at-5s.png",
    "snapshots/frame-01-at-18s.png",
    "snapshots/frame-02-at-33s.png",
    "snapshots/frame-03-at-49s.png",
    "snapshots/frame-04-at-62s.png",
    "snapshots/frame-05-at-70s.png",
    "snapshots/frame-06-at-84s.png",
)
RENDER_INPUT_PATHS = (
    *SNAPSHOT_PATHS,
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
    "evidence/video-frames.framemd5",
    "evidence/audio-pcm.framemd5",
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
