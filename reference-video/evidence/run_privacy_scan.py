"""Scan published text evidence for absolute paths or credential-shaped data."""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path


VIDEO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY = VIDEO_ROOT / "evidence/privacy-scan.json"
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".m4a", ".wav", ".woff", ".woff2", ".pyc"}
EXCLUDED_FROM_DIGEST = {"manifest.json", "evidence/privacy-scan.json"}
PATTERNS = {
    "absolute_path": re.compile(r"/(?:Users|private)/[A-Za-z0-9_.-]+"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{8,}\b"),
    "api_key": re.compile(r"(?i)\bsk-[A-Za-z0-9]{12,}\b"),
    "authorization": re.compile(r"(?i)\bauthorization\s*:\s*[^\s,;]{8,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def inventory() -> list[str]:
    paths = []
    for path in sorted(VIDEO_ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES or "__pycache__" in path.parts:
            continue
        relative = path.relative_to(VIDEO_ROOT).as_posix()
        if relative in EXCLUDED_FROM_DIGEST:
            continue
        paths.append(relative)
    return paths


def aggregate(paths: list[str]) -> str:
    payload = "".join(f"{relative}\t{digest(VIDEO_ROOT / relative)}\n" for relative in sorted(paths)).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def main() -> None:
    files = inventory()
    matches = []
    scan_paths = files + ["manifest.json", "evidence/privacy-scan.json"]
    for relative in scan_paths:
        path = VIDEO_ROOT / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                matches.append({"file": relative, "pattern": name})
    summary = {
        "schema": "proofflow.reference-runtime.privacy-scan.v2",
        "scanner": "run_privacy_scan.py",
        "scanner_sha256": digest(Path(__file__)),
        "input_paths": files,
        "excluded_from_digest": sorted(EXCLUDED_FROM_DIGEST),
        "input_digest": aggregate(files),
        "files_scanned": scan_paths,
        "patterns": sorted(PATTERNS),
        "matches": matches,
        "path_policy": "published text contains no workstation absolute paths or credential-shaped values",
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if matches:
        raise SystemExit("privacy scan found matches")
    print(json.dumps({"files_scanned": len(files), "matches": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
