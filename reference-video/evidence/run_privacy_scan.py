"""Scan published text evidence for absolute paths or credential-shaped data."""

from __future__ import annotations

import json
import re
from pathlib import Path


VIDEO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY = VIDEO_ROOT / "evidence/privacy-scan.json"
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".mp4", ".m4a", ".woff", ".woff2"}
PATTERNS = {
    "absolute_path": re.compile(r"/(?:Users|private)/[A-Za-z0-9_.-]+"),
    "bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{8,}"),
    "api_key": re.compile(r"(?i)\bsk-[A-Za-z0-9]{12,}\b"),
}


def main() -> None:
    files = []
    matches = []
    for path in sorted(VIDEO_ROOT.rglob("*")):
        if "__pycache__" in path.parts or path.suffix.lower() == ".pyc":
            continue
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        relative = path.relative_to(VIDEO_ROOT).as_posix()
        if relative == "evidence/privacy-scan.json":
            continue
        files.append(relative)
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                matches.append({"file": relative, "pattern": name})
    summary = {
        "schema": "proofflow.reference-runtime.privacy-scan.v1",
        "files_scanned": files,
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
