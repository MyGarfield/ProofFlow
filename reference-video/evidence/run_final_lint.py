"""Run HyperFrames lint and write a path-sanitized, index-bound summary."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


VIDEO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY = VIDEO_ROOT / "evidence/lint-summary.json"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    completed = subprocess.run(
        ["npx", "hyperframes", "lint", "--json"],
        cwd=VIDEO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("HyperFrames lint did not return JSON") from error
    metadata = result.get("_meta") or {}
    findings = result.get("findings") or []
    summary = {
        "schema": "proofflow.reference-runtime.lint-summary.v1",
        "tool": "hyperframes",
        "tool_version": metadata.get("version"),
        "command": "npx hyperframes lint --json",
        "index_sha256": digest(VIDEO_ROOT / "index.html"),
        "ok": bool(result.get("ok")) and completed.returncode == 0,
        "errorCount": int(result.get("errorCount", 0)),
        "warningCount": int(result.get("warningCount", 0)),
        "warningCodes": sorted(
            str(item.get("code")) for item in findings if item.get("severity") == "warning"
        ),
        "paths_redacted": True,
    }
    SUMMARY.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if not summary["ok"] or summary["errorCount"] != 0:
        raise SystemExit("HyperFrames lint failed")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
