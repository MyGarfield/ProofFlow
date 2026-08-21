"""Semantic validator for the published evidence manifest and ledgers."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VIDEO = ROOT / "reference-video"
SECRET_PATTERN = re.compile(r"(?i)(sk-[a-z0-9]|bearer\s+[a-z0-9]|cookie\s*:|authorization\s*:)")


def digest(path: Path) -> str:
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    return "sha256:" + h


def main() -> None:
    manifest = json.loads((VIDEO / "manifest.json").read_text(encoding="utf-8"))
    schema = json.loads((VIDEO / "evidence/manifest.schema.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == schema["$id"]
    assert re.fullmatch(r"[0-9a-f]{40}", manifest["recorded_source_commit"])
    assert re.fullmatch(r"[0-9a-f]{40}", manifest["artifact_payload_commit"])
    assert manifest["status"] == "REFERENCE_RUNTIME_EVIDENCE_ONLY"
    assert manifest["actual_duration_seconds"] == 92.0
    assert manifest["network_ledger_non_loopback_requests_sent"] == 0
    assert manifest["voiceover_status"] == "UNAVAILABLE_LOCAL_TTS"
    assert manifest["audio_role"] == "AAC_PLACEHOLDER_SILENCE_NOT_NARRATION"
    for relative, expected in manifest["artifact_hashes"].items():
        path = VIDEO / relative
        assert path.is_file(), relative
        assert digest(path) == expected, relative
    network = json.loads((VIDEO / "evidence/network-ledger.json").read_text(encoding="utf-8"))
    assert network["non_loopback_requests_sent"] == 0
    assert network["redirect_regression"] == {"location_observed": True, "redirect_followed": False, "sink_requests": 0, "status": 302}
    for item in network["requests"]:
        assert item["url"].startswith("http://127.0.0.1:8765/") or item["decision"] == "BLOCK_BEFORE_SOCKET"
    action = json.loads((VIDEO / "evidence/action-ledger.json").read_text(encoding="utf-8"))
    assert [item["action"] for item in action["actions"]] == ["PREPARE", "PACKAGE", "APPROVE", "PACKAGE", "VERIFY", "BENCHMARK"]
    assert [item["http_status"] for item in action["actions"]] == [200, 409, 200, 200, 200, 200]
    assert all(item["evidence"] == "PASS" for item in action["actions"])
    assert action["benchmark_contract_pass_fraction"] == "11/11"
    for relative in ("evidence/action-ledger.json", "evidence/network-ledger.json", "evidence/dom-states.json"):
        assert not SECRET_PATTERN.search((VIDEO / relative).read_text(encoding="utf-8")), relative
    probe = subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(VIDEO / "renders/reference-runtime-evidence.mp4")], text=True)
    assert float(json.loads(probe)["format"]["duration"]) == 92.0
    assert all(item["key_frame"] == 1 and item["within_one_frame"] for item in manifest["keyframe_probes"])
    print("manifest schema + semantic validation: PASS")


if __name__ == "__main__":
    main()
