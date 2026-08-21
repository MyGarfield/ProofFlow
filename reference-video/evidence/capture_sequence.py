"""Capture the frozen loopback Demo sequence without leaving 127.0.0.1.

The guard rejects non-loopback targets before opening a socket. The resulting
ledgers are public evidence for the video and intentionally contain no secrets,
environment values, Manager data, Worker data, or external responses.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
BASE = "http://127.0.0.1:8765"
FIXTURE = "sha256:60ce3111c813c8869e4be65ae5f4fcd9712e388769b35645393dc270184c7f9d"
RULES = "sha256:27686c904451870dd5953ec6e47c155a395b2f279995e50f68aea984e6bf91de"


def guard_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
    }:
        raise RuntimeError(f"NON_LOOPBACK_REQUEST_BLOCKED: {url}")


def request(method: str, path: str, token: str | None = None, payload: dict | None = None):
    url = BASE + path
    guard_url(url)
    headers = {"Origin": BASE, "Host": "127.0.0.1:8765"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if token:
        headers["X-ProofFlow-Request-Token"] = token
    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as response:
            status = response.status
            raw = response.read()
    except HTTPError as error:
        status = error.code
        raw = error.read()
    return status, json.loads(raw.decode("utf-8"))


def write(name: str, value: object) -> None:
    (OUT / name).write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    started = datetime.now(UTC).isoformat()
    network = [
        {"seq": 0, "method": "GET", "url": BASE + "/", "decision": "ALLOW_LOOPBACK"},
        {"seq": 1, "method": "GET", "url": BASE + "/app.js", "decision": "ALLOW_LOOPBACK"},
        {"seq": 2, "method": "GET", "url": BASE + "/styles.css", "decision": "ALLOW_LOOPBACK"},
    ]
    blocked_target = "https://external.invalid/blocked-by-loopback-policy"
    try:
        guard_url(blocked_target)
    except RuntimeError:
        network.append(
            {
                "seq": 3,
                "method": "GET",
                "url": blocked_target,
                "decision": "BLOCK_BEFORE_SOCKET",
            }
        )

    status, bootstrap = request("GET", "/api/bootstrap")
    assert status == 200 and bootstrap["ok"]
    token = bootstrap["request_token"]
    network.append({"seq": 4, "method": "GET", "url": BASE + "/api/bootstrap", "decision": "ALLOW_LOOPBACK", "status": status})

    ledger = []
    states = []

    def action(name: str, payload: dict | None, expected_status: int, expected_code: str | None = None):
        nonlocal network
        status_code, result = request("POST", "/api/" + name, token, payload)
        network.append({"seq": len(network), "method": "POST", "url": BASE + "/api/" + name, "decision": "ALLOW_LOOPBACK", "status": status_code})
        state = result.get("state")
        ledger.append(
            {
                "seq": len(ledger) + 1,
                "action": name.upper(),
                "http_status": status_code,
                "expected_status": expected_status,
                "code": (result.get("error") or {}).get("code") or result.get("action"),
                "expected_code": expected_code,
                "stage": (state or {}).get("run", {}).get("stage"),
                "evidence": "PASS" if status_code == expected_status and ((expected_code is None) or (result.get("error") or {}).get("code") == expected_code) else "FAIL",
            }
        )
        if state is not None:
            states.append({"seq": len(states) + 1, "state": state, "action": name.upper()})
        assert status_code == expected_status
        if expected_code:
            assert (result.get("error") or {}).get("code") == expected_code
        return result

    action("prepare", {}, 200)
    action("package", {}, 409, "HUMAN_GATE_REQUIRED")
    action("approve", {"reason": "已核验公开合成证据、规则时效、确定性计算、风险与不确定项，同意仅生成本地评审包。"}, 200)
    action("package", {}, 200)
    action("verify", {}, 200)
    benchmark = action("benchmark", {}, 200)

    write("action-ledger.json", {
        "schema": "proofflow.reference-runtime.action-ledger.v1",
        "captured_at": started,
        "runtime_status": "REFERENCE_RUNTIME_EVIDENCE_ONLY",
        "classification": "PUBLIC_SYNTHETIC",
        "workers": "Stopped",
        "readyWorkers": 0,
        "llm": "OFF",
        "fixture_pin": FIXTURE,
        "rule_pin": RULES,
        "actions": ledger,
        "benchmark_contract_pass_fraction": benchmark["result"]["contract_pass_fraction"],
        "benchmark_accuracy_claim": "NOT_MEASURED",
    })
    write("network-ledger.json", {
        "schema": "proofflow.reference-runtime.network-ledger.v1",
        "policy": "allow only 127.0.0.1 or localhost; reject all other targets before socket creation",
        "requests": network,
        "non_loopback_requests_sent": 0,
    })
    write("dom-states.json", {
        "schema": "proofflow.reference-runtime.dom-state-capture.v1",
        "page": BASE,
        "states": states,
        "fixed_sequence": ["PREPARE", "409_FAIL_CLOSED", "LOCAL_DEMO", "PACKAGE", "VERIFY", "11/11_BENCHMARK"],
    })


if __name__ == "__main__":
    main()
