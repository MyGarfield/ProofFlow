"""Capture the frozen loopback Demo sequence without leaving 127.0.0.1.

The guard rejects non-loopback targets before opening a socket. The resulting
ledgers are public evidence for the video and intentionally contain no secrets,
environment values, Manager data, Worker data, or external responses.
"""

from __future__ import annotations

import http.client
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit


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


def direct_request(method: str, url: str, headers: dict[str, str] | None = None, payload: dict | None = None):
    """Make one direct HTTP request; never reads proxy env or follows redirects."""
    guard_url(url)
    parsed = urlsplit(url)
    if parsed.scheme != "http":
        raise RuntimeError("capture supports direct HTTP loopback only")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)
    request_headers = {"Host": parsed.netloc, **(headers or {})}
    body = None
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    connection.request(method, parsed.path or "/", body=body, headers=request_headers)
    response = connection.getresponse()
    status = response.status
    raw = response.read()
    response_headers = dict(response.getheaders())
    connection.close()
    return status, raw, response_headers


def request(method: str, path: str, token: str | None = None, payload: dict | None = None):
    headers = {"Origin": BASE, "Host": "127.0.0.1:8765"}
    if token is not None:
        headers["X-ProofFlow-Request-Token"] = token
    status, raw, response_headers = direct_request(method, BASE + path, headers, payload)
    return status, json.loads(raw.decode("utf-8")), response_headers


def run_redirect_regression() -> dict[str, object]:
    """Prove a 302 Location is observed, not followed to a sink."""
    class RedirectHandler(BaseHTTPRequestHandler):
        sink_requests = 0

        def do_GET(self):  # noqa: N802
            if self.path == "/sink":
                type(self).sink_requests += 1
            self.send_response(302)
            self.send_header("Location", "https://proxy.invalid/sink")
            self.end_headers()

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    status, _raw, headers = direct_request("GET", f"http://127.0.0.1:{server.server_port}/redirect")
    server.shutdown()
    thread.join(timeout=2)
    assert status == 302 and headers.get("Location") == "https://proxy.invalid/sink"
    assert RedirectHandler.sink_requests == 0
    return {"status": status, "location_observed": True, "redirect_followed": False, "sink_requests": 0}


def write(name: str, value: object) -> None:
    (OUT / name).write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    started = datetime.now(UTC).isoformat()
    network = []
    for path in ("/", "/app.js", "/styles.css"):
        status, _raw, _headers = direct_request("GET", BASE + path, {"Origin": BASE})
        network.append({"seq": len(network), "method": "GET", "url": BASE + path, "decision": "ALLOW_LOOPBACK", "status": status})
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

    status, bootstrap, _headers = request("GET", "/api/bootstrap")
    assert status == 200 and bootstrap["ok"]
    token = bootstrap["request_token"]
    network.append({"seq": len(network), "method": "GET", "url": BASE + "/api/bootstrap", "decision": "ALLOW_LOOPBACK", "status": status})

    ledger = []
    states = []

    def action(name: str, payload: dict | None, expected_status: int, expected_code: str | None = None):
        nonlocal network
        status_code, result, _headers = request("POST", "/api/" + name, token, payload)
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
        "policy": "capture client uses direct http.client connections to 127.0.0.1/localhost only; reject all other targets before socket creation; no proxy env and no redirects",
        "requests": network,
        "redirect_regression": run_redirect_regression(),
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
