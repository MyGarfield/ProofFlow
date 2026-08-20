from __future__ import annotations

import http.client
import json
import re
import sys
import threading
import time
from collections.abc import Iterator
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.server import (  # noqa: E402
    MAX_BODY_BYTES,
    PINNED_FIXTURE_BUNDLE_DIGEST,
    PINNED_RULE_CATALOG_DIGEST,
    ApiProblem,
    DemoApplication,
    DemoConfigurationError,
    DemoHTTPServer,
    _fixture_bundle_digest,
    create_server,
    verify_pinned_inputs,
)
from proofflow.canonical import sha256_file  # noqa: E402


@pytest.fixture
def application() -> Iterator[DemoApplication]:
    app = DemoApplication()
    try:
        yield app
    finally:
        app.close()


@pytest.fixture
def live_server(application: DemoApplication) -> Iterator[DemoHTTPServer]:
    server = create_server(port=0, application=application)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(
    server: DemoHTTPServer,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(*server.server_address, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def _post(
    server: DemoHTTPServer,
    path: str,
    payload: dict[str, Any],
    *,
    origin: str | None = None,
    token: str | None = None,
    content_type: str = "application/json",
) -> tuple[int, dict[str, str], dict[str, Any]]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": content_type,
        "Origin": origin if origin is not None else server.expected_origin,
        "X-ProofFlow-Request-Token": (
            token if token is not None else server.application.request_token
        ),
    }
    status, response_headers, raw = _request(
        server,
        "POST",
        path,
        body=body,
        headers=headers,
    )
    return status, response_headers, json.loads(raw)


def test_frozen_public_synthetic_fixture_and_rules_match_pins() -> None:
    assert _fixture_bundle_digest() == PINNED_FIXTURE_BUNDLE_DIGEST
    assert (
        sha256_file(ROOT / "data/rules/cn_labor_contract_law.catalog.json")
        == PINNED_RULE_CATALOG_DIGEST
    )
    manifest = json.loads(
        (ROOT / "examples/cases/happy_path/manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["fixture_status"] == "SYNTHETIC"
    assert manifest["tenant_id"] == "tenant-public-demo"


def test_fixture_pin_mismatch_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "demo.server._fixture_bundle_digest",
        lambda: "sha256:" + "0" * 64,
    )

    with pytest.raises(DemoConfigurationError, match="does not match its pin"):
        verify_pinned_inputs()


def test_prepare_stops_at_gate_and_discloses_runtime_boundaries(
    application: DemoApplication,
) -> None:
    response = application.dispatch("prepare", {})

    assert response["result"]["stopped_at_human_gate"]
    assert response["state"]["run"]["stage"] == "AWAITING_APPROVAL"
    assert response["state"]["artifacts"] == {
        "audit_verdict": "PASS",
        "calculation_total_cny": "60000",
        "evidence": 13,
        "package_files": 0,
        "proposals": 1,
        "rules": 4,
    }
    assert response["state"]["boundaries"] == {
        "agentteams_integrated": False,
        "classification": "PUBLIC_SYNTHETIC",
        "external_side_effects_enabled": False,
        "llm_enabled": False,
        "network_bind": "127.0.0.1",
        "readyWorkers": 0,
        "workers": "Stopped",
    }


def test_real_journey_blocks_package_then_approves_packages_and_verifies(
    application: DemoApplication,
) -> None:
    application.dispatch("prepare", {})

    with pytest.raises(ApiProblem) as blocked:
        application.dispatch("package", {})
    assert blocked.value.status == HTTPStatus.CONFLICT
    assert blocked.value.code == "HUMAN_GATE_REQUIRED"
    assert application.snapshot()["gate_probe"] == "BLOCKED_AS_EXPECTED"
    assert application.snapshot()["run"]["stage"] == "AWAITING_APPROVAL"
    assert not (application.run_dir / "package").exists()

    reason = "已核验公开合成证据、规则时效、确定性计算、风险与不确定项;同意仅生成本地评审包。"
    approval = application.dispatch("approve", {"reason": reason})
    assert approval["result"] == {
        "approval_method": "LOCAL_DEMO",
        "approved_artifact_hash": approval["state"]["run"]["subject_hash"],
        "decision": "APPROVE",
        "reason_recorded": True,
        "role": "legal-reviewer",
    }
    assert approval["state"]["approval"]["reason"] == reason

    packaged = application.dispatch("package", {})
    assert packaged["result"]["file_count"] == 2
    assert packaged["state"]["run"]["stage"] == "PACKAGED"
    assert packaged["state"]["gate_probe"] == "BLOCKED_AS_EXPECTED"
    assert packaged["state"]["boundaries"]["external_side_effects_enabled"] is False

    verified = application.dispatch("verify", {})
    assert verified["result"] == {
        "checked_artifacts": 25,
        "checked_package_files": 2,
        "errors": [],
        "valid": True,
    }


def test_actions_reject_paths_uploads_roles_and_non_allowlisted_actions(
    application: DemoApplication,
) -> None:
    for action, payload, code in (
        ("prepare", {"path": "/tmp/untrusted"}, "UNEXPECTED_FIELDS"),
        ("prepare", {"upload": "bytes"}, "UNEXPECTED_FIELDS"),
        (
            "approve",
            {"reason": "A sufficiently long synthetic reason.", "role": "admin"},
            "INVALID_APPROVAL_FIELDS",
        ),
        ("shell", {}, "ACTION_NOT_ALLOWED"),
    ):
        with pytest.raises(ApiProblem) as rejected:
            application.dispatch(action, payload)
        assert rejected.value.code == code


def test_benchmark_is_11_of_11_and_uses_clean_independent_temporary_directory(
    application: DemoApplication,
) -> None:
    run_workspace = application.workspace_path
    report = application.dispatch("benchmark", {})["result"]
    benchmark_workspace = application.last_benchmark_workspace

    assert report["contract_pass_fraction"] == "11/11"
    assert report["all_contracts_satisfied"]
    assert len(report["results"]) == 11
    assert all(item["passed"] for item in report["results"])
    assert report["legal_accuracy_measured"] is False
    assert report["performance_measured"] is False
    assert benchmark_workspace is not None
    assert not benchmark_workspace.exists()
    assert run_workspace.exists()
    assert run_workspace not in benchmark_workspace.parents


def test_reset_and_close_remove_process_owned_runtime_directories() -> None:
    application = DemoApplication()
    first_workspace = application.workspace_path
    application.dispatch("prepare", {})

    reset = application.dispatch("reset", {})
    second_workspace = application.workspace_path
    assert reset["result"]["previous_workspace_removed"]
    assert not first_workspace.exists()
    assert second_workspace.exists()
    assert first_workspace != second_workspace

    application.close()
    assert not second_workspace.exists()


def test_dispatch_execution_is_serialized(application: DemoApplication) -> None:
    active = 0
    maximum_active = 0
    calls: list[int] = []
    counter_lock = threading.Lock()

    def observed_prepare() -> dict[str, int]:
        nonlocal active, maximum_active
        with counter_lock:
            active += 1
            maximum_active = max(maximum_active, active)
            call_number = len(calls) + 1
            calls.append(call_number)
        time.sleep(0.03)
        with counter_lock:
            active -= 1
        return {"call": call_number}

    application._prepare = observed_prepare  # type: ignore[method-assign]
    threads = [
        threading.Thread(target=application.dispatch, args=("prepare", {})) for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1)

    assert calls == [1, 2]
    assert maximum_active == 1


def test_snapshot_waits_for_reset_to_publish_one_atomic_state(
    application: DemoApplication,
) -> None:
    application.dispatch("prepare", {})
    reset_entered = threading.Event()
    allow_reset_to_finish = threading.Event()
    original_open_workspace = application._open_workspace
    errors: list[BaseException] = []
    snapshots: list[dict[str, Any]] = []

    def paused_open_workspace() -> None:
        reset_entered.set()
        if not allow_reset_to_finish.wait(timeout=2):
            raise TimeoutError("test did not release reset")
        original_open_workspace()

    def reset() -> None:
        try:
            application.dispatch("reset", {})
        except BaseException as exc:  # pragma: no cover - assertion captures thread failures
            errors.append(exc)

    def read_snapshot() -> None:
        try:
            snapshots.append(application.snapshot())
        except BaseException as exc:  # pragma: no cover - assertion captures thread failures
            errors.append(exc)

    application._open_workspace = paused_open_workspace  # type: ignore[method-assign]
    reset_thread = threading.Thread(target=reset)
    reset_thread.start()
    assert reset_entered.wait(timeout=1)

    reader_thread = threading.Thread(target=read_snapshot)
    reader_thread.start()
    time.sleep(0.05)
    assert reader_thread.is_alive(), "snapshot must wait until reset publishes its new workspace"

    allow_reset_to_finish.set()
    reset_thread.join(timeout=2)
    reader_thread.join(timeout=2)
    application._open_workspace = original_open_workspace  # type: ignore[method-assign]

    assert not reset_thread.is_alive()
    assert not reader_thread.is_alive()
    assert errors == []
    assert snapshots[0]["run"]["stage"] == "NOT_PREPARED"


def test_server_binds_loopback_and_issues_unique_process_tokens() -> None:
    first = DemoApplication()
    second = DemoApplication()
    server = create_server(port=0, application=first)
    try:
        assert server.server_address[0] == "127.0.0.1"
        assert first.request_token != second.request_token
        assert len(first.request_token) >= 32
        assert len(second.request_token) >= 32
    finally:
        server.server_close()
        first.close()
        second.close()


def test_bootstrap_and_static_assets_are_local_only_and_hardened(
    live_server: DemoHTTPServer,
) -> None:
    status, headers, body = _request(live_server, "GET", "/api/bootstrap")
    payload = json.loads(body)
    assert status == HTTPStatus.OK
    assert payload["request_token"] == live_server.application.request_token
    assert payload["state"]["boundaries"]["network_bind"] == "127.0.0.1"
    assert "Access-Control-Allow-Origin" not in headers
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in headers["Content-Security-Policy"]

    assets: dict[str, str] = {}
    for route in ("/", "/styles.css", "/app.js"):
        asset_status, asset_headers, asset_body = _request(live_server, "GET", route)
        assert asset_status == HTTPStatus.OK
        assert asset_headers["Cache-Control"] == "no-store"
        assets[route] = asset_body.decode("utf-8")

    combined = "\n".join(assets.values()).lower()
    assert "https://" not in combined
    assert "http://" not in combined
    assert "@import" not in assets["/styles.css"]
    assert "url(" not in assets["/styles.css"]
    assert "<style" not in assets["/"]
    assert not re.search(r"<script(?![^>]+src=)", assets["/"], re.IGNORECASE)


def test_swiss_style_accessibility_and_responsive_contracts() -> None:
    html = (ROOT / "demo/index.html").read_text(encoding="utf-8")
    css = (ROOT / "demo/styles.css").read_text(encoding="utf-8")

    for literal in (
        "--bg: #FFFFFF;",
        "--fg: #000000;",
        "--accent: #FF0000;",
        "--gold: #FFD700;",
        "--blue: #0000FF;",
        "--hair: #000000;",
        "--sans: -apple-system,BlinkMacSystemFont,"
        '"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC",'
        '"Microsoft YaHei",sans-serif;',
        '--mono: ui-monospace,"SF Mono",Menlo,Consolas,monospace;',
    ):
        assert literal in css
    assert "repeat(12, minmax(0, 1fr))" in css
    assert "@media (max-width: 760px)" in css
    assert "repeat(4, minmax(0, 1fr))" in css
    assert "overflow-x: hidden" in css
    assert "min-height: 44px" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert re.findall(r"border-radius:\s*([^;]+);", css) == ["0"]
    assert "PUBLIC SYNTHETIC" in html
    assert "NO LLM" in html
    assert "LOCAL ONLY" in html
    assert "NO EXTERNAL SIDE EFFECTS" in html
    assert "Stopped" in html
    assert "readyWorkers" in html
    assert "PF-A1…PF-A6" in html
    assert "不把它们表述为已运行的多 Agent Worker" in html


@pytest.mark.parametrize(
    ("headers", "expected_code"),
    [
        ({"Origin": "http://evil.example"}, "ORIGIN_REJECTED"),
        ({"X-ProofFlow-Request-Token": "wrong"}, "REQUEST_TOKEN_REJECTED"),
    ],
)
def test_post_rejects_cross_origin_or_wrong_token(
    live_server: DemoHTTPServer,
    headers: dict[str, str],
    expected_code: str,
) -> None:
    request_headers = {
        "Content-Type": "application/json",
        "Origin": live_server.expected_origin,
        "X-ProofFlow-Request-Token": live_server.application.request_token,
        **headers,
    }
    status, _, body = _request(
        live_server,
        "POST",
        "/api/prepare",
        body=b"{}",
        headers=request_headers,
    )
    payload = json.loads(body)
    assert status == HTTPStatus.FORBIDDEN
    assert payload == {
        "error": {
            "code": expected_code,
            "message": payload["error"]["message"],
            "status": HTTPStatus.FORBIDDEN,
        },
        "ok": False,
        "state": payload["state"],
    }


def test_http_gate_is_exact_409_and_keeps_state_at_awaiting_approval(
    live_server: DemoHTTPServer,
) -> None:
    prepare_status, _, prepare = _post(live_server, "/api/prepare", {})
    assert prepare_status == HTTPStatus.OK
    assert prepare["state"]["run"]["stage"] == "AWAITING_APPROVAL"

    package_status, headers, package = _post(live_server, "/api/package", {})
    assert package_status == HTTPStatus.CONFLICT
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert package["error"]["code"] == "HUMAN_GATE_REQUIRED"
    assert package["error"]["status"] == 409
    assert package["state"]["gate_probe"] == "BLOCKED_AS_EXPECTED"
    assert package["state"]["run"]["stage"] == "AWAITING_APPROVAL"


def test_http_verification_failure_is_a_red_409_not_a_success(
    live_server: DemoHTTPServer,
) -> None:
    assert _post(live_server, "/api/prepare", {})[0] == HTTPStatus.OK
    assert (
        _post(
            live_server,
            "/api/approve",
            {"reason": "已核验公开合成证据与风险;只批准当前固定本地评审对象。"},
        )[0]
        == HTTPStatus.OK
    )
    assert _post(live_server, "/api/package", {})[0] == HTTPStatus.OK

    review_draft = live_server.application.run_dir / "package/review-draft.md"
    review_draft.write_text(
        review_draft.read_text(encoding="utf-8") + "\nTAMPERED\n",
        encoding="utf-8",
    )

    status, _, payload = _post(live_server, "/api/verify", {})
    assert status == HTTPStatus.CONFLICT
    assert payload["ok"] is False
    assert payload["error"]["code"] == "VERIFICATION_FAILED"
    assert payload["state"]["verification"]["valid"] is False
    assert payload["state"]["verification"]["errors"]


def test_ui_loads_the_executable_view_state_contract() -> None:
    javascript = (ROOT / "demo/app.js").read_text(encoding="utf-8")

    assert "module.exports = ProofFlowViewState" in javascript
    assert "ProofFlowViewState.gatePresentation(stage, gateProbeObserved)" in javascript
    assert "ProofFlowViewState.verificationPresentation(" in javascript
    assert "ProofFlowViewState.applyStepPresentation(item, output" in javascript


def test_http_rejects_large_body_queries_media_type_and_closed_routes(
    live_server: DemoHTTPServer,
) -> None:
    base_headers = {
        "Content-Type": "application/json",
        "Origin": live_server.expected_origin,
        "X-ProofFlow-Request-Token": live_server.application.request_token,
    }
    status, _, body = _request(
        live_server,
        "POST",
        "/api/prepare",
        body=b"x" * (MAX_BODY_BYTES + 1),
        headers=base_headers,
    )
    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert json.loads(body)["error"]["code"] == "BODY_TOO_LARGE"

    status, _, body = _post(
        live_server,
        "/api/prepare",
        {},
        content_type="text/plain",
    )
    assert status == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    assert body["error"]["code"] == "JSON_REQUIRED"

    status, _, raw = _request(live_server, "GET", "/api/bootstrap?path=/tmp/file")
    assert status == HTTPStatus.BAD_REQUEST
    assert json.loads(raw)["error"]["code"] == "QUERY_NOT_ALLOWED"

    status, _, body = _post(live_server, "/api/upload", {"file": "data"})
    assert status == HTTPStatus.NOT_FOUND
    assert body["error"]["code"] == "ACTION_NOT_ALLOWED"


def test_http_rejects_host_header_and_cors_preflight(live_server: DemoHTTPServer) -> None:
    status, _, body = _request(
        live_server,
        "GET",
        "/api/bootstrap",
        headers={"Host": "localhost.invalid"},
    )
    assert status == HTTPStatus.FORBIDDEN
    assert json.loads(body)["error"]["code"] == "HOST_REJECTED"

    status, headers, body = _request(live_server, "OPTIONS", "/api/prepare")
    assert status == HTTPStatus.METHOD_NOT_ALLOWED
    assert "Access-Control-Allow-Origin" not in headers
    assert json.loads(body)["error"]["code"] == "CORS_NOT_ENABLED"
