from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import Thread

from pytest import MonkeyPatch

from benchmarks.performance.benchmark import (
    BenchmarkTarget,
    _request_once,
    summarize_observations,
)
from benchmarks.performance.samples import RequestSample


@contextmanager
def running_server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def running_raw_server(handler: type[BaseRequestHandler]) -> Iterator[str]:
    server = ThreadingTCPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def post_sample(path: str) -> RequestSample:
    return RequestSample(
        name="synthetic_post",
        method="POST",
        path=path,
        body=b"{}",
        expected_skill_status="SUCCESS",
        expected_service_status=None,
    )


def test_environment_proxy_is_ignored_and_never_receives_bearer(
    monkeypatch: MonkeyPatch,
) -> None:
    received_authorization: list[str | None] = []

    class FakeProxy(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_POST(self) -> None:
            received_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            self.wfile.write(b'{"status":"SUCCESS"}')

    with running_server(FakeProxy) as proxy_url:
        for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
            monkeypatch.setenv(variable, proxy_url)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        proxy_port = proxy_url.rsplit(":", 1)[1]
        observation = _request_once(
            BenchmarkTarget(
                "closed-loopback",
                "DIRECT_HTTP",
                f"http://127.0.0.2:{proxy_port}",
            ),
            post_sample("/proxy-must-not-see-this"),
            bearer_token="synthetic-secret-not-for-proxy",
            timeout_seconds=0.2,
        )

    assert received_authorization == []
    assert observation.http_status is None
    assert observation.transport_error is not None


def test_cross_origin_redirect_is_not_followed_and_is_not_success() -> None:
    sink_authorization: list[str | None] = []

    class Sink(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_POST(self) -> None:
            sink_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            self.wfile.write(b'{"status":"SUCCESS"}')

    with running_server(Sink) as sink_url:

        class Redirector(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                del format, args

            def do_POST(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"{sink_url}/token-sink")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        with running_server(Redirector) as redirect_url:
            observation = _request_once(
                BenchmarkTarget("redirect", "DIRECT_HTTP", redirect_url),
                post_sample("/redirect"),
                bearer_token="synthetic-secret-not-for-redirect-target",
                timeout_seconds=1,
            )

    summary = summarize_observations(
        (observation,),
        wall_seconds=0.01,
        expected_skill_status="SUCCESS",
        expected_service_status=None,
    )
    assert sink_authorization == []
    assert observation.http_status == 302
    assert observation.response_read_error is None
    assert summary["http_non_2xx_status_count"] == 1
    assert summary["functional_success_count"] == 0


def test_response_body_has_hard_size_limit() -> None:
    class Oversized(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_POST(self) -> None:
            body = b'{"status":"SUCCESS","padding":"xxxxxxxx"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with running_server(Oversized) as base_url:
        observation = _request_once(
            BenchmarkTarget("oversized", "DIRECT_HTTP", base_url),
            post_sample("/oversized"),
            bearer_token="synthetic-benchmark-token",
            timeout_seconds=1,
            max_response_bytes=16,
        )

    assert observation.http_status == 200
    assert observation.response_read_error == "RESPONSE_TOO_LARGE"
    assert not observation.json_valid


def test_slow_drip_body_hits_aggregate_read_deadline() -> None:
    class SlowDrip(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_POST(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.02)
            except OSError:
                pass

    with running_server(SlowDrip) as base_url:
        observation = _request_once(
            BenchmarkTarget("slow", "DIRECT_HTTP", base_url),
            post_sample("/slow"),
            bearer_token="synthetic-benchmark-token",
            timeout_seconds=0.07,
        )

    assert observation.http_status == 200
    assert observation.response_read_error in {
        "RESPONSE_BODY_DEADLINE",
        "RESPONSE_TOTAL_DEADLINE",
    }
    assert not observation.json_valid


def test_slow_drip_headers_hit_total_request_response_deadline() -> None:
    class SlowHeaders(BaseRequestHandler):
        def handle(self) -> None:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)
            try:
                self.request.sendall(b"HTTP/1.1 200 OK\r\n")
                for _ in range(20):
                    self.request.sendall(b"X-Synthetic: value\r\n")
                    time.sleep(0.02)
                self.request.sendall(b"Content-Length: 2\r\n\r\n{}")
            except OSError:
                pass

    with running_raw_server(SlowHeaders) as base_url:
        started = time.monotonic()
        observation = _request_once(
            BenchmarkTarget("slow-headers", "DIRECT_HTTP", base_url),
            post_sample("/slow-headers"),
            bearer_token="synthetic-benchmark-token",
            timeout_seconds=0.07,
        )
        elapsed = time.monotonic() - started

    assert elapsed < 0.5
    assert (
        observation.transport_error == "REQUEST_RESPONSE_DEADLINE"
        or observation.response_read_error == "RESPONSE_TOTAL_DEADLINE"
    )
