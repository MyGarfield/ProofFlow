"""Command-line runner for the local ProofFlow HTTP benchmark."""

from __future__ import annotations

import argparse
import os
import secrets
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from benchmarks.performance.benchmark import (
    BenchmarkConfig,
    BenchmarkConfigurationError,
    BenchmarkTarget,
    render_report,
    run_benchmark,
)
from benchmarks.performance.samples import FIXED_NOW, RULE_CATALOG_PATH
from proofflow.contracts import RuleCatalog
from proofflow.tool_server import TOKEN_ENV_VAR, ProofFlowToolHTTPServer


@contextmanager
def running_in_process_service() -> Iterator[tuple[str, str]]:
    """Start the reference service on an ephemeral loopback port for honest local runs."""
    token = secrets.token_urlsafe(32)
    catalog = RuleCatalog.model_validate_json(RULE_CATALOG_PATH.read_bytes())
    server = ProofFlowToolHTTPServer(
        ("127.0.0.1", 0),
        catalog=catalog,
        api_token=token,
        clock=lambda: FIXED_NOW,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}", token
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure local ProofFlow REST health/rule/calc endpoints with Python stdlib. "
            "This is a local single run, not a production SLA or cost benchmark."
        )
    )
    parser.add_argument(
        "--in-process",
        action="store_true",
        help="start an ephemeral loopback tool service and include it in process resources",
    )
    parser.add_argument(
        "--direct-base-url",
        default=None,
        help="local direct tool-service base URL (default: http://127.0.0.1:8787)",
    )
    parser.add_argument(
        "--higress-base-url",
        help="optional authorized Higress HTTP forward exposing the same REST paths",
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="explicitly permit a non-loopback authorized target; never implied by defaults",
    )
    parser.add_argument("--warmup", type=int, default=5, help="warmups per endpoint")
    parser.add_argument("--requests", type=int, default=100, help="measured requests per endpoint")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=Path, help="optional JSON output path")
    return parser


def _run(
    args: argparse.Namespace,
    *,
    direct_url: str,
    token: str | None,
    resource_scope: str,
) -> dict[str, object]:
    targets = [BenchmarkTarget("direct", "DIRECT_HTTP", direct_url)]
    if args.higress_base_url:
        targets.append(BenchmarkTarget("higress", "HIGRESS_HTTP_FORWARD", args.higress_base_url))
    return run_benchmark(
        BenchmarkConfig(
            targets=tuple(targets),
            warmup_requests_per_endpoint=args.warmup,
            measured_requests_per_endpoint=args.requests,
            concurrency=args.concurrency,
            timeout_seconds=args.timeout_seconds,
            allow_non_loopback=args.allow_non_loopback,
            resource_scope=resource_scope,
        ),
        bearer_token=token,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.in_process and args.direct_base_url is not None:
        parser.error("--in-process and --direct-base-url are mutually exclusive")
    try:
        if args.in_process:
            with running_in_process_service() as (direct_url, token):
                report = _run(
                    args,
                    direct_url=direct_url,
                    token=token,
                    resource_scope="CLIENT_AND_SERVICE",
                )
        else:
            report = _run(
                args,
                direct_url=args.direct_base_url or "http://127.0.0.1:8787",
                token=os.environ.get(TOKEN_ENV_VAR),
                resource_scope="RUNNER_ONLY",
            )
    except BenchmarkConfigurationError as error:
        parser.error(str(error))
    rendered = render_report(report)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    summary = report["summary"]
    assert isinstance(summary, dict)
    return 0 if summary["benchmark_run_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
