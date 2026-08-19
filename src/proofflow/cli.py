"""Command-line interface for the synthetic ProofFlow reference runtime."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from proofflow.models import ApprovalDecision
from proofflow.reference_runtime import (
    ReferenceRunError,
    approve_reference_run,
    package_reference_run,
    prepare_reference_run,
    verify_reference_run,
)
from proofflow.tool_server import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_MAX_CONCURRENT_REQUESTS,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_READ_TIMEOUT_SECONDS,
    ToolServerConfigurationError,
    api_token_from_environment,
    serve_tool_service,
)
from proofflow.trusted_store import DEFAULT_TRUSTED_ARTIFACT_CAPACITY


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofflow",
        description="Synthetic-data-only deterministic ProofFlow reference runtime",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare", help="prepare and stop at the Human Gate")
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--rules", type=Path, required=True)
    prepare.add_argument("--run-dir", type=Path, required=True)

    approve = commands.add_parser("approve", help="record an explicit local-demo human decision")
    approve.add_argument("--run-dir", type=Path, required=True)
    approve.add_argument("--approver-id", required=True)
    approve.add_argument("--role", required=True)
    approve.add_argument(
        "--decision", choices=[item.value for item in ApprovalDecision], required=True
    )
    approve.add_argument("--reason", required=True)

    package = commands.add_parser("package", help="generate a controlled local draft")
    package.add_argument("--run-dir", type=Path, required=True)

    verify = commands.add_parser("verify", help="verify artifact and package hashes")
    verify.add_argument("--run-dir", type=Path, required=True)

    serve_tools = commands.add_parser(
        "serve-tools",
        help="serve authenticated synthetic evidence, rule, and calculation REST tools",
    )
    serve_tools.add_argument("--rules", type=Path, required=True)
    serve_tools.add_argument(
        "--rules-sha256",
        required=True,
        help="expected public sha256:<file-bytes> integrity pin for --rules",
    )
    serve_tools.add_argument("--host", default="127.0.0.1")
    serve_tools.add_argument("--port", type=int, default=8787)
    serve_tools.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES)
    serve_tools.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES)
    serve_tools.add_argument(
        "--max-concurrent-requests", type=int, default=DEFAULT_MAX_CONCURRENT_REQUESTS
    )
    serve_tools.add_argument(
        "--trusted-artifact-capacity",
        type=int,
        default=DEFAULT_TRUSTED_ARTIFACT_CAPACITY,
    )
    serve_tools.add_argument(
        "--read-timeout-seconds", type=float, default=DEFAULT_READ_TIMEOUT_SECONDS
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "prepare":
            state = prepare_reference_run(
                manifest_path=args.manifest,
                rule_catalog_path=args.rules,
                run_dir=args.run_dir,
            )
            output = {
                "run_id": state.run_id,
                "stage": state.stage,
                "approval_request_id": state.approval_request_id,
                "agentteams_integrated": state.agentteams_integrated,
            }
        elif args.command == "approve":
            record = approve_reference_run(
                run_dir=args.run_dir,
                approver_id=args.approver_id,
                approver_role=args.role,
                decision=ApprovalDecision(args.decision),
                reason=args.reason,
            )
            output = {
                "approval_id": record.meta.artifact_id,
                "decision": record.decision,
                "approval_method": record.approval_method,
            }
        elif args.command == "package":
            manifest = package_reference_run(run_dir=args.run_dir)
            output = {
                "package_id": manifest.meta.artifact_id,
                "manifest_hash": manifest.manifest_hash,
            }
        elif args.command == "verify":
            report = verify_reference_run(args.run_dir)
            output = report.model_dump(mode="json")
            if not report.valid:
                print(json.dumps(output, ensure_ascii=False, indent=2), file=sys.stderr)
                return 1
        else:
            serve_tool_service(
                host=args.host,
                port=args.port,
                catalog_path=args.rules,
                catalog_sha256=args.rules_sha256,
                api_token=api_token_from_environment(),
                max_body_bytes=args.max_body_bytes,
                max_response_bytes=args.max_response_bytes,
                max_concurrent_requests=args.max_concurrent_requests,
                trusted_artifact_capacity=args.trusted_artifact_capacity,
                read_timeout_seconds=args.read_timeout_seconds,
            )
            return 0
    except ReferenceRunError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ToolServerConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
