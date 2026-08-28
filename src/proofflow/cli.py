"""Command-line interface for the synthetic ProofFlow reference runtime."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from proofflow.action_certificate import (
    MAX_ENVELOPE_BYTES,
    ApprovalRevocationSnapshot,
    ExpectedBinding,
    InMemoryReplayLedger,
    SnapshotApprovalRevocationResolver,
    TrustPolicy,
    VerificationStatus,
    parse_json_model,
    parse_utc_rfc3339_z,
    verify_action_certificate,
)
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

    certificate = commands.add_parser(
        "certificate", help="verify a signed ActionCertificate without performing its effect"
    )
    certificate_commands = certificate.add_subparsers(dest="certificate_command", required=True)
    certificate_verify = certificate_commands.add_parser(
        "verify", help="verify and process-locally reserve one ActionCertificate"
    )
    certificate_verify.add_argument("--envelope", type=Path, required=True)
    certificate_verify.add_argument("--trust-policy", type=Path, required=True)
    certificate_verify.add_argument("--expected-binding", type=Path, required=True)
    certificate_verify.add_argument("--approval-revocations", type=Path)
    certificate_verify.add_argument(
        "--at",
        required=True,
        help="explicit timezone-aware RFC 3339 verification time",
    )
    certificate_verify.add_argument("--ledger-capacity", type=int, default=10_000)

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


def _read_bounded_local_file(path: Path, *, limit: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a local regular file, not a symlink or reference")
    with path.open("rb") as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return payload


def _read_certificate_envelope(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("envelope must be a local regular file, not a symlink or reference")
    with path.open("rb") as handle:
        return handle.read(MAX_ENVELOPE_BYTES + 1)


def _parse_verification_time(value: str) -> datetime:
    return parse_utc_rfc3339_z(value, "--at")


def _verify_certificate_command(args: argparse.Namespace) -> int:
    envelope = _read_certificate_envelope(args.envelope)
    trust_policy = parse_json_model(
        _read_bounded_local_file(args.trust_policy, limit=256 * 1024, label="trust policy"),
        TrustPolicy,
        "trust policy",
    )
    expected_binding = parse_json_model(
        _read_bounded_local_file(args.expected_binding, limit=128 * 1024, label="expected binding"),
        ExpectedBinding,
        "expected binding",
    )
    resolver = None
    if args.approval_revocations is not None:
        snapshot = parse_json_model(
            _read_bounded_local_file(
                args.approval_revocations,
                limit=256 * 1024,
                label="approval revocation snapshot",
            ),
            ApprovalRevocationSnapshot,
            "approval revocation snapshot",
        )
        resolver = SnapshotApprovalRevocationResolver(snapshot)
    result = verify_action_certificate(
        envelope,
        trust_policy=trust_policy,
        expected_binding=expected_binding,
        replay_ledger=InMemoryReplayLedger(capacity=args.ledger_capacity),
        approval_revocation_resolver=resolver,
        now=_parse_verification_time(args.at),
    )
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
    if result.status == VerificationStatus.ACCEPT:
        return 0
    if result.status == VerificationStatus.REJECT:
        return 1
    return 3


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "certificate":
            return _verify_certificate_command(args)
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
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
