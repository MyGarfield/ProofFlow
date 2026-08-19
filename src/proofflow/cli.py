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
        else:
            report = verify_reference_run(args.run_dir)
            output = report.model_dump(mode="json")
            if not report.valid:
                print(json.dumps(output, ensure_ascii=False, indent=2), file=sys.stderr)
                return 1
    except ReferenceRunError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
