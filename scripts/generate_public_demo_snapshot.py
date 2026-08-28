"""Generate the public landing snapshot from one reviewed Git object.

The landing page is intentionally newer than the product source commit.  This
generator reads product files with ``git cat-file`` so an edited worktree cannot
silently become evidence for the pinned product snapshot.

The full-suite count is a separately pinned GitHub Actions declaration for that
commit.  It is not derived from Git blobs and never changes
``generator_executed_tests=false``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

ROOT: Final = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT: Final = ROOT / "public-demo" / "evidence-snapshot.json"

SOURCE_COMMIT: Final = "68911dbb2858be3b217b0b80c62eea9df57ed595"
SOURCE_TREE: Final = "be7d5d59ddbdb25bd9ab0d2480e833da829de03f"
SOURCE_COMMITTED_AT: Final = "2026-08-29T05:34:46+08:00"
SOURCE_CI_RUN_ID: Final = 33213175597
SOURCE_CI_RUN_URL: Final = "https://github.com/MyGarfield/ProofFlow/actions/runs/33213175597"

ACTION_SCHEMA_PATHS: Final = (
    "schemas/action-certificate-dsse-envelope.schema.json",
    "schemas/action-certificate-expected-binding.schema.json",
    "schemas/action-certificate-predicate-v0p1.schema.json",
    "schemas/action-certificate-revocation-snapshot.schema.json",
    "schemas/action-certificate-statement-v0p1.schema.json",
    "schemas/action-certificate-trust-policy-v0p1.schema.json",
    "schemas/action-certificate-verification-result-v0p1.schema.json",
)

SUPPLY_FRESHNESS_ASSET_PATHS: Final = (
    ".github/workflows/release-supply-chain-evidence.yml",
    "deploy/tool-service/evidence/supply-chain-evidence.schema.json",
    "deploy/tool-service/evidence/supply-chain-release-policy.schema.json",
    "deploy/tool-service/scripts/collect_supply_chain_evidence.py",
    "deploy/tool-service/scripts/validate_supply_chain_evidence.py",
)

PRODUCT_ASSET_PATHS: Final = (
    "README.md",
    ".github/workflows/ci.yml",
    "docs/12_GLOBAL_PRODUCT_ROADMAP.md",
    "docs/13_ACTION_CERTIFICATE_V0P1.md",
    "benchmarks/evaluation/README.md",
    "deploy/tool-service/SUPPLY_CHAIN_EVIDENCE.md",
    "src/proofflow/action_certificate.py",
    *ACTION_SCHEMA_PATHS,
    *SUPPLY_FRESHNESS_ASSET_PATHS,
)

FIXTURE_PATHS: Final = (
    "examples/cases/happy_path/contract.json",
    "examples/cases/happy_path/manifest.json",
    "examples/cases/happy_path/payroll.json",
    "examples/cases/happy_path/termination_notice.json",
)


class SnapshotGenerationError(RuntimeError):
    """Raised when the pinned source object cannot support the declared snapshot."""


def _git_bytes(repository_root: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotepath=false", *arguments],
            cwd=repository_root,
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SnapshotGenerationError("cannot read the pinned Git object") from exc
    if result.returncode != 0:
        raise SnapshotGenerationError("the pinned Git object or asset is unavailable")
    return result.stdout


def _git_text(repository_root: Path, *arguments: str) -> str:
    try:
        return _git_bytes(repository_root, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise SnapshotGenerationError("Git metadata was not valid UTF-8") from exc


def _blob(repository_root: Path, commit: str, path: str) -> bytes:
    return _git_bytes(repository_root, "cat-file", "blob", f"{commit}:{path}")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _record(repository_root: Path, commit: str, path: str) -> dict[str, Any]:
    payload = _blob(repository_root, commit, path)
    return {"path": path, "sha256": _sha256(payload), "bytes": len(payload)}


def _bundle_digest(records: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        records,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256(payload)


def _require_source_claims(repository_root: Path, commit: str) -> None:
    readme = _blob(repository_root, commit, "README.md").decode("utf-8")
    action_doc = _blob(repository_root, commit, "docs/13_ACTION_CERTIFICATE_V0P1.md").decode(
        "utf-8"
    )
    evaluation_doc = _blob(repository_root, commit, "benchmarks/evaluation/README.md").decode(
        "utf-8"
    )
    supply_doc = _blob(
        repository_root, commit, "deploy/tool-service/SUPPLY_CHAIN_EVIDENCE.md"
    ).decode("utf-8")

    required_fragments = (
        (readme, "ActionCertificate v0.1"),
        (readme, "569 passed"),
        (readme, "53 passed"),
        (readme, "Worker 容器数为 0"),
        (action_doc, "pre-execution slice"),
        (action_doc, "It is not a production release gate"),
        (readme, "PROTOCOL_VALIDATED_NOT_EXECUTED"),
        (evaluation_doc, "UNKNOWN"),
        (supply_doc, "Current status: historical snapshot, stale for this branch"),
        (supply_doc, "not evidence for the current build"),
        (supply_doc, "v1.2 freshness and release binding contract"),
    )
    missing = [fragment for text, fragment in required_fragments if fragment not in text]
    if missing:
        raise SnapshotGenerationError(
            "pinned source no longer supports the reviewed claims: " + ", ".join(missing)
        )


def build_snapshot(
    repository_root: Path = ROOT,
    *,
    source_commit: str = SOURCE_COMMIT,
) -> dict[str, Any]:
    """Build the closed public snapshot from the exact reviewed source commit."""
    if source_commit != SOURCE_COMMIT:
        raise SnapshotGenerationError("source commit is outside the reviewed snapshot contract")

    actual_commit = _git_text(repository_root, "rev-parse", f"{source_commit}^{{commit}}")
    actual_tree = _git_text(repository_root, "rev-parse", f"{source_commit}^{{tree}}")
    committed_at = _git_text(repository_root, "show", "-s", "--format=%cI", source_commit)
    if actual_commit != SOURCE_COMMIT or actual_tree != SOURCE_TREE:
        raise SnapshotGenerationError("pinned source commit or tree does not match the review pin")
    if committed_at != SOURCE_COMMITTED_AT:
        raise SnapshotGenerationError(
            "pinned source commit timestamp does not match the review pin"
        )

    _require_source_claims(repository_root, source_commit)
    product_assets = [_record(repository_root, source_commit, path) for path in PRODUCT_ASSET_PATHS]
    fixtures = [_record(repository_root, source_commit, path) for path in FIXTURE_PATHS]

    return {
        "schema_version": "2.0",
        "snapshot_scope": "CURRENT_CORE_ALPHA_SOURCE_OBJECT",
        "classification": "PUBLIC_SYNTHETIC",
        "repository": "https://github.com/MyGarfield/ProofFlow",
        "source": {
            "branch": "main",
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
            "committed_at": SOURCE_COMMITTED_AT,
            "commit_signature_verified_by_generator": False,
        },
        "landing": {
            "mode": "STATIC_READ_ONLY_SOURCE_SNAPSHOT",
            "included_in_source_commit": False,
            "self_authenticating": False,
            "runtime_connected": False,
            "remote_runtime_exposed": False,
            "tracking_enabled": False,
            "base_path_contract": "/ProofFlow/",
        },
        "current_core": {
            "status": "CURRENT_CORE_ALPHA_SNAPSHOT",
            "action_certificate": {
                "version": "v0.1",
                "merged_into_source": True,
                "verification_scope": "PRE_EXECUTION_AUTHORIZATION_ONLY",
                "production_release_gate": False,
                "schema_count": len(ACTION_SCHEMA_PATHS),
            },
            "test_counts": {
                "full_repo_provenance": "PINNED_MAIN_CI_DECLARATION",
                "full_repo_ci_run_id": SOURCE_CI_RUN_ID,
                "full_repo_ci_run_url": SOURCE_CI_RUN_URL,
                "full_repo_ci_head_sha": SOURCE_COMMIT,
                "full_repo_total": 610,
                "full_repo_passed": 609,
                "full_repo_skipped": 1,
                "source_readme_declared_full_repo_passed": 569,
                "action_certificate_provenance": "SOURCE_README_DECLARATION",
                "action_certificate_passed": 53,
                "generator_executed_tests": False,
            },
        },
        "runtime_boundary": {
            "workers": "Stopped",
            "readyWorkers": 0,
            "worker_containers": 0,
            "llm_enabled": False,
            "external_side_effects_enabled": False,
            "real_case_data_used": False,
            "legal_advice": False,
        },
        "evaluation_boundary": {
            "status": "PROTOCOL_VALIDATED_NOT_EXECUTED",
            "deterministic_reference_score": None,
            "single_agent_score": None,
            "six_agent_score": None,
            "official_score": None,
        },
        "supply_chain_boundary": {
            "status": "STALE",
            "historical_snapshot_only": True,
            "release_eligible": False,
            "fresh_build_scan_and_provenance_required": True,
            "freshness_release_gate_implemented": True,
            "release_policy_schema_bound": True,
            "release_workflow_is_disabled_design": True,
        },
        "product_assets": {
            "hash_kind": "UNSIGNED_GIT_BLOB_CONTENT_DIGEST",
            "bundle_sha256": _bundle_digest(product_assets),
            "entries": product_assets,
        },
        "fixture_bundle": {
            "classification": "PUBLIC_SYNTHETIC",
            "hash_kind": "UNSIGNED_GIT_BLOB_CONTENT_DIGEST",
            "bundle_sha256": _bundle_digest(fixtures),
            "entries": fixtures,
        },
        "non_claims": {
            "production_ready": False,
            "release_ready": False,
            "worker_or_llm_execution_observed": False,
            "evaluation_executed": False,
            "execution_receipt_implemented": False,
            "outcome_closure_implemented": False,
            "digests_are_signatures": False,
            "source_authenticity_proven_by_snapshot": False,
        },
    }


def serialize_snapshot(snapshot: dict[str, Any]) -> bytes:
    return (json.dumps(snapshot, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate the pinned public-demo snapshot.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--source-commit", default=SOURCE_COMMIT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the existing output is the deterministic generated snapshot",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        payload = serialize_snapshot(build_snapshot(ROOT, source_commit=args.source_commit))
    except SnapshotGenerationError as exc:
        print(f"PUBLIC_DEMO_SNAPSHOT_ERROR: {exc}")
        return 2

    output = args.output.resolve()
    if args.check:
        try:
            current = output.read_bytes()
        except OSError:
            current = b""
        if current != payload:
            print("PUBLIC_DEMO_SNAPSHOT_DRIFT")
            return 1
        print("PUBLIC_DEMO_SNAPSHOT_CURRENT")
        print(f"source_commit={SOURCE_COMMIT}")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    print(f"PUBLIC_DEMO_SNAPSHOT_WRITTEN={output}")
    print(f"source_commit={SOURCE_COMMIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
