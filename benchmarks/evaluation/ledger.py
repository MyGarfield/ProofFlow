"""Producer for a public v2 evaluation run ledger.

The builder executes only deterministic adapters. Worker arms are represented as
explicit NOT_EXECUTED/UNKNOWN entries until a user-authorized Worker run exists.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from benchmarks.evaluation.deterministic_runner import run_deterministic_scenario
from benchmarks.evaluation.fixture import fixture_manifest_digest
from benchmarks.evaluation.suite import (
    EVALUATION_DIR,
    classify_scenario_observation,
    file_digest,
    validate_manifest,
)


def _unknown_latency() -> dict[str, Any]:
    return {
        "unit": "milliseconds",
        "end_to_end_ms": None,
        "active_compute_ms": None,
        "human_wait_ms": None,
        "complete": False,
        "unknown_reason": "LATENCY_NOT_FROZEN_IN_THIS_LEDGER",
    }


def _unknown_cost() -> dict[str, Any]:
    return {
        "input_tokens": None,
        "output_tokens": None,
        "total_tokens": None,
        "total_cost": None,
        "currency": None,
        "rate_card_id": None,
        "complete": False,
        "unknown_reason": "NO_RATE_CARD_OR_MODEL_COST_RECEIPT",
    }


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


GENESIS_ENTRY_SHA256 = "sha256:" + "0" * 64


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return f"sha256:{sha256(payload).hexdigest()}"


def _entry(
    *,
    arm_id: str,
    scenario: dict[str, Any],
    replicate_id: int,
    attempt: int,
    repository_commit: str,
    result: dict[str, Any] | None,
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, Any]:
    scenario_id = scenario["id"]
    execution_status = "EXECUTED" if result is not None else "NOT_EXECUTED"
    status = "UNKNOWN" if result is None else classify_scenario_observation(scenario, result)
    run_prefix = "run" if result is not None else "not-executed"
    return {
        "entry_id": f"entry-{arm_id}-{scenario_id}-r{replicate_id}-a{attempt}",
        "arm_id": arm_id,
        "scenario_id": scenario_id,
        "replicate_id": replicate_id,
        "attempt": attempt,
        "run_id": f"{run_prefix}-{arm_id}-{scenario_id}-r{replicate_id}-a{attempt}",
        "execution_status": execution_status,
        "status": status,
        "issue_codes": [] if result is None else result["issue_codes"],
        "started_at": _timestamp(started_at),
        "finished_at": _timestamp(finished_at),
        "fixture_manifest_sha256": fixture_manifest_digest(),
        "scenario_manifest_sha256": file_digest(EVALUATION_DIR / "scenarios.json"),
        "repository_commit": repository_commit,
        "worker_evidence_sha256": None,
        "worker_evidence": None,
        "result": result,
        "latency": _unknown_latency(),
        "cost": _unknown_cost(),
    }


def build_run_ledger(
    workspace: Path,
    *,
    repository_commit: str,
    replicate_id: int = 1,
    attempt: int = 1,
    replicate_ids: Sequence[int] | None = None,
    attempts: Sequence[int] | None = None,
    recorded_at: datetime | None = None,
) -> dict[str, Any]:
    """Execute deterministic scenarios and ledger every planned applicable arm."""
    manifest = validate_manifest()
    recorded_at = recorded_at or datetime.now(UTC)
    planned_replicates = tuple(replicate_ids or (replicate_id,))
    planned_attempts = tuple(attempts or (attempt,))
    if any(value < 1 for value in (*planned_replicates, *planned_attempts)):
        raise ValueError("replicate IDs and attempts must be positive")
    entries: list[dict[str, Any]] = []
    workspace.mkdir(parents=True, exist_ok=True)
    for current_replicate in planned_replicates:
        for current_attempt in planned_attempts:
            for scenario in manifest["scenarios"]:
                scenario_id = scenario["id"]
                applicable_arms = set(scenario["arm_ids"])
                if "deterministic_reference" in applicable_arms:
                    runner_binding = scenario["runner_binding"]["deterministic_reference"]
                    if runner_binding is None:
                        raise ValueError(
                            f"deterministic scenario is missing an exact runner: {scenario_id}"
                        )
                    started_at = datetime.now(UTC)
                    result = run_deterministic_scenario(
                        scenario_id,
                        workspace / f"{scenario_id}-r{current_replicate}-a{current_attempt}",
                    )
                    finished_at = datetime.now(UTC)
                    entries.append(
                        _entry(
                            arm_id="deterministic_reference",
                            scenario=scenario,
                            replicate_id=current_replicate,
                            attempt=current_attempt,
                            repository_commit=repository_commit,
                            result=result,
                            started_at=started_at,
                            finished_at=finished_at,
                        )
                    )
                for arm_id in ("single_agent", "six_agent"):
                    if arm_id not in applicable_arms:
                        continue
                    entries.append(
                        _entry(
                            arm_id=arm_id,
                            scenario=scenario,
                            replicate_id=current_replicate,
                            attempt=current_attempt,
                            repository_commit=repository_commit,
                            result=None,
                            started_at=recorded_at,
                            finished_at=recorded_at,
                        )
                    )
    previous_hash = GENESIS_ENTRY_SHA256
    for index, entry in enumerate(entries, start=1):
        entry["entry_index"] = index
        entry["previous_entry_sha256"] = previous_hash
        entry["entry_sha256"] = _canonical_digest(entry)
        previous_hash = entry["entry_sha256"]
    ledger = {
        "schema_version": "proofflow.evaluation-run-ledger/v2",
        "ledger_id": f"proofflow-ledger-{recorded_at.strftime('%Y%m%dT%H%M%SZ')}",
        "append_only": True,
        "entry_key": "arm_id+scenario_id+replicate_id+attempt",
        "coverage_plan": {
            "replicate_ids": list(planned_replicates),
            "attempts": list(planned_attempts),
            "scope": "ALL_APPLICABLE_ARMS_AND_SCENARIOS",
        },
        "entries": entries,
        "provenance": {
            "fixture_manifest_sha256": fixture_manifest_digest(),
            "scenario_manifest_sha256": file_digest(EVALUATION_DIR / "scenarios.json"),
            "repository_commit": repository_commit,
            "collector_version": "proofflow.deterministic-ledger-builder/v2",
            "recorded_at": _timestamp(recorded_at),
        },
    }
    ledger["ledger_root_sha256"] = _canonical_digest(ledger)
    return ledger
