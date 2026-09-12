from __future__ import annotations

import multiprocessing
import os
import random
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from proofflow.outcome_closure import InMemoryOutcomeClosureIndex, OutcomeIndexStatus
from proofflow.sqlite_outcome_index import SQLiteOutcomeClosureIndex

PAYLOAD_A = "sha256:" + "a" * 64
PAYLOAD_B = "sha256:" + "b" * 64
PAYLOAD_C = "sha256:" + "c" * 64
INTENT_A = "sha256:" + "d" * 64
INTENT_B = "sha256:" + "e" * 64


def append(index: SQLiteOutcomeClosureIndex, **overrides: Any) -> OutcomeIndexStatus:
    values: dict[str, Any] = {
        "tenant_id": "tenant-001",
        "closure_id": "closure-001",
        "execution_id": "execution-001",
        "attempt_id": "attempt-001",
        "closure_sequence": 1,
        "previous_payload_sha256": None,
        "payload_sha256": PAYLOAD_A,
        "idempotency_key": "idempotency-001",
        "intent_sha256": INTENT_A,
    }
    values.update(overrides)
    return index.append_once(**values)


def process_append(path: str, start: Any, queue: Any) -> None:
    start.wait()
    queue.put(append(SQLiteOutcomeClosureIndex(path, busy_timeout_ms=10_000)).value)


class CrashingSQLiteOutcomeClosureIndex(SQLiteOutcomeClosureIndex):
    def _append(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        closure_id: str,
        execution_id: str,
        attempt_id: str,
        closure_sequence: int,
        previous_payload_sha256: str | None,
        payload_sha256: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> OutcomeIndexStatus:
        status = super()._append(
            connection,
            tenant_id=tenant_id,
            closure_id=closure_id,
            execution_id=execution_id,
            attempt_id=attempt_id,
            closure_sequence=closure_sequence,
            previous_payload_sha256=previous_payload_sha256,
            payload_sha256=payload_sha256,
            idempotency_key=idempotency_key,
            intent_sha256=intent_sha256,
        )
        if status == OutcomeIndexStatus.APPENDED:
            os._exit(73)
        return status


def process_crash_before_commit(path: str) -> None:
    append(
        CrashingSQLiteOutcomeClosureIndex(path),
        closure_id="crash-closure",
        execution_id="crash-execution",
        attempt_id="crash-attempt",
        idempotency_key="crash-idempotency",
    )


def test_sequence_survives_reopen_and_uses_private_full_sync_wal(tmp_path: Path) -> None:
    path = tmp_path / "outcomes.db"
    assert append(SQLiteOutcomeClosureIndex(path)) == OutcomeIndexStatus.APPENDED
    assert append(SQLiteOutcomeClosureIndex(path)) == OutcomeIndexStatus.ALREADY_PRESENT
    assert (
        append(
            SQLiteOutcomeClosureIndex(path),
            closure_id="closure-002",
            closure_sequence=2,
            previous_payload_sha256=PAYLOAD_A,
            payload_sha256=PAYLOAD_B,
        )
        == OutcomeIndexStatus.APPENDED
    )
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    assert connection.execute("PRAGMA synchronous").fetchone() == (2,)
    assert connection.execute("SELECT COUNT(*) FROM closure_records").fetchone() == (2,)
    assert connection.execute("SELECT COUNT(*) FROM idempotency_outcomes").fetchone() == (2,)
    connection.close()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_conflict_precedence_and_sequence_semantics_match_in_memory_index(tmp_path: Path) -> None:
    index = SQLiteOutcomeClosureIndex(tmp_path / "outcomes.db")
    assert append(index) == OutcomeIndexStatus.APPENDED
    assert append(index, payload_sha256=PAYLOAD_B) == OutcomeIndexStatus.CLOSURE_ID_CONFLICT
    assert (
        append(index, closure_id="closure-002", payload_sha256=PAYLOAD_B)
        == OutcomeIndexStatus.ATTEMPT_SEQUENCE_CONFLICT
    )
    assert (
        append(
            index,
            closure_id="closure-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
            payload_sha256=PAYLOAD_B,
            intent_sha256=INTENT_B,
        )
        == OutcomeIndexStatus.IDEMPOTENCY_CONFLICT
    )
    assert (
        append(
            index,
            closure_id="closure-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
        )
        == OutcomeIndexStatus.ALREADY_PRESENT
    )
    assert (
        append(
            index,
            closure_id="closure-003",
            closure_sequence=2,
            previous_payload_sha256=PAYLOAD_B,
            payload_sha256=PAYLOAD_C,
        )
        == OutcomeIndexStatus.PREVIOUS_DIGEST_CONFLICT
    )
    assert (
        append(
            index,
            closure_id="closure-003",
            closure_sequence=3,
            previous_payload_sha256=PAYLOAD_A,
            payload_sha256=PAYLOAD_C,
        )
        == OutcomeIndexStatus.ATTEMPT_SEQUENCE_CONFLICT
    )
    assert append(index, tenant_id="tenant-002") == OutcomeIndexStatus.APPENDED


def test_deterministic_operation_sequence_matches_in_memory_index(tmp_path: Path) -> None:
    memory = InMemoryOutcomeClosureIndex(capacity=50)
    sqlite = SQLiteOutcomeClosureIndex(tmp_path / "outcomes.db", capacity=50)
    generator = random.Random(20260912)
    for _ in range(300):
        previous = (
            None if generator.randrange(3) == 0 else (PAYLOAD_A, PAYLOAD_B)[generator.randrange(2)]
        )
        arguments = {
            "tenant_id": f"tenant-{generator.randrange(3)}",
            "closure_id": f"closure-{generator.randrange(30)}",
            "execution_id": f"execution-{generator.randrange(12)}",
            "attempt_id": f"attempt-{generator.randrange(12)}",
            "closure_sequence": generator.randrange(1, 4),
            "previous_payload_sha256": previous,
            "payload_sha256": (PAYLOAD_A, PAYLOAD_B, PAYLOAD_C)[generator.randrange(3)],
            "idempotency_key": f"idempotency-{generator.randrange(20)}",
            "intent_sha256": INTENT_A if generator.randrange(2) == 0 else INTENT_B,
        }
        assert sqlite.append_once(**arguments) == memory.append_once(**arguments)


def test_capacity_failure_does_not_leave_orphan_identity(tmp_path: Path) -> None:
    path = tmp_path / "outcomes.db"
    index = SQLiteOutcomeClosureIndex(path, capacity=1)
    assert append(index) == OutcomeIndexStatus.APPENDED
    second = {
        "tenant_id": "tenant-002",
        "closure_id": "closure-002",
        "execution_id": "execution-002",
        "attempt_id": "attempt-002",
        "idempotency_key": "idempotency-002",
    }
    assert append(index, **second) == OutcomeIndexStatus.UNAVAILABLE
    connection = sqlite3.connect(path)
    assert connection.execute("SELECT COUNT(*) FROM idempotency_outcomes").fetchone() == (1,)
    connection.close()
    assert (
        append(SQLiteOutcomeClosureIndex(path, capacity=2), **second) == OutcomeIndexStatus.APPENDED
    )


@pytest.mark.parametrize("iteration", range(3))
def test_independent_instances_append_atomically_across_threads(
    tmp_path: Path, iteration: int
) -> None:
    path = tmp_path / f"outcomes-{iteration}.db"

    def attempt(_: int) -> OutcomeIndexStatus:
        return append(SQLiteOutcomeClosureIndex(path, busy_timeout_ms=10_000))

    with ThreadPoolExecutor(max_workers=12) as executor:
        statuses = list(executor.map(attempt, range(32)))
    assert statuses.count(OutcomeIndexStatus.APPENDED) == 1
    assert statuses.count(OutcomeIndexStatus.ALREADY_PRESENT) == 31


def test_independent_processes_append_atomically(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(target=process_append, args=(str(tmp_path / "outcomes.db"), start, queue))
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    start.set()
    statuses = [queue.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    assert statuses.count(OutcomeIndexStatus.APPENDED.value) == 1
    assert statuses.count(OutcomeIndexStatus.ALREADY_PRESENT.value) == 5


def test_process_crash_before_commit_leaves_no_partial_append(tmp_path: Path) -> None:
    path = tmp_path / "outcomes.db"
    assert append(SQLiteOutcomeClosureIndex(path)) == OutcomeIndexStatus.APPENDED
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=process_crash_before_commit, args=(str(path),))
    process.start()
    process.join(timeout=20)
    assert process.exitcode == 73
    assert (
        append(
            SQLiteOutcomeClosureIndex(path),
            closure_id="crash-closure",
            execution_id="crash-execution",
            attempt_id="crash-attempt",
            idempotency_key="crash-idempotency",
        )
        == OutcomeIndexStatus.APPENDED
    )
    connection = sqlite3.connect(path)
    assert connection.execute("SELECT COUNT(*) FROM closure_records").fetchone() == (2,)
    assert connection.execute("SELECT COUNT(*) FROM idempotency_outcomes").fetchone() == (2,)
    connection.close()


def test_locked_corrupt_and_foreign_databases_fail_closed(tmp_path: Path) -> None:
    locked_path = tmp_path / "locked.db"
    assert append(SQLiteOutcomeClosureIndex(locked_path)) == OutcomeIndexStatus.APPENDED
    lock = sqlite3.connect(locked_path, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    try:
        assert (
            append(
                SQLiteOutcomeClosureIndex(locked_path, busy_timeout_ms=0),
                tenant_id="tenant-002",
                closure_id="closure-002",
                execution_id="execution-002",
                attempt_id="attempt-002",
                idempotency_key="idempotency-002",
            )
            == OutcomeIndexStatus.UNAVAILABLE
        )
    finally:
        lock.rollback()
        lock.close()
    corrupt_path = tmp_path / "corrupt.db"
    corrupt_path.write_bytes(b"not sqlite")
    assert append(SQLiteOutcomeClosureIndex(corrupt_path)) == OutcomeIndexStatus.UNAVAILABLE
    foreign_path = tmp_path / "foreign.db"
    foreign = sqlite3.connect(foreign_path)
    foreign.execute("CREATE TABLE foreign_data(value TEXT)")
    foreign.commit()
    foreign.close()
    assert append(SQLiteOutcomeClosureIndex(foreign_path)) == OutcomeIndexStatus.UNAVAILABLE
    check = sqlite3.connect(foreign_path)
    assert check.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall() == [("foreign_data",)]
    check.close()


@pytest.mark.parametrize("tamper", ["schema", "orphan_identity", "broken_chain"])
def test_schema_and_relation_tampering_fail_closed(tmp_path: Path, tamper: str) -> None:
    path = tmp_path / "outcomes.db"
    assert append(SQLiteOutcomeClosureIndex(path)) == OutcomeIndexStatus.APPENDED
    connection = sqlite3.connect(path)
    if tamper == "schema":
        connection.execute("UPDATE proofflow_metadata SET schema_version = 2")
    elif tamper == "orphan_identity":
        connection.execute("DELETE FROM idempotency_outcomes")
    else:
        connection.execute("UPDATE idempotency_outcomes SET closure_sequence = 2")
        connection.execute(
            "UPDATE closure_records SET closure_sequence = 2, previous_payload_sha256 = ?",
            (PAYLOAD_B,),
        )
    connection.commit()
    connection.close()
    assert append(SQLiteOutcomeClosureIndex(path)) == OutcomeIndexStatus.UNAVAILABLE


def test_invalid_input_and_unsafe_paths_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "outcomes.db"
    index = SQLiteOutcomeClosureIndex(path)
    assert append(index, tenant_id="../tenant") == OutcomeIndexStatus.UNAVAILABLE
    assert append(index, closure_sequence=0) == OutcomeIndexStatus.UNAVAILABLE
    assert append(index, closure_sequence=True) == OutcomeIndexStatus.UNAVAILABLE
    assert append(index, payload_sha256="sha256:not-a-digest") == OutcomeIndexStatus.UNAVAILABLE
    assert not path.exists()
    directory = tmp_path / "directory"
    directory.mkdir()
    assert append(SQLiteOutcomeClosureIndex(directory)) == OutcomeIndexStatus.UNAVAILABLE
    target = tmp_path / "target.db"
    target.write_bytes(b"")
    symlink = tmp_path / "symlink.db"
    try:
        symlink.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert append(SQLiteOutcomeClosureIndex(symlink)) == OutcomeIndexStatus.UNAVAILABLE
    assert target.read_bytes() == b""


@pytest.mark.parametrize("capacity", [0, 1_000_001])
def test_capacity_bounds_are_rejected(tmp_path: Path, capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        SQLiteOutcomeClosureIndex(tmp_path / "outcomes.db", capacity=capacity)


@pytest.mark.parametrize("busy_timeout_ms", [-1, 60_001])
def test_busy_timeout_bounds_are_rejected(tmp_path: Path, busy_timeout_ms: int) -> None:
    with pytest.raises(ValueError, match="busy timeout"):
        SQLiteOutcomeClosureIndex(tmp_path / "outcomes.db", busy_timeout_ms=busy_timeout_ms)
