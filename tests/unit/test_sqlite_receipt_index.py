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

from proofflow.execution_receipt import InMemoryReceiptIndex, ReceiptIndexStatus
from proofflow.sqlite_receipt_index import SQLiteReceiptIndex

PAYLOAD_A = "sha256:" + "a" * 64
PAYLOAD_B = "sha256:" + "b" * 64
INTENT_A = "sha256:" + "c" * 64
INTENT_B = "sha256:" + "d" * 64


def append(index: SQLiteReceiptIndex, **overrides: str) -> ReceiptIndexStatus:
    values = {
        "tenant_id": "tenant-001",
        "receipt_id": "receipt-001",
        "execution_id": "execution-001",
        "attempt_id": "attempt-001",
        "payload_sha256": PAYLOAD_A,
        "idempotency_key": "idempotency-001",
        "intent_sha256": INTENT_A,
    }
    values.update(overrides)
    return index.append_once(**values)


def process_append(path: str, start: Any, queue: Any) -> None:
    start.wait()
    status = append(SQLiteReceiptIndex(path, busy_timeout_ms=10_000))
    queue.put(status.value)


class CrashingSQLiteReceiptIndex(SQLiteReceiptIndex):
    def _append(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        receipt_id: str,
        execution_id: str,
        attempt_id: str,
        payload_sha256: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReceiptIndexStatus:
        status = super()._append(
            connection,
            tenant_id=tenant_id,
            receipt_id=receipt_id,
            execution_id=execution_id,
            attempt_id=attempt_id,
            payload_sha256=payload_sha256,
            idempotency_key=idempotency_key,
            intent_sha256=intent_sha256,
        )
        if status == ReceiptIndexStatus.APPENDED:
            os._exit(73)
        return status


def process_crash_before_commit(path: str) -> None:
    append(
        CrashingSQLiteReceiptIndex(path),
        receipt_id="crash-receipt",
        execution_id="crash-execution",
        attempt_id="crash-attempt",
        idempotency_key="crash-idempotency",
    )


def test_append_survives_reopen_and_uses_private_full_sync_wal(tmp_path: Path) -> None:
    path = tmp_path / "receipts.db"
    assert append(SQLiteReceiptIndex(path)) == ReceiptIndexStatus.APPENDED
    assert append(SQLiteReceiptIndex(path)) == ReceiptIndexStatus.ALREADY_PRESENT

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    assert connection.execute("PRAGMA synchronous").fetchone() == (2,)
    assert connection.execute("SELECT COUNT(*) FROM receipt_records").fetchone() == (1,)
    assert connection.execute("SELECT COUNT(*) FROM idempotency_intents").fetchone() == (1,)
    connection.close()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_conflict_order_retry_and_tenant_semantics_match_in_memory_index(tmp_path: Path) -> None:
    index = SQLiteReceiptIndex(tmp_path / "receipts.db")
    assert append(index) == ReceiptIndexStatus.APPENDED
    assert append(index, payload_sha256=PAYLOAD_B) == ReceiptIndexStatus.RECEIPT_ID_CONFLICT
    assert (
        append(index, receipt_id="receipt-002", payload_sha256=PAYLOAD_B)
        == ReceiptIndexStatus.ATTEMPT_CONFLICT
    )
    assert (
        append(
            index,
            receipt_id="receipt-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
            payload_sha256=PAYLOAD_B,
            intent_sha256=INTENT_B,
        )
        == ReceiptIndexStatus.IDEMPOTENCY_CONFLICT
    )
    assert (
        append(
            index,
            receipt_id="receipt-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
            payload_sha256=PAYLOAD_B,
        )
        == ReceiptIndexStatus.APPENDED
    )
    assert append(index, tenant_id="tenant-002") == ReceiptIndexStatus.APPENDED


def test_deterministic_operation_sequence_matches_in_memory_index(tmp_path: Path) -> None:
    memory = InMemoryReceiptIndex(capacity=50)
    sqlite = SQLiteReceiptIndex(tmp_path / "receipts.db", capacity=50)
    generator = random.Random(20260910)

    for _ in range(300):
        arguments = {
            "tenant_id": f"tenant-{generator.randrange(3)}",
            "receipt_id": f"receipt-{generator.randrange(30)}",
            "execution_id": f"execution-{generator.randrange(15)}",
            "attempt_id": f"attempt-{generator.randrange(15)}",
            "payload_sha256": PAYLOAD_A if generator.randrange(2) == 0 else PAYLOAD_B,
            "idempotency_key": f"idempotency-{generator.randrange(20)}",
            "intent_sha256": INTENT_A if generator.randrange(2) == 0 else INTENT_B,
        }
        assert sqlite.append_once(**arguments) == memory.append_once(**arguments)


def test_capacity_failure_does_not_leave_an_orphan_intent(tmp_path: Path) -> None:
    path = tmp_path / "receipts.db"
    index = SQLiteReceiptIndex(path, capacity=1)
    assert append(index) == ReceiptIndexStatus.APPENDED
    assert (
        append(
            index,
            receipt_id="receipt-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
            idempotency_key="idempotency-002",
        )
        == ReceiptIndexStatus.UNAVAILABLE
    )

    connection = sqlite3.connect(path)
    assert connection.execute("SELECT COUNT(*) FROM idempotency_intents").fetchone() == (1,)
    connection.close()
    assert (
        append(
            SQLiteReceiptIndex(path, capacity=2),
            receipt_id="receipt-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
            idempotency_key="idempotency-002",
        )
        == ReceiptIndexStatus.APPENDED
    )


@pytest.mark.parametrize("iteration", range(3))
def test_independent_instances_append_atomically_across_threads(
    tmp_path: Path, iteration: int
) -> None:
    path = tmp_path / f"receipts-{iteration}.db"

    def attempt(_: int) -> ReceiptIndexStatus:
        return append(SQLiteReceiptIndex(path, busy_timeout_ms=10_000))

    with ThreadPoolExecutor(max_workers=12) as executor:
        statuses = list(executor.map(attempt, range(32)))
    assert statuses.count(ReceiptIndexStatus.APPENDED) == 1
    assert statuses.count(ReceiptIndexStatus.ALREADY_PRESENT) == 31


def test_independent_processes_append_atomically(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(target=process_append, args=(str(tmp_path / "receipts.db"), start, queue))
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    start.set()
    statuses = [queue.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    assert statuses.count(ReceiptIndexStatus.APPENDED.value) == 1
    assert statuses.count(ReceiptIndexStatus.ALREADY_PRESENT.value) == 5


def test_process_crash_before_commit_leaves_no_partial_append(tmp_path: Path) -> None:
    path = tmp_path / "receipts.db"
    assert append(SQLiteReceiptIndex(path)) == ReceiptIndexStatus.APPENDED

    context = multiprocessing.get_context("spawn")
    process = context.Process(target=process_crash_before_commit, args=(str(path),))
    process.start()
    process.join(timeout=20)
    assert process.exitcode == 73

    reopened = SQLiteReceiptIndex(path)
    assert (
        append(
            reopened,
            receipt_id="crash-receipt",
            execution_id="crash-execution",
            attempt_id="crash-attempt",
            idempotency_key="crash-idempotency",
        )
        == ReceiptIndexStatus.APPENDED
    )
    connection = sqlite3.connect(path)
    assert connection.execute("SELECT COUNT(*) FROM receipt_records").fetchone() == (2,)
    assert connection.execute("SELECT COUNT(*) FROM idempotency_intents").fetchone() == (2,)
    connection.close()


def test_locked_corrupt_and_foreign_databases_fail_closed(tmp_path: Path) -> None:
    locked_path = tmp_path / "locked.db"
    assert append(SQLiteReceiptIndex(locked_path)) == ReceiptIndexStatus.APPENDED
    lock = sqlite3.connect(locked_path, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    try:
        assert (
            append(
                SQLiteReceiptIndex(locked_path, busy_timeout_ms=0),
                receipt_id="receipt-002",
                execution_id="execution-002",
                attempt_id="attempt-002",
            )
            == ReceiptIndexStatus.UNAVAILABLE
        )
    finally:
        lock.rollback()
        lock.close()

    corrupt_path = tmp_path / "corrupt.db"
    corrupt_path.write_bytes(b"not sqlite")
    assert append(SQLiteReceiptIndex(corrupt_path)) == ReceiptIndexStatus.UNAVAILABLE

    foreign_path = tmp_path / "foreign.db"
    foreign = sqlite3.connect(foreign_path)
    foreign.execute("CREATE TABLE foreign_data(value TEXT)")
    foreign.commit()
    foreign.close()
    assert append(SQLiteReceiptIndex(foreign_path)) == ReceiptIndexStatus.UNAVAILABLE
    check = sqlite3.connect(foreign_path)
    assert check.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall() == [("foreign_data",)]
    check.close()


def test_schema_version_mismatch_fails_closed_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "receipts.db"
    assert append(SQLiteReceiptIndex(path)) == ReceiptIndexStatus.APPENDED
    connection = sqlite3.connect(path)
    connection.execute("UPDATE proofflow_metadata SET schema_version = 2")
    connection.commit()
    connection.close()

    assert (
        append(
            SQLiteReceiptIndex(path),
            receipt_id="receipt-002",
            execution_id="execution-002",
            attempt_id="attempt-002",
        )
        == ReceiptIndexStatus.UNAVAILABLE
    )
    check = sqlite3.connect(path)
    assert check.execute("SELECT COUNT(*) FROM receipt_records").fetchone() == (1,)
    check.close()


@pytest.mark.parametrize("tamper", ["missing_intent", "mismatched_intent"])
def test_relational_integrity_tampering_fails_closed(tmp_path: Path, tamper: str) -> None:
    path = tmp_path / "receipts.db"
    assert append(SQLiteReceiptIndex(path)) == ReceiptIndexStatus.APPENDED
    connection = sqlite3.connect(path)
    if tamper == "missing_intent":
        connection.execute("DELETE FROM idempotency_intents")
    else:
        connection.execute(
            "UPDATE idempotency_intents SET intent_sha256 = ?",
            (INTENT_B,),
        )
    connection.commit()
    connection.close()

    assert append(SQLiteReceiptIndex(path)) == ReceiptIndexStatus.UNAVAILABLE
    check = sqlite3.connect(path)
    assert check.execute("SELECT COUNT(*) FROM receipt_records").fetchone() == (1,)
    check.close()


def test_invalid_input_and_unsafe_paths_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "receipts.db"
    index = SQLiteReceiptIndex(path)
    assert append(index, tenant_id="../tenant") == ReceiptIndexStatus.UNAVAILABLE
    assert append(index, payload_sha256="sha256:not-a-digest") == ReceiptIndexStatus.UNAVAILABLE
    assert not path.exists()

    directory = tmp_path / "directory"
    directory.mkdir()
    assert append(SQLiteReceiptIndex(directory)) == ReceiptIndexStatus.UNAVAILABLE

    target = tmp_path / "target.db"
    target.write_bytes(b"")
    symlink = tmp_path / "symlink.db"
    try:
        symlink.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert append(SQLiteReceiptIndex(symlink)) == ReceiptIndexStatus.UNAVAILABLE
    assert target.read_bytes() == b""


@pytest.mark.parametrize("capacity", [0, 1_000_001])
def test_capacity_bounds_are_rejected(tmp_path: Path, capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        SQLiteReceiptIndex(tmp_path / "receipts.db", capacity=capacity)


@pytest.mark.parametrize("busy_timeout_ms", [-1, 60_001])
def test_busy_timeout_bounds_are_rejected(tmp_path: Path, busy_timeout_ms: int) -> None:
    with pytest.raises(ValueError, match="busy timeout"):
        SQLiteReceiptIndex(tmp_path / "receipts.db", busy_timeout_ms=busy_timeout_ms)
