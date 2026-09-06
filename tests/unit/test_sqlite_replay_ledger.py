from __future__ import annotations

import multiprocessing
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from proofflow.action_certificate import ReservationStatus
from proofflow.sqlite_replay_ledger import SQLiteReplayLedger

INTENT_A = "sha256:" + "a" * 64
INTENT_B = "sha256:" + "b" * 64


def reserve(ledger: SQLiteReplayLedger, **overrides: str) -> ReservationStatus:
    values = {
        "tenant_id": "tenant-001",
        "nonce": "nonce-001",
        "idempotency_key": "idempotency-001",
        "intent_sha256": INTENT_A,
    }
    values.update(overrides)
    return ledger.reserve_once(**values)


def process_reserve(path: str, start: Any, queue: Any) -> None:
    start.wait()
    status = reserve(SQLiteReplayLedger(path, busy_timeout_ms=10_000))
    queue.put(status.value)


def test_reservation_survives_close_and_reopen(tmp_path: Path) -> None:
    path = tmp_path / "replay.db"
    assert reserve(SQLiteReplayLedger(path)) == ReservationStatus.RESERVED
    assert reserve(SQLiteReplayLedger(path)) == ReservationStatus.REPLAY

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    assert connection.execute("PRAGMA synchronous").fetchone() == (2,)
    assert connection.execute("SELECT COUNT(*) FROM replay_reservations").fetchone() == (1,)
    connection.close()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_idempotency_and_tenant_semantics_match_process_local_ledger(tmp_path: Path) -> None:
    ledger = SQLiteReplayLedger(tmp_path / "replay.db")
    assert reserve(ledger) == ReservationStatus.RESERVED
    assert reserve(ledger, nonce="nonce-002") == ReservationStatus.REPLAY
    assert (
        reserve(ledger, nonce="nonce-003", intent_sha256=INTENT_B)
        == ReservationStatus.IDEMPOTENCY_CONFLICT
    )
    assert reserve(ledger, tenant_id="tenant-002") == ReservationStatus.RESERVED


def test_capacity_is_durable_and_does_not_partially_reserve(tmp_path: Path) -> None:
    path = tmp_path / "replay.db"
    ledger = SQLiteReplayLedger(path, capacity=1)
    assert reserve(ledger) == ReservationStatus.RESERVED
    assert (
        reserve(ledger, nonce="nonce-002", idempotency_key="idempotency-002")
        == ReservationStatus.UNAVAILABLE
    )

    reopened = SQLiteReplayLedger(path, capacity=2)
    assert (
        reserve(reopened, nonce="nonce-002", idempotency_key="idempotency-002")
        == ReservationStatus.RESERVED
    )


def test_independent_instances_reserve_atomically_across_threads(tmp_path: Path) -> None:
    path = tmp_path / "replay.db"

    def attempt(_: int) -> ReservationStatus:
        return reserve(SQLiteReplayLedger(path, busy_timeout_ms=10_000))

    with ThreadPoolExecutor(max_workers=12) as executor:
        statuses = list(executor.map(attempt, range(32)))
    assert statuses.count(ReservationStatus.RESERVED) == 1
    assert statuses.count(ReservationStatus.REPLAY) == 31


def test_independent_processes_reserve_atomically(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(target=process_reserve, args=(str(tmp_path / "replay.db"), start, queue))
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    start.set()
    statuses = [queue.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    assert statuses.count(ReservationStatus.RESERVED.value) == 1
    assert statuses.count(ReservationStatus.REPLAY.value) == 5


def test_locked_corrupt_and_foreign_databases_fail_closed(tmp_path: Path) -> None:
    locked_path = tmp_path / "locked.db"
    assert reserve(SQLiteReplayLedger(locked_path)) == ReservationStatus.RESERVED
    lock = sqlite3.connect(locked_path, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    try:
        assert (
            reserve(
                SQLiteReplayLedger(locked_path, busy_timeout_ms=0),
                nonce="nonce-002",
                idempotency_key="idempotency-002",
            )
            == ReservationStatus.UNAVAILABLE
        )
    finally:
        lock.rollback()
        lock.close()

    corrupt_path = tmp_path / "corrupt.db"
    corrupt_path.write_bytes(b"not sqlite")
    assert reserve(SQLiteReplayLedger(corrupt_path)) == ReservationStatus.UNAVAILABLE

    foreign_path = tmp_path / "foreign.db"
    foreign = sqlite3.connect(foreign_path)
    foreign.execute("CREATE TABLE foreign_data(value TEXT)")
    foreign.commit()
    foreign.close()
    assert reserve(SQLiteReplayLedger(foreign_path)) == ReservationStatus.UNAVAILABLE
    check = sqlite3.connect(foreign_path)
    assert check.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall() == [("foreign_data",)]
    check.close()


def test_schema_version_mismatch_fails_closed_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "replay.db"
    assert reserve(SQLiteReplayLedger(path)) == ReservationStatus.RESERVED
    connection = sqlite3.connect(path)
    connection.execute("UPDATE proofflow_metadata SET schema_version = 2")
    connection.commit()
    connection.close()

    assert (
        reserve(
            SQLiteReplayLedger(path),
            nonce="nonce-002",
            idempotency_key="idempotency-002",
        )
        == ReservationStatus.UNAVAILABLE
    )
    check = sqlite3.connect(path)
    assert check.execute("SELECT COUNT(*) FROM replay_reservations").fetchone() == (1,)
    check.close()


def test_invalid_input_and_unsafe_paths_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "replay.db"
    ledger = SQLiteReplayLedger(path)
    assert reserve(ledger, tenant_id="../tenant") == ReservationStatus.UNAVAILABLE
    assert reserve(ledger, intent_sha256="sha256:not-a-digest") == ReservationStatus.UNAVAILABLE
    assert not path.exists()

    directory = tmp_path / "directory"
    directory.mkdir()
    assert reserve(SQLiteReplayLedger(directory)) == ReservationStatus.UNAVAILABLE

    target = tmp_path / "target.db"
    target.write_bytes(b"")
    symlink = tmp_path / "symlink.db"
    try:
        symlink.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert reserve(SQLiteReplayLedger(symlink)) == ReservationStatus.UNAVAILABLE
    assert target.read_bytes() == b""


@pytest.mark.parametrize("capacity", [0, 1_000_001])
def test_capacity_bounds_are_rejected(tmp_path: Path, capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        SQLiteReplayLedger(tmp_path / "replay.db", capacity=capacity)


@pytest.mark.parametrize("busy_timeout_ms", [-1, 60_001])
def test_busy_timeout_bounds_are_rejected(tmp_path: Path, busy_timeout_ms: int) -> None:
    with pytest.raises(ValueError, match="busy timeout"):
        SQLiteReplayLedger(tmp_path / "replay.db", busy_timeout_ms=busy_timeout_ms)
