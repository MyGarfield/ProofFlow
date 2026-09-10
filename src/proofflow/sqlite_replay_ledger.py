"""Durable single-host replay reservation adapter for ActionCertificate.

This module deliberately provides a SQLite reference implementation, not a
distributed exactly-once service. SQLite serializes writers on one database
file; callers remain responsible for selecting a trusted local path and for
backing up, monitoring, and operating that file.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from proofflow.action_certificate import (
    IDENTIFIER_PATTERN,
    SHA256_PATTERN,
    ReservationStatus,
)
from proofflow.sqlite_wal import SQLiteWalStore

_SCHEMA_NAME = "proofflow.action-certificate-replay-ledger"
_SCHEMA_VERSION = 1
_MAX_CAPACITY = 1_000_000


class SQLiteReplayLedger(SQLiteWalStore):
    """Persistent, cross-process replay reservations on one SQLite file.

    Every call uses one ``BEGIN IMMEDIATE`` transaction to preserve the
    ``ReplayLedger`` check-and-reserve contract across independent processes.
    Storage, locking, schema, or integrity failures return ``UNAVAILABLE`` so
    ActionCertificate verification fails closed.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        capacity: int = 10_000,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if capacity < 1 or capacity > _MAX_CAPACITY:
            raise ValueError("replay ledger capacity must be between 1 and 1000000")
        super().__init__(path, busy_timeout_ms=busy_timeout_ms)
        self._capacity = capacity

    def reserve_once(
        self,
        *,
        tenant_id: str,
        nonce: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReservationStatus:
        if not self._valid_identifier(tenant_id):
            return ReservationStatus.UNAVAILABLE
        if not self._valid_identifier(nonce):
            return ReservationStatus.UNAVAILABLE
        if not self._valid_identifier(idempotency_key):
            return ReservationStatus.UNAVAILABLE
        if re.fullmatch(SHA256_PATTERN, intent_sha256) is None:
            return ReservationStatus.UNAVAILABLE

        # The instance lock avoids sharing SQLite setup races between threads.
        # Independent instances and processes are serialized by BEGIN IMMEDIATE.
        with self._lock:
            try:
                self._prepare_target()
                with self._connect() as connection:
                    objects = self._schema_objects(connection)
                    if objects and objects != {"proofflow_metadata", "replay_reservations"}:
                        raise sqlite3.DatabaseError("unexpected replay ledger schema objects")
                    self._configure(connection)
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        self._initialize_or_validate_schema(connection)
                        status = self._reserve(
                            connection,
                            tenant_id=tenant_id,
                            nonce=nonce,
                            idempotency_key=idempotency_key,
                            intent_sha256=intent_sha256,
                        )
                    except Exception:
                        connection.rollback()
                        raise
                    connection.commit()
                    return status
            except (OSError, sqlite3.Error):
                return ReservationStatus.UNAVAILABLE

    @staticmethod
    def _valid_identifier(value: str) -> bool:
        return isinstance(value, str) and re.fullmatch(IDENTIFIER_PATTERN, value) is not None

    def _initialize_or_validate_schema(self, connection: sqlite3.Connection) -> None:
        objects = self._schema_objects(connection)
        if not objects:
            connection.execute(
                "CREATE TABLE proofflow_metadata ("
                "schema_name TEXT PRIMARY KEY, "
                "schema_version INTEGER NOT NULL"
                ") WITHOUT ROWID"
            )
            connection.execute(
                "CREATE TABLE replay_reservations ("
                "tenant_id TEXT NOT NULL, "
                "nonce TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, "
                "intent_sha256 TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, nonce), "
                "UNIQUE (tenant_id, idempotency_key)"
                ") WITHOUT ROWID"
            )
            connection.execute(
                "INSERT INTO proofflow_metadata(schema_name, schema_version) VALUES (?, ?)",
                (_SCHEMA_NAME, _SCHEMA_VERSION),
            )
            return

        if objects != {"proofflow_metadata", "replay_reservations"}:
            raise sqlite3.DatabaseError("unexpected replay ledger schema objects")
        metadata = connection.execute(
            "SELECT schema_name, schema_version FROM proofflow_metadata"
        ).fetchall()
        if metadata != [(_SCHEMA_NAME, _SCHEMA_VERSION)]:
            raise sqlite3.DatabaseError("unsupported replay ledger schema version")
        metadata_columns = [
            (row[1], row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(proofflow_metadata)")
        ]
        if metadata_columns != [
            ("schema_name", "TEXT", 1, None, 1),
            ("schema_version", "INTEGER", 1, None, 0),
        ]:
            raise sqlite3.DatabaseError("unexpected replay ledger metadata columns")
        reservation_columns = [
            (row[1], row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(replay_reservations)")
        ]
        if reservation_columns != [
            ("tenant_id", "TEXT", 1, None, 1),
            ("nonce", "TEXT", 1, None, 2),
            ("idempotency_key", "TEXT", 1, None, 0),
            ("intent_sha256", "TEXT", 1, None, 0),
        ]:
            raise sqlite3.DatabaseError("unexpected replay ledger columns")
        unique_keys = {
            tuple(
                row[2]
                for row in connection.execute(
                    "SELECT * FROM pragma_index_info(?) ORDER BY seqno",
                    (str(index[1]),),
                )
            )
            for index in connection.execute("PRAGMA index_list(replay_reservations)")
            if int(index[2]) == 1 and int(index[4]) == 0
        }
        if unique_keys != {
            ("tenant_id", "nonce"),
            ("tenant_id", "idempotency_key"),
        }:
            raise sqlite3.DatabaseError("unexpected replay ledger uniqueness constraints")
        integrity = connection.execute("PRAGMA quick_check(1)").fetchall()
        if integrity != [("ok",)]:
            raise sqlite3.DatabaseError("replay ledger integrity check failed")

    def _reserve(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        nonce: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReservationStatus:
        existing_nonce = connection.execute(
            "SELECT 1 FROM replay_reservations WHERE tenant_id = ? AND nonce = ?",
            (tenant_id, nonce),
        ).fetchone()
        if existing_nonce is not None:
            return ReservationStatus.REPLAY

        existing_idempotency = connection.execute(
            "SELECT intent_sha256 FROM replay_reservations "
            "WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if existing_idempotency is not None:
            if existing_idempotency[0] == intent_sha256:
                return ReservationStatus.REPLAY
            return ReservationStatus.IDEMPOTENCY_CONFLICT

        count = connection.execute("SELECT COUNT(*) FROM replay_reservations").fetchone()
        if count is None or int(count[0]) >= self._capacity:
            return ReservationStatus.UNAVAILABLE
        connection.execute(
            "INSERT INTO replay_reservations("
            "tenant_id, nonce, idempotency_key, intent_sha256"
            ") VALUES (?, ?, ?, ?)",
            (tenant_id, nonce, idempotency_key, intent_sha256),
        )
        return ReservationStatus.RESERVED


__all__ = ["SQLiteReplayLedger"]
