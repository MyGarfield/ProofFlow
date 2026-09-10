"""Persistent single-host index adapter for verified ExecutionReceipts.

The adapter preserves the v0.1 ``ReceiptIndex`` conflict order across local
processes. It records receipt identity and idempotency intent only; it does not
prove effect delivery or provide a distributed exactly-once service.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from proofflow.execution_receipt import (
    IDENTIFIER_PATTERN,
    MAX_RECEIPT_INDEX_CAPACITY,
    SHA256_PATTERN,
    ReceiptIndexStatus,
)
from proofflow.sqlite_wal import _SQLiteWalStore

_SCHEMA_NAME = "proofflow.execution-receipt-index"
_SCHEMA_VERSION = 1
_EXPECTED_OBJECTS = {
    "proofflow_metadata",
    "receipt_records",
    "idempotency_intents",
}


class SQLiteReceiptIndex(_SQLiteWalStore):
    """Persistent, atomic ExecutionReceipt identity index on one SQLite file."""

    def __init__(
        self,
        path: str | Path,
        *,
        capacity: int = 10_000,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if capacity < 1 or capacity > MAX_RECEIPT_INDEX_CAPACITY:
            raise ValueError("receipt index capacity must be between 1 and 1000000")
        super().__init__(path, busy_timeout_ms=busy_timeout_ms)
        self._capacity = capacity

    def append_once(
        self,
        *,
        tenant_id: str,
        receipt_id: str,
        execution_id: str,
        attempt_id: str,
        payload_sha256: str,
        idempotency_key: str,
        intent_sha256: str,
    ) -> ReceiptIndexStatus:
        if not all(
            self._valid_identifier(value)
            for value in (tenant_id, receipt_id, execution_id, attempt_id, idempotency_key)
        ):
            return ReceiptIndexStatus.UNAVAILABLE
        if re.fullmatch(SHA256_PATTERN, payload_sha256) is None:
            return ReceiptIndexStatus.UNAVAILABLE
        if re.fullmatch(SHA256_PATTERN, intent_sha256) is None:
            return ReceiptIndexStatus.UNAVAILABLE

        with self._lock:
            try:
                self._prepare_target()
                with self._connect() as connection:
                    objects = self._schema_objects(connection)
                    if objects and objects != _EXPECTED_OBJECTS:
                        raise sqlite3.DatabaseError("unexpected receipt index schema objects")
                    self._configure(connection)
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        self._initialize_or_validate_schema(connection)
                        status = self._append(
                            connection,
                            tenant_id=tenant_id,
                            receipt_id=receipt_id,
                            execution_id=execution_id,
                            attempt_id=attempt_id,
                            payload_sha256=payload_sha256,
                            idempotency_key=idempotency_key,
                            intent_sha256=intent_sha256,
                        )
                    except Exception:
                        connection.rollback()
                        raise
                    connection.commit()
                    return status
            except (OSError, sqlite3.Error):
                return ReceiptIndexStatus.UNAVAILABLE

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
                "CREATE TABLE idempotency_intents ("
                "tenant_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, "
                "intent_sha256 TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, idempotency_key)"
                ") WITHOUT ROWID"
            )
            connection.execute(
                "CREATE TABLE receipt_records ("
                "tenant_id TEXT NOT NULL, "
                "receipt_id TEXT NOT NULL, "
                "execution_id TEXT NOT NULL, "
                "attempt_id TEXT NOT NULL, "
                "payload_sha256 TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, "
                "intent_sha256 TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, receipt_id), "
                "UNIQUE (tenant_id, execution_id, attempt_id), "
                "FOREIGN KEY (tenant_id, idempotency_key) "
                "REFERENCES idempotency_intents(tenant_id, idempotency_key)"
                ") WITHOUT ROWID"
            )
            connection.execute(
                "INSERT INTO proofflow_metadata(schema_name, schema_version) VALUES (?, ?)",
                (_SCHEMA_NAME, _SCHEMA_VERSION),
            )
            return

        if objects != _EXPECTED_OBJECTS:
            raise sqlite3.DatabaseError("unexpected receipt index schema objects")
        metadata = connection.execute(
            "SELECT schema_name, schema_version FROM proofflow_metadata"
        ).fetchall()
        if metadata != [(_SCHEMA_NAME, _SCHEMA_VERSION)]:
            raise sqlite3.DatabaseError("unsupported receipt index schema version")
        self._validate_columns(connection)
        self._validate_constraints(connection)
        integrity = connection.execute("PRAGMA quick_check(1)").fetchall()
        if integrity != [("ok",)]:
            raise sqlite3.DatabaseError("receipt index integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise sqlite3.DatabaseError("receipt index foreign-key check failed")
        intent_mismatch = connection.execute(
            "SELECT 1 FROM receipt_records AS receipt "
            "JOIN idempotency_intents AS intent "
            "ON intent.tenant_id = receipt.tenant_id "
            "AND intent.idempotency_key = receipt.idempotency_key "
            "WHERE intent.intent_sha256 != receipt.intent_sha256 LIMIT 1"
        ).fetchone()
        if intent_mismatch is not None:
            raise sqlite3.DatabaseError("receipt index intent consistency check failed")

    @staticmethod
    def _validate_columns(connection: sqlite3.Connection) -> None:
        metadata_columns = [
            (row[1], row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(proofflow_metadata)")
        ]
        if metadata_columns != [
            ("schema_name", "TEXT", 1, None, 1),
            ("schema_version", "INTEGER", 1, None, 0),
        ]:
            raise sqlite3.DatabaseError("unexpected receipt index metadata columns")
        intent_columns = [
            (row[1], row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(idempotency_intents)")
        ]
        if intent_columns != [
            ("tenant_id", "TEXT", 1, None, 1),
            ("idempotency_key", "TEXT", 1, None, 2),
            ("intent_sha256", "TEXT", 1, None, 0),
        ]:
            raise sqlite3.DatabaseError("unexpected receipt index intent columns")
        receipt_columns = [
            (row[1], row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(receipt_records)")
        ]
        if receipt_columns != [
            ("tenant_id", "TEXT", 1, None, 1),
            ("receipt_id", "TEXT", 1, None, 2),
            ("execution_id", "TEXT", 1, None, 0),
            ("attempt_id", "TEXT", 1, None, 0),
            ("payload_sha256", "TEXT", 1, None, 0),
            ("idempotency_key", "TEXT", 1, None, 0),
            ("intent_sha256", "TEXT", 1, None, 0),
        ]:
            raise sqlite3.DatabaseError("unexpected receipt index record columns")

    @staticmethod
    def _validate_constraints(connection: sqlite3.Connection) -> None:
        unique_keys = {
            tuple(
                row[2]
                for row in connection.execute(
                    "SELECT * FROM pragma_index_info(?) ORDER BY seqno",
                    (str(index[1]),),
                )
            )
            for index in connection.execute("PRAGMA index_list(receipt_records)")
            if int(index[2]) == 1 and int(index[4]) == 0
        }
        if unique_keys != {
            ("tenant_id", "receipt_id"),
            ("tenant_id", "execution_id", "attempt_id"),
        }:
            raise sqlite3.DatabaseError("unexpected receipt index uniqueness constraints")
        foreign_keys = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute("PRAGMA foreign_key_list(receipt_records)")
        }
        if foreign_keys != {
            ("idempotency_intents", "tenant_id", "tenant_id"),
            ("idempotency_intents", "idempotency_key", "idempotency_key"),
        }:
            raise sqlite3.DatabaseError("unexpected receipt index foreign-key constraints")

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
        existing_receipt = connection.execute(
            "SELECT payload_sha256 FROM receipt_records WHERE tenant_id = ? AND receipt_id = ?",
            (tenant_id, receipt_id),
        ).fetchone()
        existing_attempt = connection.execute(
            "SELECT payload_sha256 FROM receipt_records "
            "WHERE tenant_id = ? AND execution_id = ? AND attempt_id = ?",
            (tenant_id, execution_id, attempt_id),
        ).fetchone()
        if existing_receipt is not None:
            if existing_receipt[0] == payload_sha256 and (
                existing_attempt is not None and existing_attempt[0] == payload_sha256
            ):
                return ReceiptIndexStatus.ALREADY_PRESENT
            return ReceiptIndexStatus.RECEIPT_ID_CONFLICT

        if existing_attempt is not None:
            return ReceiptIndexStatus.ATTEMPT_CONFLICT

        existing_intent = connection.execute(
            "SELECT intent_sha256 FROM idempotency_intents "
            "WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if existing_intent is not None and existing_intent[0] != intent_sha256:
            return ReceiptIndexStatus.IDEMPOTENCY_CONFLICT

        count = connection.execute("SELECT COUNT(*) FROM receipt_records").fetchone()
        if count is None or int(count[0]) >= self._capacity:
            return ReceiptIndexStatus.UNAVAILABLE
        if existing_intent is None:
            connection.execute(
                "INSERT INTO idempotency_intents(tenant_id, idempotency_key, intent_sha256) "
                "VALUES (?, ?, ?)",
                (tenant_id, idempotency_key, intent_sha256),
            )
        connection.execute(
            "INSERT INTO receipt_records("
            "tenant_id, receipt_id, execution_id, attempt_id, payload_sha256, idempotency_key, "
            "intent_sha256"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                receipt_id,
                execution_id,
                attempt_id,
                payload_sha256,
                idempotency_key,
                intent_sha256,
            ),
        )
        return ReceiptIndexStatus.APPENDED


__all__ = ["SQLiteReceiptIndex"]
