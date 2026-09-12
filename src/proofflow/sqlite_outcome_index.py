"""Persistent single-host append-only index for verified OutcomeClosures."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from proofflow.outcome_closure import (
    IDENTIFIER_PATTERN,
    MAX_OUTCOME_INDEX_CAPACITY,
    SHA256_PATTERN,
    OutcomeIndexStatus,
)
from proofflow.sqlite_wal import _SQLiteWalStore

_SCHEMA_NAME = "proofflow.outcome-closure-index"
_SCHEMA_VERSION = 1
_EXPECTED_OBJECTS = {
    "proofflow_metadata",
    "closure_records",
    "idempotency_outcomes",
}


class SQLiteOutcomeClosureIndex(_SQLiteWalStore):
    """Persistent OutcomeClosure sequencing and identity on one SQLite file."""

    def __init__(
        self,
        path: str | Path,
        *,
        capacity: int = 10_000,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if capacity < 1 or capacity > MAX_OUTCOME_INDEX_CAPACITY:
            raise ValueError("outcome index capacity must be between 1 and 1000000")
        super().__init__(path, busy_timeout_ms=busy_timeout_ms)
        self._capacity = capacity

    def append_once(
        self,
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
        if not all(
            self._valid_identifier(value)
            for value in (tenant_id, closure_id, execution_id, attempt_id, idempotency_key)
        ):
            return OutcomeIndexStatus.UNAVAILABLE
        if (
            not isinstance(closure_sequence, int)
            or isinstance(closure_sequence, bool)
            or not 1 <= closure_sequence <= 1_000_000
        ):
            return OutcomeIndexStatus.UNAVAILABLE
        if previous_payload_sha256 is not None and (
            not isinstance(previous_payload_sha256, str)
            or re.fullmatch(SHA256_PATTERN, previous_payload_sha256) is None
        ):
            return OutcomeIndexStatus.UNAVAILABLE
        if re.fullmatch(SHA256_PATTERN, payload_sha256) is None:
            return OutcomeIndexStatus.UNAVAILABLE
        if re.fullmatch(SHA256_PATTERN, intent_sha256) is None:
            return OutcomeIndexStatus.UNAVAILABLE

        with self._lock:
            try:
                self._prepare_target()
                with self._connect() as connection:
                    objects = self._schema_objects(connection)
                    if objects and objects != _EXPECTED_OBJECTS:
                        raise sqlite3.DatabaseError("unexpected outcome index schema objects")
                    self._configure(connection)
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        self._initialize_or_validate_schema(connection)
                        status = self._append(
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
                    except Exception:
                        connection.rollback()
                        raise
                    connection.commit()
                    return status
            except (OSError, sqlite3.Error):
                return OutcomeIndexStatus.UNAVAILABLE

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
                "CREATE TABLE idempotency_outcomes ("
                "tenant_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, "
                "closure_sequence INTEGER NOT NULL, "
                "intent_sha256 TEXT NOT NULL, "
                "payload_sha256 TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, idempotency_key, closure_sequence), "
                "UNIQUE (tenant_id, idempotency_key, closure_sequence, "
                "intent_sha256, payload_sha256)"
                ") WITHOUT ROWID"
            )
            connection.execute(
                "CREATE TABLE closure_records ("
                "tenant_id TEXT NOT NULL, "
                "closure_id TEXT NOT NULL, "
                "execution_id TEXT NOT NULL, "
                "attempt_id TEXT NOT NULL, "
                "closure_sequence INTEGER NOT NULL CHECK (closure_sequence BETWEEN 1 AND 1000000), "
                "previous_payload_sha256 TEXT, "
                "payload_sha256 TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, "
                "intent_sha256 TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, closure_id), "
                "UNIQUE (tenant_id, execution_id, attempt_id, closure_sequence), "
                "FOREIGN KEY (tenant_id, idempotency_key, closure_sequence, "
                "intent_sha256, payload_sha256) REFERENCES idempotency_outcomes("
                "tenant_id, idempotency_key, closure_sequence, intent_sha256, payload_sha256)"
                ") WITHOUT ROWID"
            )
            connection.execute(
                "INSERT INTO proofflow_metadata(schema_name, schema_version) VALUES (?, ?)",
                (_SCHEMA_NAME, _SCHEMA_VERSION),
            )
            return

        if objects != _EXPECTED_OBJECTS:
            raise sqlite3.DatabaseError("unexpected outcome index schema objects")
        metadata = connection.execute(
            "SELECT schema_name, schema_version FROM proofflow_metadata"
        ).fetchall()
        if metadata != [(_SCHEMA_NAME, _SCHEMA_VERSION)]:
            raise sqlite3.DatabaseError("unsupported outcome index schema version")
        self._validate_columns(connection)
        self._validate_constraints(connection)
        integrity = connection.execute("PRAGMA quick_check(1)").fetchall()
        if integrity != [("ok",)]:
            raise sqlite3.DatabaseError("outcome index integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise sqlite3.DatabaseError("outcome index foreign-key check failed")
        if self._orphan_identity_exists(connection):
            raise sqlite3.DatabaseError("outcome index identity relation is inconsistent")
        if self._broken_chain_exists(connection):
            raise sqlite3.DatabaseError("outcome index sequence chain is inconsistent")

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
            raise sqlite3.DatabaseError("unexpected outcome index metadata columns")
        idempotency_columns = [
            (row[1], row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(idempotency_outcomes)")
        ]
        if idempotency_columns != [
            ("tenant_id", "TEXT", 1, None, 1),
            ("idempotency_key", "TEXT", 1, None, 2),
            ("closure_sequence", "INTEGER", 1, None, 3),
            ("intent_sha256", "TEXT", 1, None, 0),
            ("payload_sha256", "TEXT", 1, None, 0),
        ]:
            raise sqlite3.DatabaseError("unexpected outcome index idempotency columns")
        closure_columns = [
            (row[1], row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(closure_records)")
        ]
        if closure_columns != [
            ("tenant_id", "TEXT", 1, None, 1),
            ("closure_id", "TEXT", 1, None, 2),
            ("execution_id", "TEXT", 1, None, 0),
            ("attempt_id", "TEXT", 1, None, 0),
            ("closure_sequence", "INTEGER", 1, None, 0),
            ("previous_payload_sha256", "TEXT", 0, None, 0),
            ("payload_sha256", "TEXT", 1, None, 0),
            ("idempotency_key", "TEXT", 1, None, 0),
            ("intent_sha256", "TEXT", 1, None, 0),
        ]:
            raise sqlite3.DatabaseError("unexpected outcome index record columns")

    @staticmethod
    def _index_columns(connection: sqlite3.Connection, table: str) -> set[tuple[str, ...]]:
        return {
            tuple(
                row[2]
                for row in connection.execute(
                    "SELECT * FROM pragma_index_info(?) ORDER BY seqno",
                    (str(index[1]),),
                )
            )
            for index in connection.execute(f"PRAGMA index_list({table})")
            if int(index[2]) == 1 and int(index[4]) == 0
        }

    @classmethod
    def _validate_constraints(cls, connection: sqlite3.Connection) -> None:
        if cls._index_columns(connection, "closure_records") != {
            ("tenant_id", "closure_id"),
            ("tenant_id", "execution_id", "attempt_id", "closure_sequence"),
        }:
            raise sqlite3.DatabaseError("unexpected outcome index record constraints")
        if cls._index_columns(connection, "idempotency_outcomes") != {
            ("tenant_id", "idempotency_key", "closure_sequence"),
            (
                "tenant_id",
                "idempotency_key",
                "closure_sequence",
                "intent_sha256",
                "payload_sha256",
            ),
        }:
            raise sqlite3.DatabaseError("unexpected outcome index idempotency constraints")
        foreign_keys = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute("PRAGMA foreign_key_list(closure_records)")
        }
        if foreign_keys != {
            ("idempotency_outcomes", "tenant_id", "tenant_id"),
            ("idempotency_outcomes", "idempotency_key", "idempotency_key"),
            ("idempotency_outcomes", "closure_sequence", "closure_sequence"),
            ("idempotency_outcomes", "intent_sha256", "intent_sha256"),
            ("idempotency_outcomes", "payload_sha256", "payload_sha256"),
        }:
            raise sqlite3.DatabaseError("unexpected outcome index foreign-key constraints")

    @staticmethod
    def _broken_chain_exists(connection: sqlite3.Connection) -> bool:
        broken = connection.execute(
            "SELECT 1 FROM closure_records AS current "
            "LEFT JOIN closure_records AS previous "
            "ON previous.tenant_id = current.tenant_id "
            "AND previous.execution_id = current.execution_id "
            "AND previous.attempt_id = current.attempt_id "
            "AND previous.closure_sequence = current.closure_sequence - 1 "
            "AND previous.payload_sha256 = current.previous_payload_sha256 "
            "WHERE (current.closure_sequence = 1 "
            "AND current.previous_payload_sha256 IS NOT NULL) "
            "OR (current.closure_sequence > 1 AND previous.closure_id IS NULL) "
            "OR current.closure_sequence < 1 LIMIT 1"
        ).fetchone()
        return broken is not None

    @staticmethod
    def _orphan_identity_exists(connection: sqlite3.Connection) -> bool:
        orphan = connection.execute(
            "SELECT 1 FROM idempotency_outcomes AS identity "
            "LEFT JOIN closure_records AS closure "
            "ON closure.tenant_id = identity.tenant_id "
            "AND closure.idempotency_key = identity.idempotency_key "
            "AND closure.closure_sequence = identity.closure_sequence "
            "AND closure.intent_sha256 = identity.intent_sha256 "
            "AND closure.payload_sha256 = identity.payload_sha256 "
            "GROUP BY identity.tenant_id, identity.idempotency_key, "
            "identity.closure_sequence, identity.intent_sha256, identity.payload_sha256 "
            "HAVING COUNT(closure.closure_id) != 1 LIMIT 1"
        ).fetchone()
        return orphan is not None

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
        existing_closure = connection.execute(
            "SELECT payload_sha256 FROM closure_records WHERE tenant_id = ? AND closure_id = ?",
            (tenant_id, closure_id),
        ).fetchone()
        existing_execution = connection.execute(
            "SELECT payload_sha256, previous_payload_sha256 FROM closure_records "
            "WHERE tenant_id = ? AND execution_id = ? AND attempt_id = ? "
            "AND closure_sequence = ?",
            (tenant_id, execution_id, attempt_id, closure_sequence),
        ).fetchone()
        existing_intent = connection.execute(
            "SELECT intent_sha256, payload_sha256 FROM idempotency_outcomes "
            "WHERE tenant_id = ? AND idempotency_key = ? AND closure_sequence = ?",
            (tenant_id, idempotency_key, closure_sequence),
        ).fetchone()
        if existing_closure is not None:
            if (
                existing_closure[0] == payload_sha256
                and existing_execution is not None
                and existing_execution[0] == payload_sha256
            ):
                return OutcomeIndexStatus.ALREADY_PRESENT
            return OutcomeIndexStatus.CLOSURE_ID_CONFLICT
        if existing_execution is not None:
            return OutcomeIndexStatus.ATTEMPT_SEQUENCE_CONFLICT
        if existing_intent is not None:
            if existing_intent == (intent_sha256, payload_sha256):
                return OutcomeIndexStatus.ALREADY_PRESENT
            return OutcomeIndexStatus.IDEMPOTENCY_CONFLICT

        latest = connection.execute(
            "SELECT closure_sequence, payload_sha256 FROM closure_records "
            "WHERE tenant_id = ? AND execution_id = ? AND attempt_id = ? "
            "ORDER BY closure_sequence DESC LIMIT 1",
            (tenant_id, execution_id, attempt_id),
        ).fetchone()
        if closure_sequence == 1:
            if previous_payload_sha256 is not None:
                return OutcomeIndexStatus.PREVIOUS_DIGEST_CONFLICT
        elif latest is None or latest[0] != closure_sequence - 1:
            return OutcomeIndexStatus.ATTEMPT_SEQUENCE_CONFLICT
        elif previous_payload_sha256 != latest[1]:
            return OutcomeIndexStatus.PREVIOUS_DIGEST_CONFLICT

        count = connection.execute("SELECT COUNT(*) FROM closure_records").fetchone()
        if count is None or int(count[0]) >= self._capacity:
            return OutcomeIndexStatus.UNAVAILABLE
        connection.execute(
            "INSERT INTO idempotency_outcomes("
            "tenant_id, idempotency_key, closure_sequence, intent_sha256, payload_sha256"
            ") VALUES (?, ?, ?, ?, ?)",
            (tenant_id, idempotency_key, closure_sequence, intent_sha256, payload_sha256),
        )
        connection.execute(
            "INSERT INTO closure_records("
            "tenant_id, closure_id, execution_id, attempt_id, closure_sequence, "
            "previous_payload_sha256, payload_sha256, idempotency_key, intent_sha256"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                closure_id,
                execution_id,
                attempt_id,
                closure_sequence,
                previous_payload_sha256,
                payload_sha256,
                idempotency_key,
                intent_sha256,
            ),
        )
        return OutcomeIndexStatus.APPENDED


__all__ = ["SQLiteOutcomeClosureIndex"]
