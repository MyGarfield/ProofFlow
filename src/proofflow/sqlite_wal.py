"""Shared local SQLite WAL mechanics for persistent reference indexes."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import cast

_MAX_BUSY_TIMEOUT_MS = 60_000


class _SQLiteWalStore:
    """Internal base for one trusted local SQLite WAL database file."""

    def __init__(self, path: str | Path, *, busy_timeout_ms: int) -> None:
        if busy_timeout_ms < 0 or busy_timeout_ms > _MAX_BUSY_TIMEOUT_MS:
            raise ValueError("busy timeout must be between 0 and 60000 milliseconds")
        raw_path = os.fspath(path)
        if not raw_path or raw_path == ":memory:" or raw_path.startswith("file:"):
            raise ValueError("index path must name a filesystem database")
        self._path = Path(raw_path).absolute()
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        """Absolute database path used by this adapter."""

        return self._path

    def _prepare_target(self) -> None:
        parent_status = self._path.parent.stat()
        if not stat.S_ISDIR(parent_status.st_mode):
            raise OSError("index parent is not a directory")

        try:
            target_status = self._path.lstat()
        except FileNotFoundError:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            try:
                descriptor = os.open(self._path, flags, 0o600)
            except FileExistsError:
                # Another trusted contender won creation. The lstat below still
                # rejects a symlink or other non-regular replacement.
                pass
            else:
                os.close(descriptor)
            target_status = self._path.lstat()
        if not stat.S_ISREG(target_status.st_mode):
            raise OSError("index target must be a regular file")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(
            self._path,
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )

    def _configure(self, connection: sqlite3.Connection) -> None:
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        journal_mode = self._enable_wal_with_bounded_retry(connection)
        if journal_mode is None or str(journal_mode[0]).casefold() != "wal":
            raise sqlite3.OperationalError("WAL journal mode is unavailable")
        connection.execute("PRAGMA synchronous = FULL")
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        if synchronous is None or int(synchronous[0]) != 2:
            raise sqlite3.OperationalError("FULL synchronous mode is unavailable")
        connection.execute("PRAGMA foreign_keys = ON")
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        if foreign_keys is None or int(foreign_keys[0]) != 1:
            raise sqlite3.OperationalError("foreign-key enforcement is unavailable")

    def _enable_wal_with_bounded_retry(
        self, connection: sqlite3.Connection
    ) -> tuple[object, ...] | None:
        deadline = time.monotonic() + self._busy_timeout_ms / 1_000
        while True:
            try:
                current = connection.execute("PRAGMA journal_mode").fetchone()
                if current is not None and str(current[0]).casefold() == "wal":
                    return cast(tuple[object, ...], current)
                changed = connection.execute("PRAGMA journal_mode = WAL").fetchone()
                return cast(tuple[object, ...] | None, changed)
            except sqlite3.OperationalError as exc:
                error_code = getattr(exc, "sqlite_errorcode", -1) & 0xFF
                if error_code not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.01, remaining))

    @staticmethod
    def _schema_objects(connection: sqlite3.Connection) -> set[str]:
        return {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type IN ('table', 'view', 'trigger', 'index') "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
