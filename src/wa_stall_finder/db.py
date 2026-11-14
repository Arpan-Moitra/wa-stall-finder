"""Read-only access to the message database, plus runtime schema introspection."""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _harden(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA trusted_schema = OFF")
    return conn


def _connect_ro(path: Path) -> sqlite3.Connection:
    # immutable=1: SQLite takes no locks and creates no -journal/-wal/-shm files.
    # as_uri() gives a correctly escaped file: URI on Windows as well as POSIX.
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    return _harden(sqlite3.connect(uri, uri=True))


@contextmanager
def open_plain(path: Path) -> Iterator[sqlite3.Connection]:
    """Open an already-decrypted database file read-only and immutable."""
    conn = _connect_ro(path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def open_bytes(data: bytes, *, force_tempfile: bool = False) -> Iterator[sqlite3.Connection]:
    """Load decrypted bytes without touching disk (``Connection.deserialize``).

    If this SQLite build cannot deserialize, fall back to a 0600 file inside a
    0700 temporary directory that is removed in ``finally``.
    """
    conn: sqlite3.Connection | None = None
    tmpdir: str | None = None
    try:
        if not force_tempfile:
            try:
                conn = sqlite3.connect(":memory:")
                conn.deserialize(data)
                _harden(conn)
            except (AttributeError, sqlite3.NotSupportedError):
                if conn is not None:
                    conn.close()
                conn = None
        if conn is None:
            tmpdir = tempfile.mkdtemp(prefix="wa-stall-finder-")  # created 0700
            os.chmod(tmpdir, 0o700)
            tmp = Path(tmpdir) / "msgstore.db"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            conn = _connect_ro(tmp)
        yield conn
    finally:
        if conn is not None:
            conn.close()
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


class Schema:
    """Tables and columns actually present, discovered with PRAGMA table_info."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.tables: dict[str, list[str]] = {}
        self.unreadable: list[str] = []
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name"
            )
        ]
        for name in names:
            try:
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({quote_ident(name)})")]
            except sqlite3.Error:
                # e.g. a virtual table whose module is not compiled into this SQLite
                self.unreadable.append(name)
                continue
            if cols:
                self.tables[name] = cols
            else:
                self.unreadable.append(name)

    def has(self, table: str, *columns: str) -> bool:
        cols = self.tables.get(table)
        return cols is not None and all(c in cols for c in columns)

    def missing(self, table: str, *columns: str) -> str | None:
        """Human-readable description of what is missing, or None if all present."""
        cols = self.tables.get(table)
        if cols is None:
            return f"table '{table}' not found"
        absent = [c for c in columns if c not in cols]
        if absent:
            return f"column(s) {', '.join(absent)} not found in '{table}'"
        return None
