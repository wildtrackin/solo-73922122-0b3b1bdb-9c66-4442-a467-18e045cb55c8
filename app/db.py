"""SQLite persistence layer.

Design points
-------------
* WAL mode + a busy timeout let two collector processes and the web
  process open the same database concurrently.
* The durable position for every source file lives in ``file_states``
  (committed byte offset + identity).  A collector only advances that
  offset inside the same transaction that inserts the rows, so a crash
  can never commit progress without the data (no missing rows) and can
  never keep data without the progress marker (re-reading is harmless
  because of the unique constraint -> no duplicates).
* ``alarms`` has a unique key on ``(file_id, byte_offset)`` so the same
  physical line can never be ingested twice, while identical content on
  different lines / different files is still kept as separate rows.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS file_states (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id       TEXT    NOT NULL UNIQUE,          -- stable identity (inode-based)
    inode         INTEGER NOT NULL,
    last_path     TEXT    NOT NULL,
    size_seen     INTEGER NOT NULL DEFAULT 0,
    read_offset   INTEGER NOT NULL DEFAULT 0,       -- committed safe position
    line_count    INTEGER NOT NULL DEFAULT 0,
    first_seen_utc TEXT   NOT NULL,
    updated_utc   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alarms (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      TEXT    NOT NULL,
    line_no      INTEGER NOT NULL,
    byte_offset  INTEGER NOT NULL,                 -- start byte of the JSON line
    raw_line     TEXT    NOT NULL,
    device_id    TEXT,
    event_utc    TEXT,
    alarm_code   TEXT,
    parse_ok     INTEGER NOT NULL DEFAULT 1,
    source_path  TEXT    NOT NULL,
    ingested_by  TEXT    NOT NULL,
    ingested_utc TEXT    NOT NULL,
    UNIQUE (file_id, byte_offset)
);

CREATE TABLE IF NOT EXISTS collector_heartbeats (
    collector_id  TEXT PRIMARY KEY,
    pid           INTEGER NOT NULL,
    last_beat_utc TEXT    NOT NULL,
    status        TEXT    NOT NULL,
    detail        TEXT
);

CREATE TABLE IF NOT EXISTS ingest_errors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      TEXT,
    path         TEXT,
    collector_id TEXT,
    kind         TEXT NOT NULL,                     -- read | parse | db
    message      TEXT NOT NULL,
    occurred_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alarms_file ON alarms (file_id, id);
CREATE INDEX IF NOT EXISTS idx_alarms_device ON alarms (device_id, event_utc);

-- ---------------------------------------------------------------------
-- Forensic (evidence preservation) tables.
--
-- A forensics job is accepted against ONE warehouse snapshot: every row
-- of ``forensics_items`` and ``forensics_file_snapshots`` is inserted in
-- the same BEGIN IMMEDIATE transaction as the job row, so the manifest
-- detail, source-file identities and committed byte positions all come
-- from a single committed point in time.  The packer later copies only
-- those frozen prefixes -- bytes appended afterwards and lines that never
-- received a newline can never enter the package.

CREATE TABLE IF NOT EXISTS forensics_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_uid         TEXT    NOT NULL UNIQUE,
    device_id       TEXT    NOT NULL,
    event_utc_from  TEXT    NOT NULL,           -- inclusive UTC bound
    event_utc_to    TEXT    NOT NULL,           -- inclusive UTC bound
    status          TEXT    NOT NULL,           -- pending|running|succeeded|failed
    failure_reason  TEXT,
    item_count      INTEGER NOT NULL DEFAULT 0,
    file_count      INTEGER NOT NULL DEFAULT 0,
    total_bytes     INTEGER NOT NULL DEFAULT 0,
    zip_path        TEXT,
    zip_size        INTEGER,
    zip_sha256      TEXT,
    requested_utc   TEXT    NOT NULL,
    started_utc     TEXT,
    finished_utc    TEXT
);

CREATE TABLE IF NOT EXISTS forensics_file_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id           INTEGER NOT NULL REFERENCES forensics_jobs(id),
    file_id          TEXT    NOT NULL,          -- inode-based identity at acceptance
    inode            INTEGER NOT NULL,
    snapshot_path    TEXT    NOT NULL,          -- last_path at acceptance
    prefix_bytes     INTEGER NOT NULL,          -- committed read_offset at acceptance
    prefix_sha256    TEXT,                      -- filled while packing
    UNIQUE (job_id, file_id)
);

CREATE TABLE IF NOT EXISTS forensics_items (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id       INTEGER NOT NULL REFERENCES forensics_jobs(id),
    file_id      TEXT    NOT NULL,
    line_no      INTEGER NOT NULL,
    byte_offset  INTEGER NOT NULL,
    byte_length  INTEGER NOT NULL,              -- length incl. trailing newline
    raw_line     TEXT    NOT NULL,
    device_id    TEXT,
    event_utc    TEXT,
    alarm_code   TEXT,
    source_path  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_forensics_items_job
    ON forensics_items (job_id, file_id, byte_offset);
CREATE INDEX IF NOT EXISTS idx_forensics_snap_job
    ON forensics_file_snapshots (job_id);
CREATE INDEX IF NOT EXISTS idx_forensics_jobs_status
    ON forensics_jobs (status);
"""

_init_lock = threading.Lock()
_initialized: set[Path] = set()


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open a connection with the pragmas required for shared use."""
    path = Path(db_path) if db_path is not None else config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        timeout=30.0,
        isolation_level=None,  # explicit BEGIN/COMMIT
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    # busy_timeout first so subsequent statements wait on the writer lock.
    conn.execute("PRAGMA busy_timeout=30000")
    # journal_mode=WAL itself is NOT covered by busy_timeout: if another
    # process holds a write lock exactly when we connect, it raises
    # OperationalError("database is locked"). Retry instead of dying --
    # once WAL is set it persists, so later attempts are effectively no-ops.
    for attempt in range(60):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 59:
                raise
            time.sleep(0.5)
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path | str | None = None) -> None:
    """Create tables.  Safe to call from every process; idempotent DDL.

    Note: sqlite3 ``executescript`` implicitly commits any open transaction,
    so the schema is applied directly -- every statement is
    ``CREATE ... IF NOT EXISTS`` and thus safe under concurrent first start.
    """
    path = Path(db_path) if db_path is not None else config.DB_PATH
    with _init_lock:
        if path in _initialized:
            return
        conn = connect(path)
        try:
            conn.executescript(_SCHEMA)
        finally:
            conn.close()
        _initialized.add(path)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """``BEGIN IMMEDIATE`` transaction: writer lock is taken up front so
    two collectors serialise rather than hit SQLITE_BUSY mid-flight."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
