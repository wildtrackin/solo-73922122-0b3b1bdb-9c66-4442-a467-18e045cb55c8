"""JSONL collector.

Correctness contract
--------------------
1. **Identity survives rename.**  A source file is identified by
   ``(st_dev, st_ino)``.  When the gateway renames the live file and
   creates a same-named new one, the old inode keeps being tracked under
   its new path and any later backfill append is still ingested.
2. **No partial lines.**  Only bytes up to the final newline are
   consumed; an unterminated trailing record stays on disk and is picked
   up on a later scan.  Each file advances independently, so a fragment
   on one file never blocks another (e.g. the brand-new live file).
3. **Progress commits with the data.**  Rows and the new read offset are
   written in one ``BEGIN IMMEDIATE`` transaction; on any read or write
   failure the offset is not advanced, and the next loop re-reads from
   the last committed position.  ``UNIQUE(file_id, byte_offset)`` plus a
   re-check of the committed offset make two collectors sharing the DB
   unable to double-insert a line, while identical content on different
   lines stays distinct.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config, db

log = logging.getLogger("collector")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def file_identity(st: os.stat_result) -> str:
    return f"dev{st.st_dev}-ino{st.st_ino}"


class Collector:
    def __init__(self, collector_id: str, shared_dir: Path | None = None,
                 db_path: Path | None = None) -> None:
        self.collector_id = collector_id
        self.shared_dir = shared_dir or config.SHARED_DIR
        self.conn = db.connect(db_path)
        self._stop = False
        self._beat_due = 0.0

    # ------------------------------------------------------------------
    def stop(self, *_args: object) -> None:
        self._stop = True

    def heartbeat(self, status: str = "running", detail: str | None = None) -> None:
        with db.transaction(self.conn) as tx:
            tx.execute(
                """INSERT INTO collector_heartbeats
                       (collector_id, pid, last_beat_utc, status, detail)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(collector_id) DO UPDATE SET
                       pid=excluded.pid, last_beat_utc=excluded.last_beat_utc,
                       status=excluded.status, detail=excluded.detail""",
                (self.collector_id, os.getpid(), utc_now(), status, detail),
            )

    def log_error(self, kind: str, message: str,
                  file_id: str | None = None, path: str | None = None) -> None:
        try:
            with db.transaction(self.conn) as tx:
                tx.execute(
                    """INSERT INTO ingest_errors
                           (file_id, path, collector_id, kind, message, occurred_utc)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (file_id, path, self.collector_id, kind, message[:2000], utc_now()),
                )
        except sqlite3.Error:
            # The database itself may be the failing component; never let
            # error bookkeeping mask the original failure or kill the loop.
            log.warning("could not persist %s error: %s", kind, message[:300])

    # ------------------------------------------------------------------
    def scan(self) -> None:
        """One directory scan; every file is handled independently."""
        try:
            entries = sorted(self.shared_dir.glob("*.jsonl"))
        except OSError as exc:
            self.log_error("read", f"scan failed: {exc!r}")
            return

        for path in entries:
            if self._stop:
                return
            try:
                self._process_file(path)
            except Exception as exc:  # one bad file must not kill the loop
                log.exception("file processing failed: %s", path)
                self.log_error("read", f"{path}: {exc!r}", path=str(path))

    def _get_state(self, tx: sqlite3.Connection, file_id: str) -> sqlite3.Row | None:
        return tx.execute(
            "SELECT * FROM file_states WHERE file_id = ?", (file_id,)
        ).fetchone()

    def _process_file(self, path: Path) -> None:
        try:
            st = path.stat()
        except FileNotFoundError:
            return  # renamed/removed between scan and stat; try next round
        fid = file_identity(st)

        # Register / refresh identity.  Committing the state row first is
        # harmless: read_offset stays 0 until rows are committed too.
        # INSERT OR IGNORE lets two collectors discover the same inode
        # concurrently without either transaction aborting.
        with db.transaction(self.conn) as tx:
            tx.execute(
                """INSERT OR IGNORE INTO file_states
                       (file_id, inode, last_path, size_seen, read_offset,
                        line_count, first_seen_utc, updated_utc)
                   VALUES (?, ?, ?, 0, 0, 0, ?, ?)""",
                (fid, st.st_ino, str(path), utc_now(), utc_now()),
            )
            state = self._get_state(tx, fid)
            offset, line_count = state["read_offset"], state["line_count"]
            if state["last_path"] != str(path):
                tx.execute(
                    "UPDATE file_states SET last_path = ?, updated_utc = ? WHERE file_id = ?",
                    (str(path), utc_now(), fid),
                )

        # Truncation guard: the contract says files are never truncated,
        # but do not silently skip data if it ever happens.
        if st.st_size < offset:
            self.log_error(
                "read",
                f"{path}: shrank from {offset} to {st.st_size} bytes; offset held",
                file_id=fid, path=str(path),
            )
            return

        if st.st_size == offset:
            return  # nothing new

        # Read the uncommitted tail, accumulating chunks until at least one
        # complete line (a newline) is available or EOF is reached.  A single
        # record may span many READ_CHUNK reads; reading just one chunk and
        # giving up when it has no newline would stall forever on a line
        # longer than the chunk size.  A read failure leaves the committed
        # offset untouched -> nothing is skipped.
        buf = bytearray()
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                while True:
                    chunk = fh.read(config.READ_CHUNK)
                    if not chunk:
                        break  # EOF
                    buf.extend(chunk)
                    if b"\n" in buf:
                        break
                    if len(buf) >= config.MAX_LINE_BYTES:
                        self.log_error(
                            "read",
                            f"{path}: line at offset {offset} exceeds "
                            f"{config.MAX_LINE_BYTES} bytes without newline; holding",
                            file_id=fid, path=str(path),
                        )
                        return
        except OSError as exc:
            self.log_error("read", f"{path}: {exc!r}", file_id=fid, path=str(path))
            return

        if not buf:
            return

        # Keep only complete lines; the dangling tail waits for completion.
        last_nl = buf.rfind(b"\n")
        if last_nl == -1:
            log.info("%s: %d bytes without newline, waiting", path, len(buf))
            return
        safe = bytes(buf[: last_nl + 1])
        new_offset = offset + len(safe)

        # Split into lines remembering each line's absolute byte offset.
        parsed: list[tuple[int, str, dict]] = []
        cursor = offset
        bad_offset: int | None = None
        for raw in safe.split(b"\n"):
            if not raw:  # trailing empty token after the final newline
                continue
            line_offset = cursor
            cursor += len(raw) + 1  # +1 for the '\n'
            try:
                text = raw.decode("utf-8")
                obj = json.loads(text)
                if not isinstance(obj, dict):
                    raise ValueError("JSON value is not an object")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                # Bad line: keep everything before it, stop here so the
                # bad line (and everything after) stays uncommitted and
                # is retried on the next scan once content is repaired.
                self.log_error(
                    "parse",
                    f"{path} offset {line_offset}: {exc!r}",
                    file_id=fid, path=str(path),
                )
                bad_offset = line_offset
                break
            parsed.append((line_offset, text, obj))

        if bad_offset is not None:
            new_offset = bad_offset
        if not parsed:
            return

        # One writer transaction: re-check the committed offset (the other
        # collector may have raced us), insert rows, then advance progress.
        with db.transaction(self.conn) as tx:
            state = self._get_state(tx, fid)
            committed = state["read_offset"] if state else 0
            line_no = state["line_count"] if state else 0
            # Drop lines the peer collector already committed.
            parsed = [p for p in parsed if p[0] >= committed]
            if new_offset < committed:
                new_offset = committed
            if not parsed:
                return

            inserted = 0
            for line_offset, text, obj in parsed:
                line_no += 1
                cur = tx.execute(
                    """INSERT OR IGNORE INTO alarms
                           (file_id, line_no, byte_offset, raw_line, device_id,
                            event_utc, alarm_code, parse_ok, source_path,
                            ingested_by, ingested_utc)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                    (fid, line_no, line_offset, text,
                     obj.get("device_id"), obj.get("event_utc"),
                     obj.get("alarm_code"), str(path),
                     self.collector_id, utc_now()),
                )
                inserted += cur.rowcount

            tx.execute(
                """UPDATE file_states
                       SET read_offset = ?, size_seen = ?, line_count = ?,
                           last_path = ?, updated_utc = ?
                     WHERE file_id = ?""",
                (new_offset, st.st_size, line_no, str(path), utc_now(), fid),
            )
        log.info(
            "%s: committed offset %d->%d, %d new row(s), file %s",
            path.name, offset, new_offset, inserted, fid,
        )

    # ------------------------------------------------------------------
    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        db.init_db()
        # Test-only graceful stop: presence of this file asks us to exit.
        # Enabled only when ALLOW_TEST_SHUTDOWN=1 (set by the self-test).
        stop_file = (
            self.shared_dir / f".stop-{self.collector_id}"
            if os.getenv("ALLOW_TEST_SHUTDOWN") == "1" else None
        )
        self.heartbeat("running", "startup")
        log.info("collector %s pid=%d watching %s",
                 self.collector_id, os.getpid(), self.shared_dir)
        while not self._stop:
            if stop_file is not None and stop_file.exists():
                log.info("stop file observed, exiting: %s", stop_file)
                break
            try:
                self.scan()
                if time.monotonic() >= self._beat_due:
                    self.heartbeat("running")
                    self._beat_due = time.monotonic() + 5.0
            except sqlite3.Error as exc:
                # Any DB failure leaves all offsets uncommitted; back off
                # instead of spinning, then retry from committed state.
                log.exception("database error, offsets not advanced")
                try:
                    self.heartbeat("error", str(exc)[:500])
                except sqlite3.Error:
                    pass
                self._sleep(min(2.0, config.SCAN_INTERVAL * 4))
                continue
            self._sleep(config.SCAN_INTERVAL)
        try:
            self.heartbeat("stopped")
        finally:
            self.conn.close()
        log.info("collector %s stopped", self.collector_id)

    def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self._stop and time.monotonic() < end:
            time.sleep(min(0.1, end - time.monotonic()))


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    Collector(config.COLLECTOR_ID).run()


if __name__ == "__main__":
    main()
