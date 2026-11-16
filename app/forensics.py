"""Forensic evidence preservation.

A factory investigator hands an alarm excerpt plus the originating files
to a colleague for offline review while collection keeps running.  This
module implements evidence jobs that:

1. **Accept against one warehouse snapshot.**  The job row, the manifest
   detail (``forensics_items``) and the source-file snapshot
   (``forensics_file_snapshots``) are inserted in one ``BEGIN IMMEDIATE``
   transaction.  File identity (inode-based ``file_id``) and the byte
   position that had been committed at acceptance are frozen there, so
   later appends, renames and rotations cannot change what the package
   contains.
2. **Copy only the committed prefix of each involved source file.**  The
   packer opens the file by identity (re-resolving the path, so a rename
   during copying is harmless) and streams exactly ``prefix_bytes`` from
   offset 0 into the ZIP -- bytes appended after the snapshot and any
   unterminated trailing line are excluded.
3. **Verify before accepting the package.**  Every manifest line is
   compared one by one against the exact bytes inside the ZIP entry; the
   whole copied prefix is additionally compared against the live file
   (same identity) and hashed with SHA-256.  Any mismatch or read/write
   error fails the whole order: the temporary ZIP is deleted and no
   download is ever offered for a failed job.
4. **Stream end to end.**  All file I/O is chunked
   (``FORENSICS_CHUNK``); source files larger than the container's memory
   are packed with constant, small memory usage.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from . import config, db

log = logging.getLogger("forensics")

# Job lifecycle.  Only ``succeeded`` jobs with an existing ZIP are
# downloadable; ``pending``/``running`` left behind by a restart are
# swept to ``failed`` at startup.
STATUSES = ("pending", "running", "succeeded", "failed")

# Rows streamed per cursor fetch while freezing a job manifest, keeping
# acceptance memory bounded regardless of a device's history size.
_ACCEPT_BATCH = 500


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_event_utc(value: str, field: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp; reject naive/non-UTC input."""
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    # Require the canonical ISO-8601 date/time separator and an explicit
    # UTC designator (Z or +00:00); a space-separated "naive-looking"
    # string is not accepted for a forensic time bound.
    if "T" not in text or not (text.endswith("Z") or text.endswith("+00:00")):
        raise ValueError(
            f"{field} must be an ISO-8601 UTC timestamp like "
            f"2026-11-16T00:00:00Z (got {value!r})"
        )
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be an explicit UTC timestamp (ending in Z or +00:00)")
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------- accept
def accept_job(device_id: str, event_utc_from: str, event_utc_to: str) -> dict:
    """Freeze one snapshot and register a pending job (one transaction)."""
    device = (device_id or "").strip()
    if not device:
        raise ValueError("device_id is required")
    dt_from = parse_event_utc(event_utc_from, "event_utc_from")
    dt_to = parse_event_utc(event_utc_to, "event_utc_to")
    if dt_to < dt_from:
        raise ValueError("event_utc_to must be equal to or later than event_utc_from")
    # Store canonical UTC strings; compare against canonical event_utc.
    from_s, to_s = (
        dt_from.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        dt_to.isoformat(timespec="microseconds").replace("+00:00", "Z"),
    )

    job_uid = uuid.uuid4().hex
    conn = db.connect()
    try:
        with db.transaction(conn) as tx:
            cur = tx.execute(
                """INSERT INTO forensics_jobs
                       (job_uid, device_id, event_utc_from, event_utc_to,
                        status, requested_utc)
                   VALUES (?, ?, ?, ?, 'pending', ?)""",
                (job_uid, device, from_s, to_s, utc_now()),
            )
            job_id = cur.lastrowid

            # The manifest: exact rows as committed at this instant.
            # Rows with NULL/unparsable event_utc cannot belong to a UTC
            # closed interval and are therefore never selectable.  Filtering
            # on parsed instants (not raw strings) is required because stored
            # values use mixed precision ("...:00Z" vs "...:00.123456Z"), and
            # it keeps microsecond bounds exact -- SQLite's datetime() would
            # truncate them.  The whole read still happens inside this one
            # transaction, so the snapshot is identical to a single SQL view.
            # A server-side cursor streams rows in batches: a device may own
            # far more rows than fit in the 128 MiB web container, so the
            # manifest must never be materialised as one big list.
            total_bytes = 0
            item_count = 0
            involved: dict[str, str] = {}
            prev_end: dict[str, int] = {}
            cursor = tx.execute(
                """SELECT file_id, line_no, byte_offset, raw_line, device_id,
                          event_utc, alarm_code, source_path
                     FROM alarms
                    WHERE device_id = ?
                      AND event_utc IS NOT NULL
                    ORDER BY file_id, byte_offset""",
                (device,),
            )
            while True:
                batch = cursor.fetchmany(_ACCEPT_BATCH)
                if not batch:
                    break
                for r in batch:
                    try:
                        instant = datetime.fromisoformat(
                            r["event_utc"].replace("Z", "+00:00")
                        )
                    except ValueError:
                        continue  # unparsable timestamp cannot belong to interval
                    if not (dt_from <= instant.astimezone(timezone.utc) <= dt_to):
                        continue
                    # Length of the original line including its newline; the
                    # collector stores every ingested raw_line without the
                    # terminating '\n'.
                    length = len(r["raw_line"].encode("utf-8")) + 1
                    total_bytes += length
                    item_count += 1
                    tx.execute(
                        """INSERT INTO forensics_items
                               (job_id, file_id, line_no, byte_offset, byte_length,
                                raw_line, device_id, event_utc, alarm_code, source_path)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (job_id, r["file_id"], r["line_no"], r["byte_offset"], length,
                         r["raw_line"], r["device_id"], r["event_utc"],
                         r["alarm_code"], r["source_path"]),
                    )
                    # Every manifest line must lie inside the committed prefix
                    # frozen below.
                    end = r["byte_offset"] + length
                    if end > prev_end.get(r["file_id"], 0):
                        prev_end[r["file_id"]] = end
                    involved[r["file_id"]] = r["source_path"]

            # File snapshot: identity + committed position at acceptance.
            file_count = 0
            for fid, fallback_path in involved.items():
                st_row = tx.execute(
                    "SELECT inode, last_path, read_offset FROM file_states WHERE file_id = ?",
                    (fid,),
                ).fetchone()
                if st_row is None:  # cannot verify identity -> fail the order now
                    raise RuntimeError(
                        f"file state missing for source identity {fid}; refusing order"
                    )
                prefix = st_row["read_offset"]
                if prev_end[fid] > prefix:
                    # Must never happen (ingestion commits rows and offset
                    # together), but never silently drop manifest bytes.
                    raise RuntimeError(
                        f"committed prefix {prefix} shorter than manifest data "
                        f"{prev_end[fid]} on {fid}; refusing order"
                    )
                tx.execute(
                    """INSERT INTO forensics_file_snapshots
                           (job_id, file_id, inode, snapshot_path, prefix_bytes)
                       VALUES (?, ?, ?, ?, ?)""",
                    (job_id, fid, st_row["inode"], st_row["last_path"], prefix),
                )
                file_count += 1

            tx.execute(
                """UPDATE forensics_jobs
                      SET item_count = ?, file_count = ?, total_bytes = ?
                    WHERE id = ?""",
                (item_count, file_count, total_bytes, job_id),
            )
    finally:
        conn.close()

    log.info("accepted forensics job %s device=%s items=%d files=%d",
             job_uid, device, item_count, file_count)
    return get_job(job_uid)


# --------------------------------------------------------------------- queries
def _row_to_job(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "job_uid": row["job_uid"],
        "device_id": row["device_id"],
        "event_utc_from": row["event_utc_from"],
        "event_utc_to": row["event_utc_to"],
        "status": row["status"],
        "failure_reason": row["failure_reason"],
        "item_count": row["item_count"],
        "file_count": row["file_count"],
        "total_bytes": row["total_bytes"],
        "zip_size": row["zip_size"],
        "zip_sha256": row["zip_sha256"],
        "requested_utc": row["requested_utc"],
        "started_utc": row["started_utc"],
        "finished_utc": row["finished_utc"],
    }


def list_jobs(limit: int = 100) -> list[dict]:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM forensics_jobs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_job(r) for r in rows]
    finally:
        conn.close()


def get_job(job_uid: str, conn: sqlite3.Connection | None = None) -> dict | None:
    own = conn is None
    conn = conn or db.connect()
    try:
        row = conn.execute(
            "SELECT * FROM forensics_jobs WHERE job_uid = ?", (job_uid,)
        ).fetchone()
        return _row_to_job(row) if row else None
    finally:
        if own:
            conn.close()


def get_job_id(conn: sqlite3.Connection, job_uid: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM forensics_jobs WHERE job_uid = ?", (job_uid,)
    ).fetchone()


def list_items(job_uid: str, limit: int = 500, offset: int = 0) -> dict:
    conn = db.connect()
    try:
        job = get_job_id(conn, job_uid)
        if job is None:
            return {}
        total = conn.execute(
            "SELECT COUNT(*) c FROM forensics_items WHERE job_id = ?", (job["id"],)
        ).fetchone()["c"]
        rows = conn.execute(
            """SELECT file_id, line_no, byte_offset, byte_length, raw_line,
                      device_id, event_utc, alarm_code, source_path
                 FROM forensics_items WHERE job_id = ?
                ORDER BY file_id, byte_offset LIMIT ? OFFSET ?""",
            (job["id"], limit, offset),
        ).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}
    finally:
        conn.close()


def list_snapshots(job_uid: str) -> list[dict]:
    conn = db.connect()
    try:
        job = get_job_id(conn, job_uid)
        if job is None:
            return []
        rows = conn.execute(
            "SELECT * FROM forensics_file_snapshots WHERE job_id = ? ORDER BY id",
            (job["id"],),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def zip_path_for(job: dict) -> Path:
    return config.EVIDENCE_DIR / f"{job['job_uid']}.zip"


# --------------------------------------------------------------------- packing
def _resolve_by_identity(file_id: str, inode: int, snapshot_path: str) -> Path:
    """Find the current path of a source file by (dev,inode) identity.

    Rotation renames the inode; the path recorded at acceptance may
    therefore be stale.  Match by inode across the shared directory
    instead of trusting the path, so a rename can never make us open the
    wrong (same-named new) file.
    """
    dev_part = file_id.split("-ino", 1)[0].removeprefix("dev")
    wanted_dev = int(dev_part) if dev_part.isdigit() else None
    snap = Path(snapshot_path)
    candidates = [snap]
    if config.SHARED_DIR.exists():
        candidates.extend(sorted(config.SHARED_DIR.glob("*.jsonl")))
    seen: set[Path] = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        try:
            st = cand.stat()
        except OSError:
            continue
        if st.st_ino != inode:
            continue
        if wanted_dev is not None and st.st_dev != wanted_dev:
            continue
        return cand
    raise FileNotFoundError(
        f"source identity {file_id} (inode {inode}) no longer present; "
        f"last known path {snapshot_path}"
    )


def _copy_prefix(zf: zipfile.ZipFile, entry: str, path: Path,
                 prefix: int) -> tuple[str, int]:
    """Stream exactly ``prefix`` bytes of ``path`` into a ZIP entry."""
    h = hashlib.sha256()
    written = 0
    remaining = prefix
    with zf.open(entry, "w", force_zip64=True) as out, open(path, "rb") as fh:
        while remaining > 0:
            chunk = fh.read(min(config.FORENSICS_CHUNK, remaining))
            if not chunk:
                raise EOFError(
                    f"{path} ended after {written} bytes; snapshot prefix was {prefix}"
                )
            out.write(chunk)
            h.update(chunk)
            written += len(chunk)
            remaining -= len(chunk)
    if written != prefix:
        raise EOFError(f"{entry}: copied {written} of {prefix} bytes")
    return h.hexdigest(), written


def _verify_package(zip_path: Path, job_id: int,
                    conn: sqlite3.Connection) -> None:
    """Line-by-line manifest comparison plus full-prefix byte comparison.

    Both checks stream in constant memory (chunked I/O + a server-side
    cursor), so a source much larger than the container's RAM is verified
    without buffering it or its manifest.  Raises on any discrepancy; the
    caller fails the whole order.
    """
    snaps = conn.execute(
        "SELECT * FROM forensics_file_snapshots WHERE job_id = ? ORDER BY id",
        (job_id,),
    ).fetchall()

    with zipfile.ZipFile(zip_path, "r") as zf:
        # ZIP-level integrity first (CRC + local headers).
        bad = zf.testzip()
        if bad is not None:
            raise ValueError(f"zip CRC/header check failed on entry {bad!r}")

        names = set(zf.namelist())
        for snap in snaps:
            entry = f"sources/{snap['file_id']}/{Path(snap['snapshot_path']).name}"
            if entry not in names:
                raise ValueError(f"package missing source entry {entry}")
            info = zf.getinfo(entry)
            if info.file_size != snap["prefix_bytes"]:
                raise ValueError(
                    f"{entry}: entry size {info.file_size} != snapshot prefix "
                    f"{snap['prefix_bytes']}"
                )

            live = _resolve_by_identity(
                snap["file_id"], snap["inode"], snap["snapshot_path"]
            )
            zip_h = hashlib.sha256()
            live_h = hashlib.sha256()
            # Stream the manifest lines for this source in batches; never
            # materialise the whole (possibly huge) manifest in memory.
            def iter_items() -> Iterator[sqlite3.Row]:
                item_cursor = conn.execute(
                    """SELECT byte_offset, byte_length, raw_line
                         FROM forensics_items
                        WHERE job_id = ? AND file_id = ?
                        ORDER BY byte_offset""",
                    (job_id, snap["file_id"]),
                )
                while True:
                    batch = item_cursor.fetchmany(_ACCEPT_BATCH)
                    if not batch:
                        return
                    yield from batch

            seen = 0
            with zf.open(entry, "r") as zin, open(live, "rb") as fh:
                # Pass 1: compare the whole packaged prefix against the live
                # source identity in chunks (catches truncation, replacement
                # and cross-file mix-up), hashing both as we go.
                remaining = snap["prefix_bytes"]
                while remaining > 0:
                    n = min(config.FORENSICS_CHUNK, remaining)
                    zbuf, lbuf = zin.read(n), fh.read(n)
                    if len(zbuf) != n or len(lbuf) != n:
                        raise EOFError(
                            f"{entry}: short read while comparing prefix "
                            f"(zip={len(zbuf)}, live={len(lbuf)}, want={n})"
                        )
                    if zbuf != lbuf:
                        raise ValueError(
                            f"{entry}: packaged bytes differ from live source "
                            f"identity {snap['file_id']}"
                        )
                    zip_h.update(zbuf)
                    live_h.update(lbuf)
                    remaining -= n

                # Pass 2: one sequential walk over the packaged prefix,
                # comparing each manifest line with the exact bytes at its
                # recorded position.  Offsets are increasing and the prefix
                # bytes were already proven equal to the live file, so a
                # forward read replaces per-line random seeks.
                zin.seek(0)
                position = 0
                for next_item in iter_items():
                    off = next_item["byte_offset"]
                    if off < position:
                        raise ValueError(
                            f"{entry}: manifest offsets not sequential at {off}"
                        )
                    gap = off - position
                    while gap > 0:
                        skipped = zin.read(min(config.FORENSICS_CHUNK, gap))
                        if not skipped:
                            raise EOFError(f"{entry}: unexpected EOF before offset {off}")
                        gap -= len(skipped)
                        position += len(skipped)
                    want = next_item["raw_line"].encode("utf-8") + b"\n"
                    if next_item["byte_length"] != len(want):
                        raise ValueError(
                            f"{entry}: stored byte_length disagrees with raw line "
                            f"at offset {off}"
                        )
                    raw = zin.read(next_item["byte_length"])
                    if raw != want:
                        raise ValueError(
                            f"{entry}: manifest line at offset {off} does not "
                            f"match packaged bytes"
                        )
                    position += len(raw)
                    seen += 1

            # Every manifest row for this source must have been walked.
            expected_total = conn.execute(
                "SELECT COUNT(*) c FROM forensics_items "
                "WHERE job_id=? AND file_id=?",
                (job_id, snap["file_id"]),
            ).fetchone()["c"]
            if seen != expected_total:
                raise ValueError(
                    f"{entry}: verified {seen} of {expected_total} manifest lines"
                )

            if zip_h.hexdigest() != snap["prefix_sha256"]:
                raise ValueError(
                    f"{entry}: package prefix sha256 {zip_h.hexdigest()} != "
                    f"recorded {snap['prefix_sha256']}"
                )
            if live_h.hexdigest() != snap["prefix_sha256"]:
                raise ValueError(
                    f"{entry}: live source sha256 {live_h.hexdigest()} != "
                    f"frozen snapshot {snap['prefix_sha256']} (file changed?)"
                )


def _write_manifest_document(zf: zipfile.ZipFile, job: sqlite3.Row,
                             conn: sqlite3.Connection) -> str:
    """Write manifest.json as a stream of JSON slices; return its sha256."""
    h = hashlib.sha256()
    snaps = conn.execute(
        "SELECT * FROM forensics_file_snapshots WHERE job_id = ? ORDER BY id",
        (job["id"],),
    ).fetchall()

    def emit(buf: str) -> None:
        data = buf.encode("utf-8")
        out.write(data)
        h.update(data)

    with zf.open("manifest.json", "w", force_zip64=True) as out:
        head = (
            "{\n"
            f'  "job_uid": {json.dumps(job["job_uid"])},\n'
            f'  "device_id": {json.dumps(job["device_id"])},\n'
            f'  "event_utc_from": {json.dumps(job["event_utc_from"])},\n'
            f'  "event_utc_to": {json.dumps(job["event_utc_to"])},\n'
            f'  "requested_utc": {json.dumps(job["requested_utc"])},\n'
            f'  "finished_utc": {json.dumps(job["finished_utc"])},\n'
            '  "interval": "closed UTC interval on event_utc; both bounds inclusive",\n'
            '  "note": "Source prefixes stop at the byte position committed at '
            'acceptance; later appends and lines without a newline are excluded.",\n'
            '  "files": [\n'
        )
        emit(head)
        for i, snap in enumerate(snaps):
            entry = f"sources/{snap['file_id']}/{Path(snap['snapshot_path']).name}"
            doc = {
                "file_id": snap["file_id"],
                "inode": snap["inode"],
                "snapshot_path": snap["snapshot_path"],
                "zip_entry": entry,
                "prefix_bytes": snap["prefix_bytes"],
                "prefix_sha256": snap["prefix_sha256"],
            }
            emit("    " + json.dumps(doc, ensure_ascii=False))
            emit(",\n" if i < len(snaps) - 1 else "\n")
        emit("  ],\n  \"items\": [\n")
        # Stream items per source in ordered batches so a device with a huge
        # history never needs the whole manifest resident in memory.
        first = True
        for snap in snaps:
            item_cursor = conn.execute(
                """SELECT file_id, line_no, byte_offset, byte_length, raw_line,
                          device_id, event_utc, alarm_code, source_path
                     FROM forensics_items
                    WHERE job_id = ? AND file_id = ?
                    ORDER BY byte_offset""",
                (job["id"], snap["file_id"]),
            )
            while True:
                rows = item_cursor.fetchmany(_ACCEPT_BATCH)
                if not rows:
                    break
                for r in rows:
                    doc = {
                        "file_id": r["file_id"],
                        "line_no": r["line_no"],
                        "byte_offset": r["byte_offset"],
                        "byte_length": r["byte_length"],
                        "raw_line": r["raw_line"],
                        "device_id": r["device_id"],
                        "event_utc": r["event_utc"],
                        "alarm_code": r["alarm_code"],
                        "source_path": r["source_path"],
                        "zip_entry":
                            f"sources/{r['file_id']}/{Path(r['source_path']).name}",
                    }
                    if not first:
                        emit(",\n")
                    emit("    " + json.dumps(doc, ensure_ascii=False))
                    first = False
        emit("\n  ]\n}\n")
    return h.hexdigest()


def _process_job(job_uid: str) -> None:
    """Pack one pending job.  Any error -> status failed, no ZIP offered."""
    config.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = db.connect()
    try:
        job = get_job_id(conn, job_uid)
        if job is None or job["status"] not in ("pending", "running"):
            return
        with db.transaction(conn) as tx:
            tx.execute(
                "UPDATE forensics_jobs SET status='running', started_utc=? "
                "WHERE id=? AND status IN ('pending','running')",
                (utc_now(), job["id"]),
            )
        job = get_job_id(conn, job_uid)
        tmp_zip = config.EVIDENCE_DIR / f".{job_uid}.tmp.zip"
        final_zip = zip_path_for(dict(job))
        try:
            if tmp_zip.exists():
                tmp_zip.unlink()
            snaps = conn.execute(
                "SELECT * FROM forensics_file_snapshots WHERE job_id=? ORDER BY id",
                (job["id"],),
            ).fetchall()

            # Phase 1 -- stream the frozen source prefixes into the ZIP and
            # close it (a ZIP central directory only exists after close).
            # allowZip64 supports sources larger than 4 GiB; chunked writes
            # keep memory bounded regardless of file size.
            source_checksums: list[str] = []
            with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED,
                                 allowZip64=True) as zf:
                for snap in snaps:
                    path = _resolve_by_identity(
                        snap["file_id"], snap["inode"], snap["snapshot_path"]
                    )
                    entry = (f"sources/{snap['file_id']}/"
                             f"{Path(snap['snapshot_path']).name}")
                    digest, written = _copy_prefix(
                        zf, entry, path, snap["prefix_bytes"]
                    )
                    if written != snap["prefix_bytes"]:
                        raise EOFError(
                            f"{entry}: wrote {written}, expected {snap['prefix_bytes']}"
                        )
                    with db.transaction(conn) as tx:
                        tx.execute(
                            "UPDATE forensics_file_snapshots SET prefix_sha256=? "
                            "WHERE id=?",
                            (digest, snap["id"]),
                        )
                    source_checksums.append(
                        f"{digest}  {entry}  "
                        f"(prefix {snap['prefix_bytes']} bytes of "
                        f"{Path(snap['snapshot_path']).name})"
                    )

            # Phase 2 -- re-open the closed archive and verify every byte
            # before any bookkeeping document is added.  A failure here
            # deletes the temp file and fails the whole order.
            job = get_job_id(conn, job_uid)
            _verify_package(tmp_zip, job["id"], conn)

            # Phase 3 -- append manifest / checksum / README.  These describe
            # only data already verified above.
            checksums = list(source_checksums)
            with zipfile.ZipFile(tmp_zip, "a", zipfile.ZIP_DEFLATED,
                                 allowZip64=True) as zf:
                manifest_hash = _write_manifest_document(zf, job, conn)
                checksums.append(f"{manifest_hash}  manifest.json")
                with zf.open("SHA256SUMS.txt", "w") as out:
                    out.write(
                        ("# sha256 of every archived object; source entries "
                         "cover the committed prefix only\n"
                         + "\n".join(checksums) + "\n").encode("utf-8")
                    )
                with zf.open("README.txt", "w") as out:
                    readme = (
                        "Forensic evidence package\n"
                        "=========================\n"
                        f"job_uid: {job['job_uid']}\n"
                        f"device_id: {job['device_id']}\n"
                        f"UTC closed interval: {job['event_utc_from']} .. "
                        f"{job['event_utc_to']} (inclusive)\n\n"
                        "manifest.json      - every archived alarm line with its "
                        "source identity and byte position\n"
                        "SHA256SUMS.txt     - sha256 of manifest and source prefixes\n"
                        "sources/<file_id>/ - raw source prefixes, frozen at the "
                        "committed byte position at acceptance\n"
                    )
                    out.write(readme.encode("utf-8"))
            # Re-check the final archive (central directory incl. phase 3).
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                bad = zf.testzip()
                if bad is not None:
                    raise ValueError(f"final zip CRC check failed on {bad!r}")

            # Hash the finished ZIP itself (streamed, constant memory).
            zh = hashlib.sha256()
            with open(tmp_zip, "rb") as fh:
                while True:
                    chunk = fh.read(config.FORENSICS_CHUNK)
                    if not chunk:
                        break
                    zh.update(chunk)
            os.replace(tmp_zip, final_zip)
            with db.transaction(conn) as tx:
                tx.execute(
                    """UPDATE forensics_jobs
                          SET status='succeeded', failure_reason=NULL,
                              zip_path=?, zip_size=?, zip_sha256=?,
                              finished_utc=?
                        WHERE id=?""",
                    (str(final_zip), final_zip.stat().st_size, zh.hexdigest(),
                     utc_now(), job["id"]),
                )
            log.info("forensics job %s succeeded -> %s (%d bytes)",
                     job_uid, final_zip, final_zip.stat().st_size)
        except Exception as exc:  # noqa: BLE001 - any failure fails the order
            reason = f"{type(exc).__name__}: {exc}"[:2000]
            log.exception("forensics job %s failed", job_uid)
            try:
                if tmp_zip.exists():
                    tmp_zip.unlink()
            except OSError:
                pass
            with db.transaction(conn) as tx:
                tx.execute(
                    """UPDATE forensics_jobs
                          SET status='failed', failure_reason=?, finished_utc=?
                        WHERE id=? AND status != 'succeeded'""",
                    (reason, utc_now(), job["id"]),
                )
    finally:
        conn.close()


# --------------------------------------------------------------------- worker
class ForensicsWorker:
    """Single background thread: one order at a time, polled from the DB."""

    def __init__(self, poll_interval: float = 1.0) -> None:
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="forensics-worker", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        # Test-only delay before picking up an order, lets fault-injection
        # tests mutate a source before packing.  Unset (0) in production.
        pack_delay = float(os.getenv("FORENSICS_PACK_DELAY", "0"))
        while not self._stop.is_set():
            try:
                conn = db.connect()
                try:
                    row = conn.execute(
                        "SELECT job_uid FROM forensics_jobs "
                        "WHERE status='pending' ORDER BY id LIMIT 1"
                    ).fetchone()
                finally:
                    conn.close()
                if row:
                    if pack_delay:
                        self._stop.wait(pack_delay)
                    _process_job(row["job_uid"])
                    continue  # immediately pick up the next order
            except Exception:  # noqa: BLE001 - worker must never die silently
                log.exception("forensics worker loop error")
            self._stop.wait(self.poll_interval)


def sweep_interrupted() -> int:
    """Mark unfinished orders failed after a restart; finished ones stay."""
    conn = db.connect()
    try:
        with db.transaction(conn) as tx:
            cur = tx.execute(
                """UPDATE forensics_jobs
                      SET status='failed',
                          failure_reason=COALESCE(failure_reason,
                              'interrupted by service restart before completion'),
                          finished_utc=?
                    WHERE status IN ('pending','running')""",
                (utc_now(),),
            )
            n = cur.rowcount
        # Remove orphaned temporary packages left by the previous process.
        if config.EVIDENCE_DIR.exists():
            for p in config.EVIDENCE_DIR.glob(".*.tmp.zip"):
                try:
                    p.unlink()
                except OSError:
                    pass
        if n:
            log.warning("marked %d interrupted forensics job(s) as failed", n)
        return n
    finally:
        conn.close()
