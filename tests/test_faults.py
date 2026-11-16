"""Targeted correctness tests that need special failure injection:

  W1 a database WRITE failure must not advance the committed read offset;
     after the DB becomes writable again the same lines are ingested once.
  W2 reads larger than READ_CHUNK are followed across chunks without gaps.
  W3 empty lines are tolerated and do not consume alarm rows.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import config, db  # noqa: E402
from app.collector import Collector, file_identity  # noqa: E402
from app.gateway import append_alarm, append_raw  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def fresh_env(tmp: Path) -> tuple[Path, Path]:
    shared = tmp / "shared"
    dbp = tmp / "wh" / "alarms.db"
    shared.mkdir(parents=True, exist_ok=True)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    config.SHARED_DIR = shared.resolve()
    config.DB_PATH = dbp.resolve()
    return shared.resolve(), dbp.resolve()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="alarm-fault-"))

    # ---------------- W1: write failure must not advance offset ----------
    print("W1 DB write failure holds the offset, then resumes exactly once")
    shared, dbp = fresh_env(tmp / "w1")
    db.init_db(dbp)
    # one good line first
    append_alarm(device_id="dev-1", alarm_code="A1")
    c = Collector("w1-collector", shared, dbp)
    c.scan()
    con = sqlite3.connect(dbp)
    base_rows = con.execute("SELECT COUNT(*) FROM alarms").fetchone()[0]
    check("first line ingested", base_rows == 1, f"rows={base_rows}")

    # two more lines that we will fail to commit
    append_alarm(device_id="dev-2", alarm_code="A2")
    append_alarm(device_id="dev-3", alarm_code="A3")

    # Simulate a hard DB write failure (e.g. read-only / disk-full class) by
    # installing an authorizer that denies every mutating statement.
    def deny_writes(action, *args):
        if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE,
                      sqlite3.SQLITE_DELETE):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    c.conn.set_authorizer(deny_writes)
    c.scan()
    con2 = sqlite3.connect(dbp)
    rows_during_failure = con2.execute("SELECT COUNT(*) FROM alarms").fetchone()[0]
    fid = file_identity((shared / config.CURRENT_FILE).stat())
    offset_during = con2.execute(
        "SELECT read_offset FROM file_states WHERE file_id=?", (fid,)
    ).fetchone()[0]
    check("no rows committed while writes fail", rows_during_failure == 1,
          f"rows={rows_during_failure}")
    initial_off = con2.execute(
        "SELECT read_offset FROM file_states WHERE file_id=?", (fid,)
    ).fetchone()[0]
    check("read_offset not advanced by failed write", offset_during == initial_off)

    # restore a healthy connection and re-scan
    c.conn.set_authorizer(None)
    c.scan()
    con3 = sqlite3.connect(dbp)
    rows_after = con3.execute("SELECT COUNT(*) FROM alarms").fetchone()[0]
    offset_after = con3.execute(
        "SELECT read_offset FROM file_states WHERE file_id=?", (fid,)
    ).fetchone()[0]
    disk_size = (shared / config.CURRENT_FILE).stat().st_size
    check("both held lines ingested after recovery", rows_after == 3, f"rows={rows_after}")
    check("offset catches up exactly to file size", offset_after == disk_size,
          f"{offset_after} != {disk_size}")
    # scan again -> idempotent, nothing duplicated
    c.scan()
    con4 = sqlite3.connect(dbp)
    dup = con4.execute(
        "SELECT COUNT(*) c FROM (SELECT file_id,byte_offset FROM alarms "
        "GROUP BY file_id,byte_offset HAVING COUNT(*)>1)").fetchone()[0]
    check("rescans do not duplicate rows",
          con4.execute("SELECT COUNT(*) FROM alarms").fetchone()[0] == 3 and dup == 0)

    # ---------------- W2: multi-chunk reads -------------------------------
    print("W2 multi-chunk reads (lines bigger than READ_CHUNK)")
    shared2, dbp2 = fresh_env(tmp / "w2")
    db.init_db(dbp2)
    config.READ_CHUNK = 256  # force many chunks
    # 20 lines, each payload ~300 bytes -> every read returns mid-line chunks
    for i in range(20):
        append_alarm(device_id=f"dev-{i}",
                     alarm_code="LONG-" + ("x" * 260))
    c2 = Collector("w2-collector", shared2, dbp2)
    for _ in range(40):
        c2.scan()
        n = sqlite3.connect(dbp2).execute("SELECT COUNT(*) FROM alarms").fetchone()[0]
        if n == 20:
            break
        time.sleep(0.05)
    n = sqlite3.connect(dbp2).execute("SELECT COUNT(*) FROM alarms").fetchone()[0]
    check("all 20 oversized lines ingested across chunks", n == 20, f"rows={n}")
    fid2 = file_identity((shared2 / config.CURRENT_FILE).stat())
    final_off = sqlite3.connect(dbp2).execute(
        "SELECT read_offset FROM file_states WHERE file_id=?", (fid2,)).fetchone()[0]
    size2 = (shared2 / config.CURRENT_FILE).stat().st_size
    check("final offset equals whole file size", final_off == size2,
          f"{final_off} != {size2}")
    dup2 = sqlite3.connect(dbp2).execute(
        "SELECT COUNT(*) c FROM (SELECT file_id,byte_offset FROM alarms "
        "GROUP BY file_id,byte_offset HAVING COUNT(*)>1)").fetchone()[0]
    check("no duplicates across chunk boundaries", dup2 == 0)

    # ---------------- W3: blank lines -------------------------------------
    print("W3 blank lines do not become alarm rows")
    shared3, dbp3 = fresh_env(tmp / "w3")
    db.init_db(dbp3)
    append_alarm(device_id="d", alarm_code="B0")
    append_raw("\n\n")  # two blank newline-only lines
    append_alarm(device_id="d", alarm_code="B1")
    c3 = Collector("w3-collector", shared3, dbp3)
    c3.scan()
    n3 = sqlite3.connect(dbp3).execute("SELECT COUNT(*) FROM alarms").fetchone()[0]
    check("blank lines skipped, only real records stored", n3 == 2, f"rows={n3}")
    fid3 = file_identity((shared3 / config.CURRENT_FILE).stat())
    off3 = sqlite3.connect(dbp3).execute(
        "SELECT read_offset FROM file_states WHERE file_id=?", (fid3,)).fetchone()[0]
    size3 = (shared3 / config.CURRENT_FILE).stat().st_size
    check("offset still reaches EOF past blank lines", off3 == size3,
          f"{off3} != {size3}")

    # ---------------- W4: read failure holds the offset -------------------
    print("W4 unreadable file: offset held, then ingested after restore")
    shared4, dbp4 = fresh_env(tmp / "w4")
    db.init_db(dbp4)
    append_alarm(device_id="d", alarm_code="R0")
    c4 = Collector("w4-collector", shared4, dbp4)
    c4.scan()
    live4 = shared4 / config.CURRENT_FILE
    append_alarm(device_id="d", alarm_code="R1")
    # Revoke read permission to force open()/read() to fail. Skip gracefully
    # where the sandbox lets root bypass permission bits.
    os.chmod(live4, 0o000)
    can_block = not os.access(live4, os.R_OK)
    if can_block:
        fid4 = file_identity(live4.stat())
        off_before = sqlite3.connect(dbp4).execute(
            "SELECT read_offset FROM file_states WHERE file_id=?", (fid4,)).fetchone()[0]
        c4.scan()
        n_hold = sqlite3.connect(dbp4).execute(
            "SELECT COUNT(*) FROM alarms").fetchone()[0]
        off_hold = sqlite3.connect(dbp4).execute(
            "SELECT read_offset FROM file_states WHERE file_id=?", (fid4,)).fetchone()[0]
        check("second line not ingested while file unreadable", n_hold == 1, f"rows={n_hold}")
        check("offset unchanged through read failure", off_hold == off_before,
              f"{off_hold} != {off_before}")
        err_n = sqlite3.connect(dbp4).execute(
            "SELECT COUNT(*) FROM ingest_errors WHERE kind='read'").fetchone()[0]
        check("read error recorded", err_n >= 1, f"errors={err_n}")
        os.chmod(live4, 0o644)
        c4.scan()
        n_ok = sqlite3.connect(dbp4).execute(
            "SELECT COUNT(*) FROM alarms").fetchone()[0]
        off_ok = sqlite3.connect(dbp4).execute(
            "SELECT read_offset FROM file_states WHERE file_id=?", (fid4,)).fetchone()[0]
        check("held line ingested once after read access restored", n_ok == 2, f"rows={n_ok}")
        check("offset reaches EOF after restore",
              off_ok == live4.stat().st_size, f"{off_ok} != {live4.stat().st_size}")
    else:
        os.chmod(live4, 0o644)
        print("  [SKIP] read-permission denial not enforced in this sandbox")

    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
