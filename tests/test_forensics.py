"""End-to-end tests for the forensic evidence feature.

Spins up one uvicorn web process (which also runs the single forensics
worker thread) plus two collector processes against throwaway temp dirs,
and verifies the evidence contract:

  F1  accept freezes one snapshot: later appends and unterminated lines
      never enter the package; UTC bounds form a closed interval.
  F2  package contents: manifest line-by-line byte equality, source
      prefix == committed prefix at acceptance, SHA-256 recorded.
  F3  rotation/rename/backfill while/after acceptance never break the
      order and never mix files up (identity is inode-based).
  F4  ingestion continues while evidence is being produced: both
      collectors keep committing rows during packing.
  F5  a tampered source fails the whole order, records a reason and
      offers no ZIP; a missing source fails cleanly too.
  F6  an interrupted (pending/running) order is marked failed after a
      service restart and can be re-requested; finished packages stay
      downloadable.
  F7  download is refused unless the order succeeded; input validation
      rejects naive/non-UTC/inverted bounds.

Run:
  PYTHONPATH=<project root> python3 -I tests/test_forensics.py
"""
from __future__ import annotations

import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def http(method: str, url: str, body: dict | None = None) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            http("GET", url)
            return
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.25)
    raise RuntimeError(f"service not ready: {url}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_collector(cid: str, shared: Path, dbp: Path, ev: Path,
                    env: dict) -> subprocess.Popen:
    e = dict(env)
    e.update({"COLLECTOR_ID": cid, "SHARED_DIR": str(shared),
              "DB_PATH": str(dbp), "EVIDENCE_DIR": str(ev)})
    return subprocess.Popen(
        [sys.executable, "-m", "app.collector"],
        cwd=str(ROOT), env=e,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def wait_status(base: str, uid: str, want: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st, body = http("GET", f"{base}/api/forensics/jobs/{uid}")
        job = json.loads(body)
        if job["status"] == want:
            return job
        if job["status"] == "failed" and want != "failed":
            raise AssertionError(f"job {uid} failed: {job['failure_reason']}")
        time.sleep(0.2)
    raise AssertionError(f"job {uid} did not reach {want} within {timeout}s")


def wait_warehouse_rows(base: str, expected: int, timeout: float = 20.0) -> int:
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        last = json.loads(http("GET", base + "/api/stats")[1])["alarm_rows"]
        if last >= expected:
            return last
        time.sleep(0.2)
    raise AssertionError(f"warehouse rows stuck at {last}, expected {expected}")


def wait_device_rows(base: str, device: str, expected: int,
                     timeout: float = 25.0) -> list[dict]:
    deadline = time.monotonic() + timeout
    last: list[dict] = []
    while time.monotonic() < deadline:
        st, body = http("GET", f"{base}/api/alarms?limit=5000&device_id={device}")
        last = json.loads(body)["items"]
        if len(last) >= expected:
            return last
        time.sleep(0.25)
    raise AssertionError(
        f"device {device} rows stuck at {len(last)} "
        f"{sorted(r['alarm_code'] for r in last)}, expected {expected}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="forensics-e2e-"))
    shared, dbp, ev = tmp / "shared", tmp / "wh" / "alarms.db", tmp / "evidence"
    shared.mkdir(parents=True)
    port = free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env.update({"SHARED_DIR": str(shared), "DB_PATH": str(dbp),
                "EVIDENCE_DIR": str(ev), "SCAN_INTERVAL": "0.1",
                "FORENSICS_PACK_DELAY": "1.5",
                "ALLOW_TEST_SHUTDOWN": "1"})
    base = f"http://127.0.0.1:{port}"
    web = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    ca = start_collector("collector-a", shared, dbp, ev, env)
    cb = start_collector("collector-b", shared, dbp, ev, env)
    procs = {"web": web, "collector-a": ca, "collector-b": cb}
    try:
        wait_http(base + "/healthz")
        time.sleep(0.8)

        def append(device, code, ts, filename=None):
            http("POST", base + "/api/gateway/append",
                 {"device_id": device, "alarm_code": code,
                  "event_utc": ts, "filename": filename})

        # ------------------------------------------------ F1 + F2: snapshot
        print("F1/F2 snapshot isolation, closed UTC interval, package bytes")
        for i in range(6):
            append("dev-1", f"C{i}", f"2026-11-16T0{i}:00:00Z")
        time.sleep(1.2)
        st, body = http("POST", base + "/api/forensics/jobs",
                        {"device_id": "dev-1",
                         "event_utc_from": "2026-11-16T02:00:00Z",
                         "event_utc_to": "2026-11-16T04:00:00Z"})
        check("job accepted 201", st == 201, str(st))
        job = json.loads(body)
        uid = job["job_uid"]
        check("frozen manifest has exactly 3 interval rows",
              job["item_count"] == 3, str(job["item_count"]))

        # data produced AFTER acceptance must be excluded
        for i in range(4):
            append("dev-1", f"LATE{i}", "2026-11-16T09:00:00Z")
        st, _ = http("POST", base + "/api/gateway/fragment",
                     {"text": '{"device_id":"dev-1","event_utc":"2026-11-16T10:00:00Z","alarm_code":"HALF"}'})
        # An unterminated line parks the collector at that offset by design;
        # complete it now so later sections' appends are not held behind it.
        http("POST", base + "/api/gateway/complete", {"tail": "\n"})
        ok = wait_status(base, uid, "succeeded")
        check("job succeeds with zip sha256/size",
              bool(ok["zip_sha256"]) and ok["zip_size"] > 0)

        st, blob = http("GET", f"{base}/api/forensics/jobs/{uid}/download")
        check("download 200 + zip magic", st == 200 and blob[:2] == b"PK", str(st))
        zf = zipfile.ZipFile(io.BytesIO(blob))
        check("zip CRC healthy", zf.testzip() is None)
        man = json.loads(zf.read("manifest.json"))
        codes = [i["alarm_code"] for i in man["items"]]
        check("manifest equals closed interval C2..C4", codes == ["C2", "C3", "C4"], str(codes))
        source_blob = b"".join(
            zf.read(n) for n in zf.namelist() if n.startswith("sources/"))
        check("later appends excluded", b"LATE" not in source_blob)
        check("unterminated fragment excluded", b"HALF" not in source_blob)
        # every manifest line matches the exact packaged bytes
        line_ok = all(
            zf.read(it["zip_entry"])[
                it["byte_offset"]:it["byte_offset"] + it["byte_length"]
            ] == (it["raw_line"] + "\n").encode()
            for it in man["items"]
        )
        check("each manifest line byte-equal to package bytes", line_ok)
        # prefix sha256 inside manifest matches the archived entry
        import hashlib
        hash_ok = all(
            hashlib.sha256(zf.read(fs["zip_entry"])).hexdigest()
            == fs["prefix_sha256"]
            for fs in man["files"]
        )
        check("archived prefix sha256 equals manifest", hash_ok)
        check("SHA256SUMS + README present",
              "SHA256SUMS.txt" in zf.namelist() and "README.txt" in zf.namelist())

        # ----------------------------------------- F3: rotation/rename/backfill
        print("F3 rotation + rename + backfill do not break or mix evidence")
        stats0 = json.loads(http("GET", base + "/api/stats")[1])["alarm_rows"]
        append("dev-2", "OLD0", "2026-11-16T00:00:00Z")
        append("dev-2", "OLD1", "2026-11-16T01:00:00Z")
        wait_warehouse_rows(base, stats0 + 2)
        check("two OLD rows ingested before rotation", True)
        st, _ = http("POST", base + "/api/gateway/rotate")
        check("rotation succeeded", st == 200, str(st))
        append("dev-2", "NEW0", "2026-11-16T02:00:00Z")
        http("POST", base + "/api/gateway/append",
             {"filename": "alarms.1.jsonl", "device_id": "dev-2",
              "alarm_code": "BACKFILL", "event_utc": "2026-11-16T03:00:00Z"})
        # wait until all four dev-2 rows are committed before accepting
        dev2_rows = wait_device_rows(base, "dev-2", 4)
        check("four dev-2 rows committed before acceptance",
              len(dev2_rows) >= 4, f"got {len(dev2_rows)}")
        st, body = http("POST", base + "/api/forensics/jobs",
                        {"device_id": "dev-2",
                         "event_utc_from": "2026-11-16T00:00:00Z",
                         "event_utc_to": "2026-11-16T03:00:00Z"})
        j2 = json.loads(body)
        check("order spans two source identities", j2["file_count"] == 2,
              f"{j2['file_count']} (items={j2['item_count']})")
        # churn again DURING packing: another rotation moves both inodes
        st, _ = http("POST", base + "/api/gateway/rotate")
        http("POST", base + "/api/gateway/append",
             {"filename": "alarms.1.jsonl", "device_id": "dev-2",
              "alarm_code": "LATE-BF", "event_utc": "2026-11-16T08:00:00Z"})
        append("dev-2", "LATE-LIVE", "2026-11-16T08:30:00Z")
        ok2 = wait_status(base, j2["job_uid"], "succeeded")
        st, blob = http("GET", f"{base}/api/forensics/jobs/{ok2['job_uid']}/download")
        zf2 = zipfile.ZipFile(io.BytesIO(blob))
        man2 = json.loads(zf2.read("manifest.json"))
        got = sorted(i["alarm_code"] for i in man2["items"])
        check("all pre-snapshot rows kept across rename",
              got == sorted(["OLD0", "OLD1", "NEW0", "BACKFILL"]), str(got))
        check("post-accept backfill/live excluded",
              "LATE-BF" not in got and "LATE-LIVE" not in got)
        mix_ok = all(it["file_id"] in it["zip_entry"] for it in man2["items"])
        check("no cross-file mix (item file_id inside its entry path)", mix_ok)
        entry_ok = all(
            hashlib.sha256(zf2.read(fs["zip_entry"])).hexdigest()
            == fs["prefix_sha256"]
            for fs in man2["files"]
        )
        check("both renamed prefixes verified by identity", entry_ok)

        # --------------------------------- F4: collection continues while packing
        print("F4 dual collectors keep ingesting during evidence production")
        before = json.loads(http("GET", base + "/api/stats")[1])["alarm_rows"]
        st, body = http("POST", base + "/api/forensics/jobs",
                        {"device_id": "dev-1",
                         "event_utc_from": "2026-11-16T00:00:00Z",
                         "event_utc_to": "2026-11-16T23:59:59Z"})
        uid3 = json.loads(body)["job_uid"]
        for i in range(20):
            append("dev-conc", f"K{i}", f"2026-11-16T0{i % 24:02d}:30:00Z")
        wait_status(base, uid3, "succeeded")
        time.sleep(1.5)
        after = json.loads(http("GET", base + "/api/stats")[1])["alarm_rows"]
        check("rows ingested while an evidence job ran", after >= before + 20,
              f"{before} -> {after}")
        ids = set()
        # both collectors must appear across the workload
        st, alarms = http("GET", base + "/api/alarms?limit=5000")
        for a in json.loads(alarms)["items"]:
            ids.add(a["ingested_by"])
        check("both collector identities present in warehouse",
              {"collector-a", "collector-b"} <= ids, str(ids))

        # --------------------------------------------- F5: tamper / missing fail
        print("F5 verification failure fails the whole order, no download")
        append("dev-3", "X0", "2026-11-16T00:00:00Z")
        # make sure dev-3 is committed before accepting the order
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            st, body = http("GET", base + "/api/alarms?limit=5000&device_id=dev-3")
            if json.loads(body)["items"]:
                break
            time.sleep(0.2)
        st, body = http("POST", base + "/api/forensics/jobs",
                        {"device_id": "dev-3",
                         "event_utc_from": "2026-11-16T00:00:00Z",
                         "event_utc_to": "2026-11-16T01:00:00Z"})
        tampered_uid = json.loads(body)["job_uid"]
        # Corrupt the source in place before the worker packs it.  The worker
        # polls on a ~1s interval, so an immediate in-place edit reliably lands
        # first; identity (inode) is unchanged, only the bytes diverge, which
        # the packer's prefix/hash comparison must reject.
        src = None
        for p in sorted(shared.glob("*.jsonl")):
            if b"dev-3" in p.read_bytes():
                src = p
                break
        check("located dev-3 source on disk", src is not None)
        if src is not None:
            data = bytearray(src.read_bytes())
            idx = data.find(b"dev-3")
            data[idx:idx + 5] = b"dev-Z"  # same-length in-place byte tamper
            src.write_bytes(bytes(data))
        failed = wait_status(base, tampered_uid, "failed")
        check("tampered order failed with a reason",
              failed["status"] == "failed" and bool(failed["failure_reason"]))
        st, _ = http("GET", f"{base}/api/forensics/jobs/{tampered_uid}/download")
        check("failed order offers no download (409)", st == 409, str(st))
        check("no temp zip left behind",
              not list(ev.glob(".*.tmp.zip")))
        # a new order for the same device is still possible (re-forensics)
        st, body = http("POST", base + "/api/forensics/jobs",
                        {"device_id": "dev-3",
                         "event_utc_from": "2030-01-01T00:00:00Z",
                         "event_utc_to": "2030-01-02T00:00:00Z"})
        check("re-request accepted after failure", st == 201, str(st))

        # ------------------------------------------------ F7: validation/404s
        print("F7 input validation and status codes")
        bad_inputs = [
            {"device_id": "dev-1", "event_utc_from": "bad",
             "event_utc_to": "2026-11-16T04:00:00Z"},
            {"device_id": "dev-1",
             "event_utc_from": "2026-11-16T04:00:00Z",
             "event_utc_to": "2026-11-16T01:00:00Z"},
            {"device_id": "dev-1",
             "event_utc_from": "2026-11-16 01:00:00Z",
             "event_utc_to": "2026-11-16T04:00:00Z"},
            {"device_id": "dev-1",
             "event_utc_from": "2026-11-16T01:00:00+08:00",
             "event_utc_to": "2026-11-16T04:00:00Z"},
            {"device_id": "",
             "event_utc_from": "2026-11-16T01:00:00Z",
             "event_utc_to": "2026-11-16T04:00:00Z"},
        ]
        rejected = all(
            http("POST", base + "/api/forensics/jobs", b)[0] == 400
            for b in bad_inputs
        )
        check("all invalid bounds rejected with 400", rejected)
        st, _ = http("GET", base + "/api/forensics/jobs/does-not-exist")
        check("unknown job -> 404", st == 404, str(st))
        st, body = http("GET", base + "/api/forensics/jobs?limit=5")
        check("jobs list endpoint works",
              st == 200 and len(json.loads(body)["items"]) >= 1)
        for path in ("/", "/forensics"):
            st, body = http("GET", base + path)
            check(f"page {path} renders", st == 200 and b"<!DOCTYPE" in body)

        # --------------------------------------- F6: restart sweep semantics
        print("F6 restart marks unfinished orders failed, keeps finished ones")
        finished_uid = uid  # the F1 successful job
        st, body = http("POST", base + "/api/forensics/jobs",
                        {"device_id": "dev-1",
                         "event_utc_from": "2030-02-01T00:00:00Z",
                         "event_utc_to": "2030-02-02T00:00:00Z"})
        pending_uid = json.loads(body)["job_uid"]
        # stop the web process hard while the new order is pending, then restart
        try:
            http("POST", base + "/__test/shutdown", {})
        except Exception:
            pass
        web.wait(timeout=10)
        # leave an orphan temp file to prove startup cleanup
        (ev / f".{pending_uid}.tmp.zip").write_bytes(b"partial")
        web2 = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        procs["web"] = web2
        wait_http(base + "/healthz")
        time.sleep(1.0)
        pj = json.loads(http("GET", f"{base}/api/forensics/jobs/{pending_uid}")[1])
        check("pending order marked failed after restart",
              pj["status"] == "failed" and "restart" in (pj["failure_reason"] or ""))
        check("orphan temp package removed",
              not (ev / f".{pending_uid}.tmp.zip").exists())
        fj = json.loads(http("GET", f"{base}/api/forensics/jobs/{finished_uid}")[1])
        check("finished order still succeeded after restart", fj["status"] == "succeeded")
        st, blob = http("GET", f"{base}/api/forensics/jobs/{finished_uid}/download")
        check("finished package still downloadable",
              st == 200 and blob[:2] == b"PK", str(st))
        # re-request the interrupted one and let it finish
        st, body = http("POST", base + "/api/forensics/jobs",
                        {"device_id": "dev-1",
                         "event_utc_from": "2030-02-01T00:00:00Z",
                         "event_utc_to": "2030-02-02T00:00:00Z"})
        redo_uid = json.loads(body)["job_uid"]
        redo = wait_status(base, redo_uid, "succeeded")
        check("re-requested order succeeds (empty interval)",
              redo["item_count"] == 0)

        print(f"\n==== {PASS} passed, {FAIL} failed ====")
    finally:
        try:
            http("POST", base + "/__test/shutdown", {})
        except Exception:
            pass
        for cid in ("collector-a", "collector-b"):
            (shared / f".stop-{cid}").touch()
        for name, p in procs.items():
            try:
                p.wait(timeout=8)
                continue
            except subprocess.TimeoutExpired:
                pass
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except (PermissionError, subprocess.TimeoutExpired):
                pass
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
