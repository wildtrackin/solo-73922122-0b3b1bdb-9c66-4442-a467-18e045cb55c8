"""FastAPI web service: gateway control + ingestion inspection + forensics."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import config, db, forensics, gateway

# One background packer for the whole web process.
worker = forensics.ForensicsWorker()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    config.SHARED_DIR.mkdir(parents=True, exist_ok=True)
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db()
    # Orders interrupted by a restart can never finish in this process.
    forensics.sweep_interrupted()
    # Make sure the live file exists so the page is usable immediately.
    gateway._ensure_current()
    worker.start()
    yield
    worker.stop()


app = FastAPI(title="Alarm Gateway & Collector Demo", version="1.0.0",
              lifespan=lifespan)


# --------------------------------------------------------------------- models
class AppendIn(BaseModel):
    filename: str | None = Field(None, description="target file; live file if omitted")
    device_id: str | None = None
    alarm_code: str | None = None
    event_utc: str | None = None


class FragmentIn(BaseModel):
    text: str = Field(..., description="raw bytes written WITHOUT trailing newline")
    filename: str | None = None


class CompleteIn(BaseModel):
    tail: str = Field("\n", description="text appended to finish the line")
    filename: str | None = None


class ForensicsIn(BaseModel):
    device_id: str = Field(..., description="exact device_id to collect evidence for")
    event_utc_from: str = Field(..., description="inclusive UTC lower bound, ISO-8601 ...Z")
    event_utc_to: str = Field(..., description="inclusive UTC upper bound, ISO-8601 ...Z")


# --------------------------------------------------------------------- gateway
@app.post("/api/gateway/append", tags=["gateway"])
def append_record(body: AppendIn) -> dict:
    """Append one complete newline-terminated JSON alarm record."""
    return gateway.append_alarm(
        filename=body.filename,
        device_id=body.device_id,
        alarm_code=body.alarm_code,
        event_utc=body.event_utc,
    )


@app.post("/api/gateway/fragment", tags=["gateway"])
def append_fragment(body: FragmentIn) -> dict:
    """Write a record without its trailing newline (held back by collectors)."""
    return gateway.append_fragment(body.text, filename=body.filename)


@app.post("/api/gateway/complete", tags=["gateway"])
def complete_line(body: CompleteIn) -> dict:
    """Finish a previously fragmented line."""
    return gateway.complete_line(tail=body.tail, filename=body.filename)


@app.post("/api/gateway/rotate", tags=["gateway"])
def rotate() -> dict:
    """Rename-only rotation; refuses beyond MAX_GENERATIONS (never deletes)."""
    try:
        return gateway.rotate()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/gateway/files", tags=["gateway"])
def files() -> dict:
    return {"shared_dir": str(config.SHARED_DIR), "files": gateway.list_files()}


# ----------------------------------------------------------------- inspection
@app.get("/api/alarms", tags=["warehouse"])
def list_alarms(limit: int = Query(200, ge=1, le=5000),
                offset: int = Query(0, ge=0),
                file_id: str | None = None,
                device_id: str | None = None) -> dict:
    conn = db.connect()
    try:
        where, params = "", []
        if file_id:
            where, params = "WHERE file_id = ?", [file_id]
        elif device_id:
            where, params = "WHERE device_id = ?", [device_id]
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM alarms {where}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT id, file_id, line_no, byte_offset, raw_line, device_id,
                       event_utc, alarm_code, parse_ok, source_path,
                       ingested_by, ingested_utc
                  FROM alarms {where}
                 ORDER BY id DESC LIMIT ? OFFSET ?""",
            [*params, limit, offset],
        ).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/file-states", tags=["warehouse"])
def file_states() -> dict:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM file_states ORDER BY id"
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/collectors", tags=["warehouse"])
def collectors() -> dict:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM collector_heartbeats ORDER BY collector_id"
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/errors", tags=["warehouse"])
def errors(limit: int = Query(100, ge=1, le=1000)) -> dict:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM ingest_errors ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/stats", tags=["warehouse"])
def stats() -> dict:
    conn = db.connect()
    try:
        alarm_total = conn.execute("SELECT COUNT(*) c FROM alarms").fetchone()["c"]
        file_total = conn.execute("SELECT COUNT(*) c FROM file_states").fetchone()["c"]
        offset_sum = conn.execute(
            "SELECT COALESCE(SUM(read_offset),0) s FROM file_states"
        ).fetchone()["s"]
        disk_size = 0
        if config.SHARED_DIR.exists():
            disk_size = sum(
                p.stat().st_size for p in config.SHARED_DIR.glob("*.jsonl")
            )
        return {
            "alarm_rows": alarm_total,
            "tracked_files": file_total,
            "committed_bytes": offset_sum,
            "disk_bytes": disk_size,
            "fully_ingested": offset_sum == disk_size,
        }
    finally:
        conn.close()


# ------------------------------------------------------------------- forensics
@app.post("/api/forensics/jobs", tags=["forensics"], status_code=201)
def create_forensics_job(body: ForensicsIn) -> dict:
    """Accept an evidence order against one committed warehouse snapshot."""
    try:
        return forensics.accept_job(
            body.device_id, body.event_utc_from, body.event_utc_to
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/forensics/jobs", tags=["forensics"])
def forensics_jobs(limit: int = Query(100, ge=1, le=1000)) -> dict:
    return {"items": forensics.list_jobs(limit)}


@app.get("/api/forensics/jobs/{job_uid}", tags=["forensics"])
def forensics_job(job_uid: str) -> dict:
    job = forensics.get_job(job_uid)
    if job is None:
        raise HTTPException(status_code=404, detail="forensics job not found")
    return job


@app.get("/api/forensics/jobs/{job_uid}/items", tags=["forensics"])
def forensics_job_items(job_uid: str,
                        limit: int = Query(500, ge=1, le=5000),
                        offset: int = Query(0, ge=0)) -> dict:
    if forensics.get_job(job_uid) is None:
        raise HTTPException(status_code=404, detail="forensics job not found")
    return forensics.list_items(job_uid, limit, offset)


@app.get("/api/forensics/jobs/{job_uid}/snapshots", tags=["forensics"])
def forensics_job_snapshots(job_uid: str) -> dict:
    if forensics.get_job(job_uid) is None:
        raise HTTPException(status_code=404, detail="forensics job not found")
    return {"items": forensics.list_snapshots(job_uid)}


@app.get("/api/forensics/jobs/{job_uid}/download", tags=["forensics"])
def forensics_download(job_uid: str) -> StreamingResponse:
    """Stream the finished ZIP. Failed/in-progress orders are never served."""
    job = forensics.get_job(job_uid)
    if job is None:
        raise HTTPException(status_code=404, detail="forensics job not found")
    if job["status"] != "succeeded":
        raise HTTPException(
            status_code=409,
            detail=f"job is {job['status']}; download is only available after success",
        )
    path = forensics.zip_path_for(job)
    if not path.is_file():
        raise HTTPException(status_code=410, detail="evidence package missing on disk")

    def stream():
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(config.FORENSICS_CHUNK)
                if not chunk:
                    break
                yield chunk

    return StreamingResponse(
        stream(),
        media_type="application/zip",
        headers={
            "Content-Disposition":
                f'attachment; filename="evidence-{job_uid}.zip"',
            "Content-Length": str(path.stat().st_size),
        },
    )


# ------------------------------------------------------------------------ page
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(str(Path(__file__).parent / "static" / "index.html"))


@app.get("/forensics", include_in_schema=False)
def forensics_page() -> FileResponse:
    return FileResponse(str(Path(__file__).parent / "static" / "forensics.html"))


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"status": "ok", "pid": os.getpid()}


@app.post("/__test/shutdown", include_in_schema=False)
def shutdown() -> dict:
    """Test-only graceful shutdown, enabled by ALLOW_TEST_SHUTDOWN=1."""
    if os.getenv("ALLOW_TEST_SHUTDOWN") != "1":
        raise HTTPException(status_code=404, detail="not found")
    import threading

    def _stop() -> None:
        import time as _time

        _time.sleep(0.1)
        os._exit(0)

    threading.Thread(target=_stop, daemon=True).start()
    return {"status": "shutting down"}
