"""FastAPI web service: gateway control + ingestion inspection."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import config, db, gateway


@asynccontextmanager
async def lifespan(_app: FastAPI):
    config.SHARED_DIR.mkdir(parents=True, exist_ok=True)
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db.init_db()
    # Make sure the live file exists so the page is usable immediately.
    gateway._ensure_current()
    yield


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


# ------------------------------------------------------------------------ page
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(str(Path(__file__).parent / "static" / "index.html"))


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
