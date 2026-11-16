"""Gateway simulator.

Writes JSONL alarm files into the shared directory and demonstrates
rename-only rotation:

* the live file is always ``CURRENT_FILE``;
* rotation renames the live file and immediately creates a new empty
  file with the same name -- nothing is deleted or truncated;
* at most ``MAX_GENERATIONS`` files are kept; rotation is refused beyond
  that so no old file (and therefore no backfill data) can disappear;
* old files can still be appended to after rotation (backfill).

A ``flock`` on a sidecar lock file serialises every mutating operation,
including across worker processes.
"""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from . import config


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _lock_path() -> Path:
    return config.SHARED_DIR / ".gateway.lock"


@contextmanager
def gateway_lock() -> Iterator[None]:
    config.SHARED_DIR.mkdir(parents=True, exist_ok=True)
    fh = open(_lock_path(), "w")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()


def _old_path(generation: int) -> Path:
    # alarms.1.jsonl, alarms.2.jsonl, ...
    stem, suffix = os.path.splitext(config.CURRENT_FILE)
    return config.SHARED_DIR / f"{stem}.{generation}{suffix}"


def list_files() -> list[dict]:
    """Return every JSONL file in the shared dir with stat info."""
    out: list[dict] = []
    if not config.SHARED_DIR.exists():
        return out
    for p in sorted(config.SHARED_DIR.glob("*.jsonl")):
        st = p.stat()
        out.append(
            {
                "name": p.name,
                "path": str(p),
                "inode": st.st_ino,
                "size": st.st_size,
                "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
            }
        )
    return out


def _jsonl_files() -> list[Path]:
    return sorted(config.SHARED_DIR.glob("*.jsonl"))


def _ensure_current() -> Path:
    config.SHARED_DIR.mkdir(parents=True, exist_ok=True)
    cur = config.SHARED_DIR / config.CURRENT_FILE
    if not cur.exists():
        cur.touch()
    return cur


def make_line(device_id: str | None = None,
              alarm_code: str | None = None,
              event_utc: str | None = None) -> str:
    payload = {
        "device_id": device_id or f"dev-{os.getpid() % 100:03d}",
        "event_utc": event_utc or utc_now(),
        "alarm_code": alarm_code or "ALM-1001",
    }
    return json.dumps(payload, ensure_ascii=False)


def append_alarm(filename: str | None = None,
                 device_id: str | None = None,
                 alarm_code: str | None = None,
                 event_utc: str | None = None) -> dict:
    """Append one complete newline-terminated JSON record."""
    with gateway_lock():
        target = config.SHARED_DIR / filename if filename else _ensure_current()
        line = make_line(device_id, alarm_code, event_utc)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        st = target.stat()
        return {
            "file": target.name,
            "inode": st.st_ino,
            "size": st.st_size,
            "line": line,
        }


def append_fragment(text: str, filename: str | None = None) -> dict:
    """Append raw text WITHOUT a trailing newline.

    Used to demonstrate that a record lacking its terminating newline is
    held back by the collectors until the line is completed later.
    """
    return append_raw(text, filename=filename, newline=False)


def append_raw(text: str, filename: str | None = None, newline: bool = False) -> dict:
    with gateway_lock():
        target = config.SHARED_DIR / filename if filename else _ensure_current()
        data = text + ("\n" if newline else "")
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        st = target.stat()
        return {"file": target.name, "inode": st.st_ino, "size": st.st_size}


def complete_line(tail: str = "\n", filename: str | None = None) -> dict:
    """Complete a previously fragmented line (default: just the newline)."""
    return append_raw(tail, filename=filename, newline=False)


def rotate() -> dict:
    """Rename-only rotation. Refuses once MAX_GENERATIONS files exist."""
    with gateway_lock():
        config.SHARED_DIR.mkdir(parents=True, exist_ok=True)
        cur = config.SHARED_DIR / config.CURRENT_FILE
        existing = _jsonl_files()
        if len(existing) >= config.MAX_GENERATIONS:
            raise RuntimeError(
                f"rotation refused: {len(existing)} files already present "
                f"(limit {config.MAX_GENERATIONS}); no file is deleted or truncated"
            )
        old_inode = None
        old_size = 0
        if cur.exists():
            st = cur.stat()
            old_inode, old_size = st.st_ino, st.st_size
            # shift existing generations backwards: 2->3, 1->2, ...
            gens = sorted(
                int(p.name.split(".")[-2])
                for p in existing
                if p.name != config.CURRENT_FILE
            )
            for gen in reversed(gens):
                _old_path(gen).rename(_old_path(gen + 1))
            cur.rename(_old_path(1))
        # create a brand new empty file with the same name (new inode)
        cur.touch()
        os.sync()
        return {
            "rotated": old_inode is not None,
            "previous_inode": old_inode,
            "previous_size": old_size,
            "files": list_files(),
        }
