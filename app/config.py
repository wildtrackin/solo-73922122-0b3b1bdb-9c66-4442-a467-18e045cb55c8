"""Runtime configuration, driven by environment variables so the same
image can be used by the gateway / collector / web services."""
from __future__ import annotations

import os
from pathlib import Path

# Shared directory that the gateway writes JSONL files into and the
# collectors read from.  In compose this is a mounted shared volume.
SHARED_DIR = Path(os.getenv("SHARED_DIR", "/data/shared")).resolve()

# SQLite database file (lives on its own volume in compose).
DB_PATH = Path(os.getenv("DB_PATH", "/data/warehouse/alarms.db")).resolve()

# Forensic evidence packages are written here (its own compose volume so
# temporary and finished ZIPs stay on disk, never in the page cache budget).
EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "/data/evidence")).resolve()

# Streaming chunk size used while copying source prefixes into evidence ZIPs.
# Bounded memory regardless of source file size.
FORENSICS_CHUNK = int(os.getenv("FORENSICS_CHUNK", str(1024 * 1024)))

# File name the gateway is currently appending to.
CURRENT_FILE = os.getenv("CURRENT_FILE", "alarms.jsonl")

# Rotation keeps CURRENT_FILE + at most this many renamed old files.
MAX_GENERATIONS = int(os.getenv("MAX_GENERATIONS", "3"))

# Collector scan interval (seconds).
SCAN_INTERVAL = float(os.getenv("SCAN_INTERVAL", "0.5"))

# How many bytes a single read() call pulls at most.
READ_CHUNK = int(os.getenv("READ_CHUNK", str(1024 * 1024)))

# Safety cap on one logical line: a record with no newline beyond this size
# is treated as a stuck/abusive line and held (never silently truncated).
MAX_LINE_BYTES = int(os.getenv("MAX_LINE_BYTES", str(64 * 1024 * 1024)))

# Stable identity of this collector process/instance.
COLLECTOR_ID = os.getenv("COLLECTOR_ID", "collector-unknown")
