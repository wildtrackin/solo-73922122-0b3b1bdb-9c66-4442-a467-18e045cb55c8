#!/bin/sh
# Role dispatcher:
#   web        -> FastAPI + uvicorn (also creates the live file)
#   collector  -> one collector process (COLLECTOR_ID set by compose)
set -eu

mkdir -p "${SHARED_DIR:-/data/shared}" "$(dirname "${DB_PATH:-/data/warehouse/alarms.db}")" "${EVIDENCE_DIR:-/data/evidence}"

case "${1:-web}" in
  web)
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000
    ;;
  collector)
    exec python -m app.collector
    ;;
  *)
    exec "$@"
    ;;
esac
