#!/bin/sh
set -e

python -m alembic upgrade head

# One worker: Phase 1 runs scans in-process. Phase 2 moves them to an RQ
# worker service, after which the web tier can scale horizontally.
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers 1 \
  --proxy-headers \
  --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-*}"
