#!/bin/sh
# One image, two roles: UNMASK_ROLE=web (default) or UNMASK_ROLE=worker.
set -e

# Fails with a readable list of missing variables, and waits for Postgres.
python -m app.cli preflight

if [ "${UNMASK_ROLE:-web}" = "worker" ]; then
  exec python -m app.worker
fi

python -m alembic upgrade head

# With UNMASK_QUEUE=inline scans run inside the web process, so keep a single
# worker; with rq the web tier is stateless and WEB_CONCURRENCY can be raised.
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers "${WEB_CONCURRENCY:-1}" \
  --proxy-headers \
  --timeout-keep-alive 5 \
  --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-*}"
