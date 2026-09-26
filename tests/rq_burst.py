"""Run one burst RQ worker with the test fake adapters, as a real worker process would."""

import os

from rq import Queue, SimpleWorker

from app.adapters import registry
from app.jobs import QUEUES_BY_PRIORITY, redis_connection
from tests.fakes import FakeFailingAdapter, FakeUsernameAdapter

for adapter in registry.all_adapters():
    registry.unregister(adapter.name)
registry.register(FakeUsernameAdapter())
registry.register(FakeFailingAdapter())

if os.environ.get("UNMASK_TEST_CRASH"):
    import app.services.scans as scans

    async def _boom(run_id):
        raise RuntimeError("database went away")

    scans.execute_scan_run = _boom

conn = redis_connection()
SimpleWorker([Queue(q, connection=conn) for q in QUEUES_BY_PRIORITY], connection=conn).work(burst=True)
