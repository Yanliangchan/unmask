"""Memory: embeddings in a child process, the command-line tool cap, the idle monitor and trim()."""

from __future__ import annotations

import asyncio
import sys
import time

import pytest

from app.adapters.base import run_tool_subprocess
from app.config import get_settings
from app.correlation import embeddings
from app.correlation.embeddings import EmbeddingError, SentenceTransformerEmbedder, get_embedder, set_embedder
from app.idle import IdleMonitor
from app.memory import rss_mb, trim

# A stand-in for the sentence-transformers package, importable only by the child process.
STUB = """
class SentenceTransformer:
    def __init__(self, name, cache_folder=None, device=None, local_files_only=False):
        assert local_files_only and device == "cpu"
        self.name = name

    def encode(self, texts, normalize_embeddings=False, show_progress_bar=True):
        return [[1.0, float(len(t))] for t in texts]
"""


@pytest.fixture
def stub_package(tmp_path, monkeypatch):
    pkg = tmp_path / "sentence_transformers"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(STUB)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    return tmp_path


@pytest.fixture
def fresh_embedder_state(monkeypatch):
    monkeypatch.setattr(embeddings, "_loaded", False)
    monkeypatch.setattr(embeddings, "_embedder", None)
    monkeypatch.setattr(embeddings, "_unavailable_reason", None)
    yield
    set_embedder(None, "disabled in tests")


async def test_embeddings_run_in_a_child_process_that_exits(stub_package, tmp_path):
    model_dir = tmp_path / "all-MiniLM-L6-v2"
    model_dir.mkdir()
    embedder = SentenceTransformerEmbedder(str(model_dir), None)
    assert embedder.name == "all-MiniLM-L6-v2"
    assert await embedder.embed(["ab", "abcd"]) == [[1.0, 2.0], [1.0, 4.0]]
    # Nothing heavy was imported here: the model only ever lived in the child.
    assert "sentence_transformers" not in sys.modules and "torch" not in sys.modules


async def test_a_failing_embedding_process_is_an_embedding_error(tmp_path, monkeypatch):
    bad = tmp_path / "sentence_transformers"
    bad.mkdir()
    (bad / "__init__.py").write_text("raise RuntimeError('model files are corrupt')\n")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    with pytest.raises(EmbeddingError, match="model files are corrupt"):
        await SentenceTransformerEmbedder("x", None).embed(["a", "b"])


def test_availability_is_checked_without_importing_the_model(stub_package, tmp_path, monkeypatch,
                                                             fresh_embedder_state):  # fmt: skip
    s = get_settings()
    monkeypatch.syspath_prepend(str(stub_package))
    monkeypatch.setattr(s, "embedding_model", str(tmp_path / "missing-model"))
    assert get_embedder() == (None, "embedding model could not be loaded: model files are missing")

    monkeypatch.setattr(embeddings, "_loaded", False)
    (tmp_path / "present-model").mkdir()
    monkeypatch.setattr(s, "embedding_model", str(tmp_path / "present-model"))
    embedder, reason = get_embedder()
    assert reason is None and embedder.name == "present-model"
    assert "sentence_transformers" not in sys.modules

    monkeypatch.setattr(embeddings, "_loaded", False)
    monkeypatch.setattr(s, "embedding_model", "")
    assert get_embedder()[1] == "embedding model disabled (UNMASK_EMBEDDING_MODEL is empty)"


def test_hub_cache_layout_counts_as_present(tmp_path):
    (tmp_path / "models--sentence-transformers--all-MiniLM-L6-v2").mkdir()
    assert embeddings.model_files_present("sentence-transformers/all-MiniLM-L6-v2", str(tmp_path))
    assert not embeddings.model_files_present("sentence-transformers/other", str(tmp_path))


async def test_pass2_reports_an_embedding_failure_instead_of_crashing(db):
    from app.correlation import engine
    from tests.test_correlation import add, new_case

    class Broken:
        name = "broken"

        async def embed(self, texts):
            raise EmbeddingError("embedding process failed: out of memory")

    set_embedder(Broken())
    try:
        case = await new_case(db)
        add(db, case, "name", "J. Chan")
        add(db, case, "name", "Yan Liang Chan")
        await db.flush()
        result = await engine.correlate_case(db, case.id)
        assert result.pass2 == "skipped (embedding process failed: out of memory)"
    finally:
        set_embedder(None, "disabled in tests")


async def test_command_line_tools_are_capped_and_queue_time_is_not_timeout(monkeypatch):
    monkeypatch.setattr(get_settings(), "tool_processes", 2)
    sleeper = [sys.executable, "-c", "import time; time.sleep(0.4)"]
    started = time.monotonic()
    # timeout=0.7 covers one run but not the queueing before it: queue time must not count.
    results = await asyncio.gather(*(run_tool_subprocess(sleeper, timeout=0.7) for _ in range(4)))
    elapsed = time.monotonic() - started
    assert all(r.returncode == 0 for r in results)
    assert elapsed >= 0.8  # two batches of two, not four at once


async def test_idle_monitor_winds_down_and_wakes_on_the_next_request(monkeypatch):
    disposed = []

    async def fake_dispose():
        disposed.append(True)

    monkeypatch.setattr("app.db.dispose_engine", fake_dispose)
    ticks = []

    async def scheduler():
        ticks.append(time.monotonic())
        await asyncio.sleep(3600)

    mon = IdleMonitor(1, scheduler)
    mon.start()
    try:
        await asyncio.sleep(0.05)
        assert len(ticks) == 1 and not mon.quiet
        # A request in flight keeps it awake past the idle time.
        mon.request_started()
        await asyncio.sleep(1.3)
        assert not mon.quiet and not disposed
        mon.request_finished()
        await asyncio.sleep(1.3)
        assert mon.quiet and disposed and mon._scheduler is None

        mon.request_started()
        mon.request_finished()
        await asyncio.sleep(0.05)
        assert not mon.quiet and len(ticks) == 2  # the scheduler restarted and ticked straight away
    finally:
        await mon.stop()


def test_trim_is_safe_and_rss_is_readable():
    trim()
    trim()
    assert rss_mb() > 0
