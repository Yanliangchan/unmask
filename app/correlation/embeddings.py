"""Local text embeddings for correlation pass 2 (CPU only, no network at runtime).

The model is baked into the Docker image at build time. When the library or
model is missing, pass 2 is reported as skipped — never silently replaced by
something weaker.

torch and the model take ~300 MB, far more than the rest of the app, and pass 2
runs once per scan. So the model never loads in the web or worker process: each
``embed()`` call runs ``python -m app.correlation.embed_worker`` in a child
process, which exits as soon as the vectors are back and returns all of that
memory to the OS. Checking whether pass 2 is available only looks for the
package and the model files; it imports nothing.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import math
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from app.config import get_settings

log = logging.getLogger(__name__)

EMBED_TIMEOUT_SECONDS = 120
_REPO_ROOT = str(Path(__file__).resolve().parents[2])


class EmbeddingError(RuntimeError):
    pass


class Embedder(Protocol):
    name: str

    async def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


def model_files_present(model_name: str, cache_dir: str | None) -> bool:
    """Whether the model is on disk where SentenceTransformer(local_files_only=True) will look."""
    if os.path.isdir(model_name):
        return True
    hub_dir = "models--" + model_name.replace("/", "--")
    legacy = model_name.replace("/", "_")
    roots = [cache_dir] if cache_dir else []
    roots += [
        os.environ.get("SENTENCE_TRANSFORMERS_HOME"),
        os.environ.get("HF_HUB_CACHE"),
        os.path.join(os.environ["HF_HOME"], "hub") if os.environ.get("HF_HOME") else None,
        os.path.join(Path.home(), ".cache", "huggingface", "hub"),
    ]
    return any(root and (os.path.isdir(os.path.join(root, hub_dir)) or os.path.isdir(os.path.join(root, legacy)))
               for root in roots)  # fmt: skip


class SentenceTransformerEmbedder:
    """Runs the model in a short-lived child process per call."""

    def __init__(self, model_name: str, cache_dir: str | None) -> None:
        self.model_name, self.cache_dir = model_name, cache_dir
        self.name = model_name.rstrip("/").rsplit("/", 1)[-1]

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        # One model in memory at a time: concurrent scans (pivots) take turns.
        async with _one_at_a_time():
            return await self._embed(texts)

    async def _embed(self, texts: Sequence[str]) -> list[list[float]]:
        # Only what the model needs: no database URL, keys or session secret.
        env = {k: v for k, v in os.environ.items()
               if k in ("PATH", "HOME", "LANG", "HF_HOME", "HF_HUB_CACHE", "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE",
                        "SENTENCE_TRANSFORMERS_HOME", "PYTHONPATH", "MALLOC_ARENA_MAX")}  # fmt: skip
        env.update({"OMP_NUM_THREADS": "1", "TOKENIZERS_PARALLELISM": "false", "PYTHONUNBUFFERED": "1"})
        request = json.dumps({"model": self.model_name, "cache_dir": self.cache_dir, "texts": list(texts)})
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "app.correlation.embed_worker",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=env, cwd=_REPO_ROOT,
        )  # fmt: skip
        try:
            out, err = await asyncio.wait_for(proc.communicate(request.encode()), EMBED_TIMEOUT_SECONDS)
        except (TimeoutError, asyncio.CancelledError) as exc:
            proc.kill()
            await asyncio.shield(proc.wait())
            if isinstance(exc, TimeoutError):
                raise EmbeddingError(f"embedding process timed out after {EMBED_TIMEOUT_SECONDS}s") from exc
            raise
        if proc.returncode != 0:
            tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or ["no output"]
            raise EmbeddingError(f"embedding process failed: {tail[0][:200]}")
        vectors = json.loads(out)
        if len(vectors) != len(texts):
            raise EmbeddingError("embedding process returned the wrong number of vectors")
        return vectors


_locks: dict[int, asyncio.Lock] = {}


def _one_at_a_time() -> asyncio.Lock:
    key = id(asyncio.get_running_loop())
    if key not in _locks:
        if len(_locks) > 16:
            _locks.clear()
        _locks[key] = asyncio.Lock()
    return _locks[key]


_embedder: Embedder | None = None
_unavailable_reason: str | None = None
_loaded = False


def get_embedder() -> tuple[Embedder | None, str | None]:
    """Returns (embedder, None) or (None, reason it is unavailable). Cheap: loads no model."""
    global _embedder, _unavailable_reason, _loaded
    if not _loaded:
        _loaded, _embedder, _unavailable_reason = True, None, None
        s = get_settings()
        if not s.embedding_model:
            _unavailable_reason = "embedding model disabled (UNMASK_EMBEDDING_MODEL is empty)"
        elif importlib.util.find_spec("sentence_transformers") is None:
            _unavailable_reason = "sentence-transformers is not installed"
        elif not model_files_present(s.embedding_model, s.embedding_cache_dir or None):
            _unavailable_reason = "embedding model could not be loaded: model files are missing"
        else:
            _embedder = SentenceTransformerEmbedder(s.embedding_model, s.embedding_cache_dir or None)
    return _embedder, _unavailable_reason


def set_embedder(embedder: Embedder | None, reason: str | None = None) -> None:
    """Override the embedder (tests, or an operator swapping models)."""
    global _embedder, _unavailable_reason, _loaded
    _embedder, _unavailable_reason, _loaded = embedder, reason, True


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0
