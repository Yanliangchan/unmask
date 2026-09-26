"""Local text embeddings for correlation pass 2 (CPU only, no network at runtime).

The model is baked into the Docker image at build time. When the library or
model is missing, pass 2 is reported as skipped — never silently replaced by
something weaker.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Sequence
from typing import Protocol

from app.config import get_settings

log = logging.getLogger(__name__)


class Embedder(Protocol):
    name: str

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str, cache_dir: str | None) -> None:
        from sentence_transformers import SentenceTransformer

        self.name = model_name.rsplit("/", 1)[-1]
        # local_files_only: the platform never downloads models while running.
        self._model = SentenceTransformer(model_name, cache_folder=cache_dir, device="cpu", local_files_only=True)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors = self._model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False)
        return [list(map(float, v)) for v in vectors]


_embedder: Embedder | None = None
_unavailable_reason: str | None = None
_loaded = False


def get_embedder() -> tuple[Embedder | None, str | None]:
    """Returns (embedder, None) or (None, reason it is unavailable)."""
    global _embedder, _unavailable_reason, _loaded
    if not _loaded:
        _loaded = True
        s = get_settings()
        if not s.embedding_model:
            _unavailable_reason = "embedding model disabled (UNMASK_EMBEDDING_MODEL is empty)"
        else:
            try:
                _embedder = SentenceTransformerEmbedder(s.embedding_model, s.embedding_cache_dir or None)
            except ImportError:
                _unavailable_reason = "sentence-transformers is not installed"
            except Exception as exc:  # model files missing, corrupt, ...
                _unavailable_reason = f"embedding model could not be loaded: {exc.__class__.__name__}"
                log.warning("embedding model unavailable: %s", exc)
    return _embedder, _unavailable_reason


def set_embedder(embedder: Embedder | None, reason: str | None = None) -> None:
    """Override the embedder (tests, or an operator swapping models)."""
    global _embedder, _unavailable_reason, _loaded
    _embedder, _unavailable_reason, _loaded = embedder, reason, True


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0
