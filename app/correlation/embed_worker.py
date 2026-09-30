"""Child process for correlation pass 2: ``python -m app.correlation.embed_worker``.

Reads {"model", "cache_dir", "texts"} as JSON on stdin and writes the
normalised vectors as a JSON list on stdout, then exits, so torch and the
model never stay in the long-running app process. Imports nothing from the
app beyond this file.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    request = json.load(sys.stdin)
    from sentence_transformers import SentenceTransformer

    # local_files_only: the platform never downloads models while running.
    model = SentenceTransformer(request["model"], cache_folder=request.get("cache_dir"), device="cpu",
                                local_files_only=True)  # fmt: skip
    vectors = model.encode(list(request["texts"]), normalize_embeddings=True, show_progress_bar=False)
    json.dump([[float(x) for x in v] for v in vectors], sys.stdout)


if __name__ == "__main__":
    main()
