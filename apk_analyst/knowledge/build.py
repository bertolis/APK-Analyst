"""Build the knowledge index (run once, or when sources change).

    python3 run.py --build-kb

Gathers course + MASVS chunks, embeds them with Voyage, and writes the index
to apk_analyst/data/knowledge/. The agent then loads that index read-only.
"""
from __future__ import annotations

from pathlib import Path

from .corpus import gather_chunks
from .embedder import Embedder
from .store import DATA_DIR, KnowledgeBase

_CACHE = DATA_DIR.parent / "masvs_cache"


def build_index(out_dir: Path = DATA_DIR) -> KnowledgeBase:
    print("Building knowledge index...")
    chunks = gather_chunks(_CACHE)
    if not chunks:
        raise RuntimeError("no knowledge chunks gathered (check course dir / network)")
    print(f"  embedding {len(chunks)} chunk(s) with Voyage...")
    kb = KnowledgeBase.build(chunks, Embedder())
    kb.save(out_dir)
    by_src: dict[str, int] = {}
    for c in kb.chunks:
        by_src[c["source"]] = by_src.get(c["source"], 0) + 1
    print(f"  saved {len(kb)} vectors to {out_dir}  ({by_src})")
    return kb


if __name__ == "__main__":
    build_index()
