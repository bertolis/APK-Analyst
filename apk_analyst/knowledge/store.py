"""The vector store — what a "vector store" actually is, minimally.

For a corpus this small (a few hundred chunks) a real DB (Chroma/FAISS) is
overkill. We store L2-normalized embeddings in one numpy matrix and the chunk
metadata in parallel; a query becomes a dot-product against the matrix (cosine
similarity, since everything is normalized) and we take the top-k rows.

Index lives on disk as two files: embeddings.npy + chunks.json.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .corpus import Chunk
from .embedder import Embedder

# Default index location: apk_analyst/data/knowledge/
DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "knowledge"
_EMB = "embeddings.npy"
_META = "chunks.json"


def _normalize(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms


@dataclass
class Hit:
    score: float
    chunk: dict     # {text, source, category, title, ref}

    def as_context(self) -> str:
        c = self.chunk
        return (f"[{c['ref'] or c['category']}] {c['title']}  "
                f"(source: {c['source']}, relevance {self.score:.2f})\n{c['text']}")


class KnowledgeBase:
    def __init__(self, embeddings: np.ndarray, chunks: list[dict],
                 embedder: Embedder | None = None):
        self.embeddings = embeddings          # (N, D), normalized
        self.chunks = chunks                  # len N
        self._embedder = embedder             # lazily created for queries

    # --- build / persist ---
    @classmethod
    def build(cls, chunks: list[Chunk], embedder: Embedder) -> "KnowledgeBase":
        texts = [c.embed_text() for c in chunks]
        vecs = np.asarray(embedder.embed_documents(texts), dtype=np.float32)
        vecs = _normalize(vecs)
        meta = [{"text": c.text, "source": c.source, "category": c.category,
                 "title": c.title, "ref": c.ref} for c in chunks]
        return cls(vecs, meta, embedder)

    def save(self, out_dir: Path = DATA_DIR) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        np.save(out_dir / _EMB, self.embeddings)
        (out_dir / _META).write_text(json.dumps(self.chunks, indent=2))

    @classmethod
    def load(cls, in_dir: Path = DATA_DIR, embedder: Embedder | None = None) -> "KnowledgeBase":
        emb = np.load(in_dir / _EMB)
        chunks = json.loads((in_dir / _META).read_text())
        return cls(emb, chunks, embedder)

    @classmethod
    def exists(cls, in_dir: Path = DATA_DIR) -> bool:
        return (in_dir / _EMB).is_file() and (in_dir / _META).is_file()

    # --- query ---
    def search(self, query: str, k: int = 4, source: str | None = None) -> list[Hit]:
        if self._embedder is None:
            self._embedder = Embedder()
        q = np.asarray(self._embedder.embed_query(query), dtype=np.float32)
        q = q / (np.linalg.norm(q) or 1.0)
        scores = self.embeddings @ q                      # cosine similarities
        order = np.argsort(-scores)
        hits: list[Hit] = []
        for i in order:
            c = self.chunks[i]
            if source and c["source"] != source:
                continue
            hits.append(Hit(score=float(scores[i]), chunk=c))
            if len(hits) >= k:
                break
        return hits

    def __len__(self) -> int:
        return len(self.chunks)
