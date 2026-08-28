"""Voyage AI embeddings — turn text into vectors for semantic search.

Anthropic doesn't serve embeddings itself; Voyage is its recommended provider.
Documents and queries are embedded with matching `input_type` hints so the
vectors land in the right corner of the space for retrieval.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import voyageai
from dotenv import load_dotenv

MODEL = "voyage-3.5"        # general-purpose; strong on technical/security text
# Free tier without a card is 3 requests/min AND 10K tokens/min. Keep each batch
# small enough that ~3 batches/min stay under the token ceiling; a real word->token
# ratio runs ~1.4x, so budget conservatively on the estimate.
_TOKENS_PER_BATCH = 2200
_PACE_SECONDS = 22          # ~2.7 requests/min
_MAX_RETRIES = 6            # retry on transient rate-limit


def _est_tokens(text: str) -> int:
    return int(len(text.split()) * 1.3) + 2   # rough word->token estimate


def _budget_batches(texts: list[str]) -> list[list[str]]:
    """Group texts so each request stays under the per-minute token ceiling."""
    batches, cur, n = [], [], 0
    for t in texts:
        tk = _est_tokens(t)
        if cur and n + tk > _TOKENS_PER_BATCH:
            batches.append(cur)
            cur, n = [], 0
        cur.append(t)
        n += tk
    if cur:
        batches.append(cur)
    return batches


def load_voyage() -> voyageai.Client:
    """Load VOYAGE_API_KEY from .env and return a client."""
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    if not os.getenv("VOYAGE_API_KEY"):
        raise RuntimeError(
            "VOYAGE_API_KEY not set. Add it to the .env file at the project root "
            "(get a free key at https://dashboard.voyageai.com/)."
        )
    return voyageai.Client()


class Embedder:
    def __init__(self, client: voyageai.Client | None = None, model: str = MODEL):
        self.client = client or load_voyage()
        self.model = model

    def _embed(self, batch: list[str], input_type: str) -> list[list[float]]:
        """One request, retrying on rate-limit with backoff (free tier is 3 RPM)."""
        delay = float(_PACE_SECONDS)
        for attempt in range(_MAX_RETRIES):
            try:
                return self.client.embed(batch, model=self.model, input_type=input_type).embeddings
            except voyageai.error.RateLimitError:
                if attempt == _MAX_RETRIES - 1:
                    raise
                print(f"    rate-limited; waiting {delay:.0f}s (free tier)...")
                time.sleep(delay)
                delay = min(delay * 1.5, 60)
        raise RuntimeError("unreachable")

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        batches = _budget_batches(texts)
        out: list[list[float]] = []
        for i, batch in enumerate(batches, 1):
            if i > 1:
                time.sleep(_PACE_SECONDS)   # pace under the free-tier token/min ceiling
            print(f"    batch {i}/{len(batches)} ({len(batch)} chunks)...")
            out.extend(self._embed(batch, "document"))
        return out

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text], "query")[0]
