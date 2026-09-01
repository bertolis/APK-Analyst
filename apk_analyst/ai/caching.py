"""Prompt caching helpers — cut the cost of the agentic loop.

The Step-3 agent re-sends the SAME large prefix on every one of its ~16
iterations: the system prompt (the whole playbook), the tool schemas, and the
seed context, plus a transcript that only grows. Anthropic prompt caching lets
the API reuse that prefix instead of re-reading it each call — cached reads cost
~10% of normal input tokens (writes cost ~25% more, paid once).

We place cache breakpoints with `cache_control: {"type": "ephemeral"}`:
  * `cache_system` / `cache_tools` — mark the two STATIC prefixes (identical on
    every call), each its own long-lived breakpoint.
  * `mark_rolling_cache` — move ONE breakpoint onto the latest message before
    each call, so the whole conversation-so-far is cached incrementally: each
    turn re-reads the cached transcript and only pays full price for the new turn.

That's 3 breakpoints total (Anthropic allows 4). Caching has a minimum size
(~1024 tokens); prefixes below it simply aren't cached — no error, no harm.
"""
from __future__ import annotations

from typing import Any

_EPHEMERAL = {"type": "ephemeral"}


def cache_system(text: str) -> list[dict]:
    """Turn the system prompt string into a single cached text block."""
    return [{"type": "text", "text": text, "cache_control": _EPHEMERAL}]


def cache_tools(schemas: list[dict]) -> list[dict]:
    """Copy the tool schemas and cache the block by marking the last tool
    (a breakpoint caches everything up to and including it)."""
    tools = [dict(s) for s in schemas]
    tools[-1] = {**tools[-1], "cache_control": _EPHEMERAL}
    return tools


def mark_rolling_cache(messages: list[dict]) -> None:
    """Keep exactly one rolling breakpoint on the last message's last block, so
    the entire message prefix is cached. Mutates `messages` in place.

    Only touches dict-based content blocks we build (seed + tool_result turns);
    assistant turns hold SDK objects and are left alone — the rolling breakpoint
    always lands on the trailing user message right before a create() call."""
    # Drop any stale breakpoint we set on a previous turn (avoid piling up past 4).
    for m in messages:
        content = m.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    block.pop("cache_control", None)

    last = messages[-1]
    content = last["content"]
    if isinstance(content, str):
        last["content"] = [{"type": "text", "text": content, "cache_control": _EPHEMERAL}]
    elif isinstance(content, list) and content and isinstance(content[-1], dict):
        content[-1]["cache_control"] = _EPHEMERAL


def usage_delta(usage: Any) -> tuple[int, int]:
    """(cache_read, cache_write) tokens from a response usage object, 0 if absent."""
    read = getattr(usage, "cache_read_input_tokens", 0) or 0
    write = getattr(usage, "cache_creation_input_tokens", 0) or 0
    return read, write
