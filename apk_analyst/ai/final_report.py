"""Producing the final structured AnalysisReport — with a cheap recovery cascade.

The agent's investigation (Step 3) is the expensive part: many iterations, each
re-sending the whole transcript (native strings, tool outputs, source excerpts).
The very last step just serialises that finished work into JSON. Occasionally
that JSON comes back truncated/malformed (usually the model hit max_tokens),
and `messages.parse` throws — throwing away a completed, already-paid-for scan.

Re-running the whole final call re-sends the entire transcript again, so on a
large APK that is the single most expensive call in the run. We should almost
never need it. Instead we recover cheapest-first:

  Tier 1  local repair        — free. Strip fences, slice the JSON object, try to
                                 balance truncated brackets, then validate.
  Tier 2  Haiku JSON-fix      — cents. Send ONLY the broken report text + schema
                                 to a cheap model to rewrite as valid JSON. The
                                 investigation transcript is never re-sent.
  Tier 3  full re-parse       — expensive. Re-run the whole final call over the
                                 entire transcript. Gated by a confirm callback:
                                 the CLI asks the user; unattended callers (the
                                 eval harness) auto-retry once.

Tiers 1 and 2 fix the common truncation case for free/cents, so the user is only
ever asked before the one tier that actually costs real money.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

import anthropic
from pydantic import TypeAdapter

from .models import AnalysisReport

FIX_MODEL = "claude-haiku-4-5"   # cheap model for the Tier-2 JSON repair

# Callback invoked before the expensive Tier-3 full re-parse. It receives the
# last error and returns True to spend the big call, False to give up. None =
# unattended (eval harness): auto-retry once.
ConfirmRetry = Optional[Callable[[Exception], bool]]


def _schema_output_config() -> Optional[dict]:
    """Server-side json_schema constraint for AnalysisReport (same as messages.parse
    builds internally). Returns None if the SDK internals aren't where we expect —
    the caller then falls back to an unconstrained call + our own validation."""
    try:
        from anthropic.lib._parse._transform import transform_schema
        schema = TypeAdapter(AnalysisReport).json_schema()
        return {"format": {"type": "json_schema", "schema": transform_schema(schema)}}
    except Exception:
        return None


def _text_of(resp) -> str:
    return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")


# --- Tier 1: free local repair ------------------------------------------------

def _extract_json(text: str) -> str:
    """Pull the JSON object out of a model reply (drop ``` fences / prose)."""
    t = text.strip()
    if "```" in t:
        # take the content of the first fenced block
        parts = t.split("```")
        for p in parts:
            p = p.lstrip()
            if p.startswith("json"):
                p = p[4:]
            if p.lstrip().startswith("{"):
                t = p
                break
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return t[start:end + 1]
    return t[start:] if start != -1 else t


def _balance(text: str) -> str:
    """Best-effort close of a truncated JSON object: drop any dangling partial
    tail, then append the missing closing brackets in the right order."""
    # Walk the string tracking string-state and the bracket stack.
    stack: list[str] = []
    in_str = False
    esc = False
    last_safe = 0  # index just after the last completed value/structural char
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
                last_safe = i + 1
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
            last_safe = i + 1
        elif ch in "}]":
            if stack:
                stack.pop()
            last_safe = i + 1
        elif ch in ", \n\r\t":
            last_safe = i + 1 if ch not in ", " else last_safe
    # If we ended mid-string or mid-token, cut back to the last safe boundary.
    body = text if not in_str else text[:last_safe]
    body = body.rstrip().rstrip(",")
    return body + "".join(reversed(stack))


def _local_parse(text: str) -> Optional[AnalysisReport]:
    core = _extract_json(text)
    for candidate in (text, core, _balance(core)):
        if not candidate:
            continue
        try:
            return AnalysisReport.model_validate_json(candidate)
        except Exception:
            continue
    return None


# --- Tier 2: cheap Haiku JSON-fix (report text only, not the transcript) ------

_FIX_SYSTEM = (
    "You repair malformed or truncated JSON so it becomes a single valid JSON "
    "object matching the given schema. Preserve all real content; only fix "
    "structure (close brackets/strings, drop a dangling partial field). If a "
    "field was cut off mid-value, drop that incomplete entry rather than invent "
    "data. Output ONLY the JSON object, nothing else."
)


def _haiku_fix(client: anthropic.Anthropic, text: str) -> Optional[AnalysisReport]:
    schema = json.dumps(TypeAdapter(AnalysisReport).json_schema())
    kwargs: dict = dict(
        model=FIX_MODEL, max_tokens=16000, system=_FIX_SYSTEM,
        messages=[{"role": "user", "content":
                   f"JSON SCHEMA:\n{schema}\n\nMALFORMED / TRUNCATED OUTPUT TO FIX:\n{text}"}],
    )
    fmt = _schema_output_config()
    if fmt:
        kwargs["output_config"] = fmt
    try:
        resp = client.messages.create(**kwargs)
    except Exception:
        return None
    return _local_parse(_text_of(resp))


# --- Tier 0/3: the (expensive) full call over the whole transcript ------------

def produce_final_report(
    client: anthropic.Anthropic,
    *,
    model: str,
    system: str,
    tools,
    messages: list,
    max_tokens: int = 16000,
    on_expensive_retry: ConfirmRetry = None,
    verbose: bool = True,
) -> AnalysisReport:
    """Make the final structured-output call and recover cheaply if the JSON is
    malformed. `messages` already ends with the final-instruction user turn."""
    fmt = _schema_output_config()

    def big_call() -> tuple[str, bool]:
        kwargs: dict = dict(model=model, max_tokens=max_tokens, system=system,
                            tools=tools, messages=messages)
        if fmt:
            kwargs["output_config"] = fmt
        resp = client.messages.create(**kwargs)
        return _text_of(resp), (resp.stop_reason == "max_tokens")

    # Tier 0 — the one big call we always make (equivalent to the old parse call).
    text, truncated = big_call()

    # Tier 1 — free local repair.
    report = _local_parse(text)
    if report is not None:
        if truncated and verbose:
            # Salvaged from a max_tokens cut-off: findings that never finished
            # generating are gone for good (no tier can recover un-generated text).
            print(f"  [final] response hit max_tokens — salvaged {len(report.findings)} "
                  "finding(s); report may be incomplete. Consider raising max_tokens.")
        return report
    if verbose:
        print("  [final] JSON malformed"
              f"{' (truncated at max_tokens)' if truncated else ''} — local repair failed, "
              "trying cheap JSON-fix…")

    # Tier 2 — cents; only the broken report text is re-sent, not the transcript.
    report = _haiku_fix(client, text)
    if report is not None:
        if verbose:
            print("  [final] recovered via cheap JSON-fix (no re-scan).")
        return report

    # Tier 3 — expensive: re-run the whole final call. Ask first (unless unattended).
    err = ValueError("final report JSON could not be parsed or cheaply repaired")
    if on_expensive_retry is None or on_expensive_retry(err):
        if verbose:
            print("  [final] cheap tiers failed — re-running the full final call…")
        text, _ = big_call()
        report = _local_parse(text) or _haiku_fix(client, text)
        if report is not None:
            return report
        raise ValueError("final report still unparseable after full re-run")

    raise err
