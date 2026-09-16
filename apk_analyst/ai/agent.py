"""Step 3 — the agentic loop. The model drives the investigation.

Instead of pre-packing everything (Step 2), we hand Claude a small seed view
plus a toolbox (tools.py) and let it decide what to read/grep/strings next. It
loops until it's satisfied (or hits a safety cap), then we make one final
structured-output call to emit the AnalysisReport.

Design: manual loop (full control, no beta dependency, explicit iteration cap).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, List, Optional

import anthropic

from ..errors import ScanCancelled
from .analyst import MODEL, SYSTEM_PROMPT, load_client
from .caching import cache_system, cache_tools, mark_rolling_cache, usage_delta
from .citations import validate_report
from .final_report import ConfirmRetry, produce_final_report
from .models import AnalysisReport
from .tools import TOOL_SCHEMAS, Toolbox

MAX_ITERATIONS = 16   # safety cap so the loop always terminates

# Optional UI hook. Called once per iteration as
# on_progress(iteration, max_iterations, tool_infos, thought) where tool_infos is
# a list of {"name","input","display"} and thought is the model's short reasoning
# text for this turn (may be ""). A UI can show the display lines always and the
# input/thought only in a verbose mode.
ProgressCb = Optional[Callable[[int, int, List[dict], str], None]]
# Optional cancel hook: returns True when the user has asked to stop.
CancelCb = Optional[Callable[[], bool]]

AGENT_SYSTEM = SYSTEM_PROMPT + """

You are working AGENTICALLY. You have tools to explore the decompiled APK:
list_dir, read_file, grep, and strings_in_lib (for native .so libraries), plus
search_knowledge to ground findings in real security standards.

Investigate like a real analyst:
- Start from the manifest facts and file overview you're given.
- Follow leads: if you see a crypto call, read the surrounding code; if a key
  looks like a resource reference, read strings.xml; if the real logic is in a
  native .so, run strings_in_lib on it and chase URLs/keys/root-checks.
- Confirm findings with evidence you actually retrieved. Don't stop at the
  surface — pull the native library apart with strings before concluding.
- GROUND your findings: for each real issue, call search_knowledge with a short
  description of it to retrieve the matching OWASP guidance — a MASVS control, a
  MASWE weakness, and/or a MASTG test — then record their citation labels in the
  finding's `standards`. Prefer the most specific label retrieved — a control id
  like MASVS-CRYPTO-2 (or a weakness like MASWE-0007) over the bare category
  MASVS-CRYPTO. Only cite standards you actually retrieved — never invent an id
  (post-processing drops any citation not in the knowledge base).
- Be efficient: don't re-run the same tool with trivially different arguments.
  A couple of targeted strings_in_lib calls per library is enough — if the .so is
  stripped/obfuscated, record that and move on rather than repeating the search.
- When you have investigated thoroughly, stop calling tools and say you are done.
"""

FINAL_INSTRUCTION = (
    "You have finished investigating. Output your final structured security report.\n"
    "Report EVERY distinct issue you found as its own separate finding — do not collapse "
    "them into one. Include, where applicable: cryptography (hardcoded key/IV, weak modes), "
    "insecure transport (cleartext HTTP, network_security_config), insecure storage (local DB, "
    "backup exposure), permissions (over-broad grants), component/IPC exposure, and the native "
    "library (as its own finding flagged for deeper review, noting exactly what you observed). "
    "Include lower-severity and informational findings too. Be complete."
)


@dataclass
class AgentResult:
    report: AnalysisReport
    iterations: int
    tool_calls: list[str]        # names of tools called, in order


def _seed_context(summary: dict) -> str:
    m = summary["manifest"]
    natives = [{"path": n["path"], "abi": n["abi"], "urls": n["urls"]} for n in summary["natives"]]
    return (
        "You are analyzing a decompiled APK. Workspace layout: 'jadx/sources/' holds "
        "decompiled Java, 'apktool/' holds smali + decoded resources (res/values/strings.xml, "
        "res/xml/network_security_config.xml) and native libs under 'apktool/lib/<abi>/'.\n\n"
        f"## Package\n{m['package']}  (framework: {', '.join(summary['frameworks'])})\n\n"
        f"## Manifest facts\n{json.dumps(m, indent=2)}\n\n"
        f"## Native libraries\n{json.dumps(natives, indent=2)}\n\n"
        "Investigate using your tools, then produce the report."
    )


def analyze_agentic(summary: dict, client: anthropic.Anthropic | None = None,
                    max_iterations: int = MAX_ITERATIONS, verbose: bool = True,
                    on_expensive_retry: ConfirmRetry = None,
                    on_progress: "ProgressCb" = None,
                    should_cancel: "CancelCb" = None,
                    voyage_api_key: str | None = None) -> AgentResult:
    """`on_progress`, if given, is called once per iteration as
    on_progress(iteration, max_iterations, last_tool_names) so a UI can show
    live progress. It must not raise.

    `should_cancel`, if given, is polled at the start of each iteration; when it
    returns True the loop raises ScanCancelled so a user Stop takes effect within
    one iteration (before paying for the next model call)."""
    client = client or load_client()
    tools = Toolbox(summary["workspace"], voyage_api_key=voyage_api_key)

    messages: list[dict] = [{"role": "user", "content": _seed_context(summary)}]
    tool_calls: list[str] = []
    iterations = 0

    # Cache the two static prefixes once; roll a third breakpoint over the
    # transcript each turn (see ai/caching.py). Big cost win over the ~16-iter loop.
    system = cache_system(AGENT_SYSTEM)
    tools_cached = cache_tools(TOOL_SCHEMAS)
    cache_read = cache_write = 0

    while iterations < max_iterations:
        if should_cancel is not None and should_cancel():
            raise ScanCancelled()
        iterations += 1
        mark_rolling_cache(messages)
        resp = client.messages.create(
            model=MODEL, max_tokens=8000,
            system=system, tools=tools_cached, messages=messages,
        )
        r, w = usage_delta(resp.usage)
        cache_read += r
        cache_write += w
        messages.append({"role": "assistant", "content": resp.content})

        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        if not tool_uses:
            break  # model is done investigating

        results = []
        for tu in tool_uses:
            tool_calls.append(tu.name)
            if verbose:
                print(f"  [tool {iterations}] {tu.name}({json.dumps(tu.input)[:80]})")
            output = tools.run(tu.name, tu.input)
            results.append({"type": "tool_result", "tool_use_id": tu.id, "content": output})
        messages.append({"role": "user", "content": results})

        if on_progress is not None:
            try:
                # The model's short reasoning text for this turn (verbose UIs show it).
                thought = " ".join(
                    b.text.strip() for b in resp.content if b.type == "text"
                ).strip()[:240]
                # One entry per tool call: a readable display line plus the raw
                # input (verbose UIs can show the full input).
                infos = []
                for tu in tool_uses:
                    inp = tu.input or {}
                    arg = inp.get("path") or inp.get("pattern") or inp.get("query") \
                          or next(iter(inp.values()), "")
                    infos.append({"name": tu.name, "input": inp,
                                  "display": f"{tu.name}({str(arg)[:70]})"})
                on_progress(iterations, max_iterations, infos, thought)
            except Exception:
                pass  # a UI hook must never break the scan

    # Final structured-output pass over the whole investigation. The scan is done
    # by now; produce_final_report serialises it and recovers cheaply (local repair
    # -> cheap JSON-fix -> gated expensive re-run) if the JSON comes back malformed,
    # so a transient bad serialisation doesn't throw away a completed run.
    messages.append({"role": "user", "content": FINAL_INSTRUCTION})
    mark_rolling_cache(messages)   # the big final call reuses the cached transcript
    report = produce_final_report(
        client, model=MODEL, system=system, tools=tools_cached,
        messages=messages, max_tokens=16000,
        on_expensive_retry=on_expensive_retry, verbose=verbose,
    )
    if verbose and (cache_read or cache_write):
        print(f"  [cache] loop reused {cache_read} cached input token(s) "
              f"(wrote {cache_write}) across {iterations} iteration(s).")

    # Ground-truth the citations: drop any `standards` label that isn't a real
    # corpus ref (the model asserting a control it never retrieved). Cheap pass —
    # only runs if the KB is loaded; if not, we can't validate so we leave them.
    kb = tools._load_kb()
    if kb is not None:
        audit = validate_report(report, kb.valid_refs())
        if verbose and audit.n_dropped:
            print(f"  [citations] dropped {audit.n_dropped} unverifiable citation(s):")
            for title, ref in audit.dropped:
                print(f"      - {ref!r} on \"{title[:60]}\"")

    return AgentResult(report=report, iterations=iterations, tool_calls=tool_calls)
