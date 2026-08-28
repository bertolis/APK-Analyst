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

import anthropic

from .analyst import MODEL, SYSTEM_PROMPT, load_client
from .models import AnalysisReport
from .tools import TOOL_SCHEMAS, Toolbox

MAX_ITERATIONS = 16   # safety cap so the loop always terminates

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
  description of it to retrieve the matching OWASP MASVS control and course
  notes, then record their citation labels in the finding's `standards`. Only
  cite standards you actually retrieved — never invent a control id.
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
                    max_iterations: int = MAX_ITERATIONS, verbose: bool = True) -> AgentResult:
    client = client or load_client()
    tools = Toolbox(summary["workspace"])

    messages: list[dict] = [{"role": "user", "content": _seed_context(summary)}]
    tool_calls: list[str] = []
    iterations = 0

    while iterations < max_iterations:
        iterations += 1
        resp = client.messages.create(
            model=MODEL, max_tokens=8000,
            system=AGENT_SYSTEM, tools=TOOL_SCHEMAS, messages=messages,
        )
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

    # Final structured-output pass over the whole investigation.
    messages.append({"role": "user", "content": FINAL_INSTRUCTION})
    final = client.messages.parse(
        model=MODEL, max_tokens=16000,
        system=AGENT_SYSTEM, tools=TOOL_SCHEMAS, messages=messages,
        output_format=AnalysisReport,
    )
    return AgentResult(report=final.parsed_output, iterations=iterations, tool_calls=tool_calls)
