"""The Step 2 Claude call: extracted facts -> structured AnalysisReport.

One request, structured output (Pydantic via messages.parse). No agentic loop
yet — that's Step 3. The system prompt encodes the course playbook so findings
follow *this* methodology, not generic OWASP boilerplate.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from .context import build_context
from .models import AnalysisReport

MODEL = "claude-opus-5"

SYSTEM_PROMPT = """You are a senior Android application security analyst.

You are given the extracted facts of a decompiled APK: manifest facts, framework
detection, native-library strings, and the app's first-party Java source. Analyze
it the way a human analyst following a disciplined static-analysis methodology would.

Work through this playbook and report only what the evidence supports:
1.  Manifest — exported components without permissions, debuggable, allowBackup,
    cleartext traffic / network-security-config, dangerous permissions, deep links.
2.  Hardcoded secrets — API keys, tokens, passwords, URLs, crypto keys/IVs in code,
    resources, or native strings.
3.  Cryptography — weak algos (MD5/SHA-1/DES/RC4/ECB), hardcoded/predictable keys & IVs,
    keys derived from device build values, custom crypto.
4.  Data storage — plaintext secrets in SharedPreferences/SQLite/files; backup exposure.
5.  Auth/authorization — client-side auth, local PIN/hash checks, patchable gates
    (isPremium/isProUnlocked/authenticate), IDOR via client-supplied IDs.
6.  Insecure communication — HTTP for sensitive data, trust-all TrustManager, broken
    pinning, tokens in URLs.
7.  Input/output validation — SQLi, command injection (Runtime.exec), path traversal,
    WebView loadData / JS bridge.
8.  Component/IPC exposure — exported components, implicit-intent broadcast leaks,
    AIDL/binder leaks, pending intents.
9.  Obfuscation / anti-analysis — root/Frida/debugger detection, anti-patching signature
    checks, obfuscated/encoded strings.
10. Native code — JNI entry points, suspicious strings/URLs, root checks in .so.
11. Supply chain — suspicious third-party SDKs, telemetry/exfil endpoints, dynamic
    dex/plugin loading without integrity checks.
12. Malware behaviors — accessibility/overlay abuse, SMS/2FA interception, C2, fraud.

Rules:
- Ground every finding in specific evidence you were given. Quote the snippet/fact.
- Do not invent code you cannot see. If key logic is only in a native .so you cannot
  read, say so and flag it for deeper native review rather than guessing its behavior.
- Prefer precision over volume. Set confidence honestly (firm/likely/tentative).
- Severity reflects real exploitability and impact, not theoretical worst case.
"""


def load_client() -> anthropic.Anthropic:
    """Load .env (ANTHROPIC_API_KEY) and return a client."""
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set. Add it to a .env file at the project root."
        )
    return anthropic.Anthropic()


def analyze_with_ai(summary: dict, client: anthropic.Anthropic | None = None) -> AnalysisReport:
    client = client or load_client()
    context = build_context(summary)

    response = client.messages.parse(
        model=MODEL,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": (
                "Here are the extracted facts of the APK. Produce a prioritized "
                "security analysis report.\n\n" + context
            ),
        }],
        output_format=AnalysisReport,
    )
    return response.parsed_output


def report_to_dict(report: AnalysisReport) -> dict:
    return json.loads(report.model_dump_json())
