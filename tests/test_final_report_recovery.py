"""Fault-injection test for the final-report recovery cascade.

We never wait for a real scan to hand us a malformed report — we *inject* one.
A scripted fake Anthropic client returns whatever text we want from
`messages.create`, keyed by model, so each tier of `produce_final_report`'s
cascade can be driven deterministically with ZERO real API calls / cost.

Cascade under test (see final_report.py):
  Tier 1  local repair   — free
  Tier 2  Haiku JSON-fix — cents (model=FIX_MODEL)
  Tier 3  full re-run     — expensive, gated by on_expensive_retry

Run:  python3 tests/test_final_report_recovery.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apk_analyst.ai import final_report as fr
from apk_analyst.ai.final_report import FIX_MODEL, produce_final_report
from apk_analyst.ai.models import (
    AnalysisReport,
    Confidence,
    Finding,
    OwaspMobile,
    Severity,
)

BIG_MODEL = "claude-opus-5"  # the expensive transcript call


def _valid_report_json() -> str:
    """A minimal but schema-valid AnalysisReport, serialised."""
    report = AnalysisReport(
        summary="Test app; one representative finding.",
        findings=[
            Finding(
                title="Hardcoded AES key",
                severity=Severity.critical,
                confidence=Confidence.firm,
                owasp_mobile=OwaspMobile.m10_crypto,
                cwe="CWE-798",
                location="Crypto.java",
                evidence='SecretKeySpec("k1k1k1k1k1k1k1k1".getBytes(), "AES")',
                exploit_path="Extract the static key from the APK; decrypt all traffic.",
                recommendation="Derive keys per-device; store in the Keystore.",
                standards=["MASVS-CRYPTO-1"],
            )
        ],
    )
    return report.model_dump_json()


# --- Scripted fake client -----------------------------------------------------

class _Block:
    type = "text"

    def __init__(self, text: str):
        self.text = text


class _Resp:
    def __init__(self, text: str, stop_reason: str = "end_turn"):
        self.content = [_Block(text)]
        self.stop_reason = stop_reason


class _Messages:
    def __init__(self, owner: "FakeClient"):
        self._owner = owner

    def create(self, **kwargs):
        model = kwargs["model"]
        self._owner.calls.append(model)
        script = self._owner.script.get(model)
        if not script:
            raise AssertionError(f"unexpected call to model {model!r}")
        # Each entry is a (text, stop_reason) tuple; consumed in order, last repeats.
        text, stop = script[0] if len(script) == 1 else script.pop(0)
        return _Resp(text, stop)


class FakeClient:
    """`script` maps model name -> list of (text, stop_reason) responses,
    consumed in order (a single-entry list repeats)."""

    def __init__(self, script: dict[str, list]):
        self.script = {m: list(v) for m, v in script.items()}
        self.calls: list[str] = []
        self.messages = _Messages(self)


def _run(script, **kw):
    client = FakeClient(script)
    report = produce_final_report(
        client, model=BIG_MODEL, system="sys", tools=[],
        messages=[{"role": "user", "content": "final"}], verbose=False, **kw,
    )
    return report, client


# --- Test scenarios -----------------------------------------------------------

def test_tier1_clean_pass():
    """Valid JSON on the first call — no repair needed, no extra calls."""
    report, client = _run({BIG_MODEL: [(_valid_report_json(), "end_turn")]})
    assert len(report.findings) == 1
    assert client.calls == [BIG_MODEL], client.calls
    assert FIX_MODEL not in client.calls


def test_tier1_local_repair_truncated():
    """Truncated (unbalanced) JSON that Tier-1 _balance can close locally —
    still no Haiku call."""
    good = _valid_report_json()
    truncated = good[: good.rindex("]")]  # drop the closing ']}' → unbalanced
    report, client = _run({BIG_MODEL: [(truncated, "max_tokens")]})
    assert len(report.findings) == 1
    assert client.calls == [BIG_MODEL], client.calls  # Haiku never invoked


def test_tier2_haiku_fix():
    """Locally unrepairable garbage from the big call, but Haiku returns valid
    JSON → recovered at Tier 2, no expensive re-run."""
    junk = "I could not produce JSON. Sorry."  # no braces → Tier-1 can't help
    script = {
        BIG_MODEL: [(junk, "end_turn")],
        FIX_MODEL: [(_valid_report_json(), "end_turn")],
    }
    report, client = _run(script)
    assert len(report.findings) == 1
    assert client.calls == [BIG_MODEL, FIX_MODEL], client.calls
    assert client.calls.count(BIG_MODEL) == 1  # transcript NOT re-sent


def test_tier3_unattended_autoretry():
    """Big call + Haiku both fail; on_expensive_retry=None (eval harness) →
    auto re-runs the big call once, which now succeeds."""
    junk = "still not json"
    script = {
        BIG_MODEL: [(junk, "end_turn"), (_valid_report_json(), "end_turn")],
        FIX_MODEL: [(junk, "end_turn")],
    }
    report, client = _run(script, on_expensive_retry=None)
    assert len(report.findings) == 1
    assert client.calls.count(BIG_MODEL) == 2, client.calls  # re-ran the big call
    assert client.calls.count(FIX_MODEL) >= 1


def test_tier3_gate_declined():
    """Cheap tiers fail and the confirm callback says NO → we raise instead of
    spending the big call again. The gate was actually consulted."""
    junk = "nope"
    script = {BIG_MODEL: [(junk, "end_turn")], FIX_MODEL: [(junk, "end_turn")]}
    seen = {"asked": False}

    def deny(err):
        seen["asked"] = True
        return False

    raised = False
    try:
        _run(script, on_expensive_retry=deny)
    except ValueError:
        raised = True
    assert raised, "expected ValueError when the retry gate declines"
    assert seen["asked"], "on_expensive_retry was never consulted"


def test_tier3_gate_approved():
    """Same as declined, but the callback says YES → the big call re-runs and
    recovers."""
    junk = "nope"
    script = {
        BIG_MODEL: [(junk, "end_turn"), (_valid_report_json(), "end_turn")],
        FIX_MODEL: [(junk, "end_turn")],
    }
    seen = {"asked": False}

    def allow(err):
        seen["asked"] = True
        return True

    report, client = _run(script, on_expensive_retry=allow)
    assert seen["asked"]
    assert len(report.findings) == 1
    assert client.calls.count(BIG_MODEL) == 2, client.calls


def main():
    tests = [
        test_tier1_clean_pass,
        test_tier1_local_repair_truncated,
        test_tier2_haiku_fix,
        test_tier3_unattended_autoretry,
        test_tier3_gate_declined,
        test_tier3_gate_approved,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as e:
            failures += 1
            print(f"  FAIL  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
