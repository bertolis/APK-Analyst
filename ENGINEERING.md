# Engineering Notes — features, optimizations & the reasoning behind them

A deeper look at *what* was built into APKAnalyst beyond "call an LLM," *why*,
and *how* each piece works. Written as an engineering talk-track: each section is
a self-contained thing you can explain end-to-end.

Quick map of where each lives in the code:

| Feature | Files |
|---|---|
| Agentic tool-use loop | `apk_analyst/ai/agent.py`, `ai/tools.py` |
| Structured output (schema-constrained) | `ai/models.py`, `ai/analyst.py` |
| RAG grounding (rulebook + playbook) | `apk_analyst/knowledge/`, `ai/tools.py` (`search_knowledge`) |
| Prompt caching | `ai/caching.py`, wired in `ai/agent.py` |
| Broken-JSON recovery cascade | `ai/final_report.py` |
| Citation validation | `ai/citations.py` |
| Evals + adjudication | `eval/` |

---

## 1. Agentic tool-use loop (the centerpiece)

**What:** Instead of stuffing the whole decompiled APK into one prompt, the model
is given a small seed view plus a toolbox and runs a **plan → call tool → observe
→ iterate** loop (manual, not a framework), capped at ~16 iterations, then a final
pass serializes its findings.

**Why:** A decompiled APK is far too large and messy for one prompt, and most of
it is irrelevant (framework code, generated `R.java`). An agent decides *what
matters* and only pulls that in — the same way a human analyst wouldn't read
every file.

**How:** Tools are `list_dir`, `read_file`, `grep`, `strings_in_lib`, and
`search_knowledge`. The toolbox is **sandboxed**: path-safety prevents escaping
the workspace, and the tool is blocked from reading our own generated reports
(so it can't "cheat" off prior output).

**Why it matters:** The agentic-ness is real and measurable — on the same app the
agent produced **15 findings vs. 10** from a single-call baseline, and the extra
five came from *verifying* things the one-shot could only guess (reading
`network_security_config.xml` to confirm cleartext, probing a native `.so` with
strings, grepping for anti-tamper). Agency = verification, not just more text.

---

## 2. Structured output (schema-constrained)

**What:** Every finding is forced into a Pydantic schema — severity, confidence,
OWASP Mobile category, CWE, location, evidence, exploit path, recommendation,
cited standards — via the model's JSON-schema output mode.

**Why:** Raw prose from an LLM isn't machine-usable and drifts in format. A strict
schema makes the output sortable, scoreable (the evals depend on it), and
trustworthy to a downstream consumer — the "raw input → structured output" shape
of a real production tool.

---

## 3. RAG grounding — rulebook + playbook split

**What:** A local vector knowledge base the agent queries with `search_knowledge`.
It has **two deliberately different roles**:

- **Rulebook = OWASP MASVS** (control-level, e.g. `MASVS-CRYPTO-2`) — cites *what
  standard* a finding violates.
- **Playbook = curated analyst methodology** (static/malware analysis course
  notes) — guides *how to find and confirm* an issue.

**Why:** Two different jobs. The model already "knows" security generically;
grounding stops it citing standards from memory (a subtle hallucination) and
makes it follow *a specific documented methodology* rather than emitting generic
OWASP advice.

**How:** Sources are chunked, embedded once with Voyage AI, stored in a small
numpy vector store; retrieval is cosine similarity by *meaning*. Each MASVS
control is its own chunk whose id **is** the citation label, so retrieval and
citation share one vocabulary.

**Why it matters:** The rulebook/playbook split is the interesting design call —
most RAG demos have one undifferentiated blob; here the two corpora answer two
different questions ("is it a violation?" vs. "how do I prove it?").

---

## 4. Prompt caching (cost optimization — with an honest number)

**What:** The two static prefixes (system playbook + tool schemas) are marked
cacheable, and a single **rolling cache breakpoint** moves down the growing
transcript so each iteration re-reads cached content instead of re-paying for it.

**Why:** The agent loop re-sends a growing transcript every iteration (~16×), so
the same prefix would be billed over and over without caching.

**Honest result:** modeled at ~10% of full cost; **measured ~35%** on a live run
(≈€1.10, not the projected ≈€0.35). The static prefixes cache well, but the
*growing transcript* (native strings + tool outputs) dominates and one rolling
breakpoint doesn't fully cover it.

**Why it matters:** This is a good story precisely *because* the estimate was
wrong and I measured it. The fix levers are known: more breakpoints on the
transcript, trimming what's re-sent per iteration, or capping iterations —
a real cost/latency-vs-coverage tradeoff, not a solved checkbox.

---

## 5. Broken-JSON recovery cascade

**What:** The final step serializes the agent's finished investigation into JSON.
Occasionally that JSON comes back truncated/malformed (usually a `max_tokens`
cut-off) — which would throw away an expensive, *already-completed* scan. Recovery
is **cheapest-first**:

- **Tier 1 — local repair (free):** strip ``` fences, slice out the JSON object,
  balance truncated brackets, re-validate.
- **Tier 2 — Haiku JSON-fix (cents):** send **only the broken report text** + the
  schema to a cheap model. The expensive investigation transcript is *never*
  re-sent.
- **Tier 3 — full re-run (expensive):** redo the whole final call. **Gated by a
  confirm callback** — the CLI asks the user; the unattended eval harness
  auto-retries once.

**Why:** The insight is that if only the final JSON is malformed, *the scan already
succeeded* — so don't re-pay for the expensive part. Tiers 1–2 fix the common
truncation case for free/cents; the user is only ever asked before the one tier
that costs real money.

**How it's verified:** `tests/test_final_report_recovery.py` injects malformed
output via a scripted fake client (zero API cost) and drives all three tiers
deterministically — 6/6 pass, including the gate being consulted before any
expensive retry.

**Why it matters:** Cost-aware failure handling. Naive code re-runs the whole
call on any parse error; this classifies the failure and spends the minimum.

---

## 6. Citation validation (catching a subtle hallucination)

**What:** After the report is produced, every `standards` label is checked against
the *actual* set of refs in the knowledge corpus. Any label that isn't a real,
resolvable ref is **dropped**.

**Why:** The model can assert a plausible-looking control it never actually
retrieved (`MASVS-CRYPTO-99`) — a citation that *looks* grounded but isn't. This
guarantees every surviving citation resolves to a real corpus entry.

**Honest scope:** this is the *cheap* version (validate against the known ref
set). The full version — tracking exactly which refs each finding retrieved — is
deliberately deferred; the cheap check already kills fabricated citations.

---

## 7. Evals + human adjudication (the trust story)

**What:** A 6-app eval set (security-course APKs), each with one known
headline vuln the agent never sees. A harness runs the agent **blind**, and an
**LLM-as-judge** (cheap model) scores each graded issue caught/missed and lists
every *extra* finding for human review.

**Results:**
- **Recall: 6/6 (100%)** — every known vuln discovered blind.
- **False-positive rate: 1/48 (~2.1%)** — from human adjudication of the 74
  extra findings (see `eval/UNLABELED_ADJUDICATION.md`): ~47 genuine secondary
  issues, 26 honest negative/inventory notes, 1 false positive.
- **0 false positives on the graded vulns.**

**Why blind (didn't train on the challenges' own course):** ingesting the source
course would be teaching-to-the-test; the static *discovery* patterns are already
in the playbook, so a blind score is honest.

**Why it matters:** The number I lead with is the *false-positive rate from human
adjudication*, not just recall — because for a security tool, crying wolf is the
failure mode that destroys trust. Having a measured FP rate **and** a concrete
plan to lower it (tighten prompts / add KB rules for the borderline classes,
re-run evals, compare) is the story.

---

## 8. Deliberately stateless (a design decision, not a gap)

**What:** No per-run memory or "learning" layer. Each APK gets a self-contained,
unbiased verdict.

**Why:** A tool that learned from its *own* unverified guesses would compound its
mistakes. "Learning" belongs in the **curated, reviewed** RAG KB + the evals loop,
not in runtime memory. The agentic-ness comes from the tool-driven loop, not from
persistence. Revisit a learned-patterns layer only *after* evals give a measured
FP rate to improve against.

---

*These notes track the engineering decisions worth explaining out loud. The
[README](README.md) is the quick tour; this is the deep dive.*
