# Case Study — Agentic vs. Single-Call on a Blind Target (lWS)

> **The question:** does the agentic loop actually earn its extra cost, or is
> single-call "good enough"? This is a controlled test on a real app the model
> had never analyzed — and the answer is measured, not asserted.

---

## Why this test is honest

Most "look what my AI found" demos are contaminated: the app is famous, so you
can't tell whether the model **read the vulnerability** or **recalled it from
training**. To avoid that, the target was picked to be:

- **Real** — genuine third-party code with real complexity, not a planted-bug toy.
- **Open source (GPL-3.0)** — so the findings can be published legally and the
  ground truth can be verified against upstream source.
- **Obscure** — [lWS](https://f-droid.org/packages/net.basov.lws.fdroid/), a
  ~54 KB LAN web server on F-Droid, with no CVE writeups for the model to memorize.

**Bias controls:** APKAnalyst reads only the decompiled bytes of *this* APK plus
its local knowledge base (OWASP MASVS + course methodology). It has **no web
access** and was never shown lWS's source, README, or issue tracker. Ground truth
was read from upstream **by a human, after the scans** — never fed to the agent.
Each scan is **stateless**, so running the cheap scan first could not bias the
agentic one.

**Target:** `net.basov.lws.fdroid` v07.00.00 · 54 KB · engine `claude-opus-5`.

---

## Ground truth

lWS is an unauthenticated HTTP file server for a LAN. Its documented, design-level
exposures:

| # | Issue | OWASP |
|---|-------|-------|
| 1 | **Cleartext HTTP** — all content served unencrypted over the LAN | M5 |
| 2 | **No authentication** — anyone on the network who knows the URL can read files | M3 |
| 3 | **Unrestricted file exposure** — whole document root readable; user can point it at any path (e.g. `/sdcard`) | M9 |

*Not present:* no WebView, no login, no hardcoded secrets, no native code.

---

## Recall — both modes caught all three

| Expected issue | Single-call | Agentic |
|----------------|-------------|---------|
| Cleartext HTTP | ✓ *(inferred from manifest)* | ✓ *(confirmed in `strings.xml`)* |
| No authentication | ◐ *(assumed, unverified)* | ✓ *(grep confirmed no auth header)* |
| Unrestricted file exposure | ◐ *(handler not verified)* | ✓ *(+ traversal bypass in code)* |

**Recall 3/3 for both** — but single-call *guessed* from manifest permissions,
while agentic *proved* each finding from the decompiled bytecode.

---

## Where they diverge

| | Single-call | Agentic |
|--|-------------|---------|
| Findings | **6** (1H / 3M / 1L / 1I) | **11** (2H / 1M / 4L / 4I) |
| Basis | Manifest only | Java + smali, 16 iterations, 21 tool calls |
| Code-level bugs | 0 (all tentative) | **3 real** (below) |
| Citations | none | MASVS controls + course notes per finding |
| False positives | **1** (see below) | 0 (caught & corrected it) |

### Three bugs only the agentic scan found

These live in the request-handling **code** — invisible to a manifest-only pass:

1. **Path-traversal blacklist bypass** *(CWE-22, High)* — the `contains("..")`
   check flips the status to 403, but the directory-listing branch returns 200
   anyway; the 403 is never consulted. Arbitrary directories outside the document
   root get listed.
   ```
   b.smali: const-string v9, ".." → contains() → sets 0x193 (403)
   …but :cond_5 emits R.string.rc200 and returns before status is checked
   ```
2. **Stored XSS in the directory listing** *(CWE-79, Medium)* — filenames are
   inserted raw into the listing HTML; a file named `<img src=x onerror=…>.txt`
   executes script in the server's origin and can exfiltrate other served files.
3. **Slowloris DoS** *(CWE-400, Low)* — unbounded thread-per-connection with no
   `setSoTimeout`; half-open connections block in `readLine()` forever.

### The false positive — and why it matters

Single-call flagged an **"exported PreferencesActivity (no permission guard)"** as
MEDIUM, inferred without reading the manifest. The agentic scan **read the decoded
manifest** and found the component is explicitly `android:exported="false"` — not
reachable by other apps. It retracted the claim and logged the discrepancy as an
INFO note.

> Verification against the actual bytes doesn't just find **more** — it also
> **removes** what a shallower pass gets wrong.

---

## Takeaway

| Metric | Result |
|--------|--------|
| Ground-truth recall (both modes) | **3 / 3** |
| Net findings, agentic vs. single-call | **+5** |
| False positives retracted by agentic | **1** |
| Web access used | **0** — fully offline |

On a genuinely blind target, the agentic loop backed every finding with quoted
evidence, uncovered three real code-level bugs beyond the manifest, and retracted
a false positive — with no sign of memorized bias. That is the case for spending
the extra tokens.
