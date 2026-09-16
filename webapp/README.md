# APKAnalyst — Web UI

A drag-and-drop front-end over the analysis engine: upload an APK, pick a scan
mode, watch live progress, read the report in the browser.

## Run it locally

From the repo root (`apk-analyst/`), with the dependencies installed
(`pip install -r requirements.txt`):

```bash
python3 -m uvicorn webapp.server:app --reload --port 8077
```

Then open <http://127.0.0.1:8077>.

- **Scan mode** — *Full agentic* (the tool-driven agent + RAG grounding, best
  findings, a few minutes) or *Single-call* (one structured pass, faster and
  cheaper, fewer findings).
- **API key** — an Anthropic key is **required** (bring-your-own-key); there is
  no server-key fallback. The key is used only to build that scan's client — it
  is never stored, logged, or written to disk.
- **Grounding key (Voyage)** — optional web field (bring-your-own); there is no
  server-key fallback. Used by `search_knowledge` in agentic mode to embed the
  query for RAG grounding. If no key is provided or the index isn't built, an
  agentic scan pops a warning *before* any paid model call: continue ungrounded,
  or cancel. Note: a card-less free Voyage account is throttled to 3 RPM / 10K
  TPM; add a payment method to remove it.

A user-facing documentation page is served at `/docs` (how it works, why it needs
keys, how keys/data are handled, and the Voyage free-vs-paid throttle).

> **Restart after editing `.env`.** Keys and directory settings are read once at
> startup, so a running server won't see changes to `.env` — restart it (Ctrl+C
> and relaunch) after adding or changing a key.

The engine needs `jadx`, `apktool`, and `strings` on the server's PATH, and the
RAG index built once (`python3 run.py --build-kb`) for grounding/citations. The
playbook half of that index comes from your own notes — see the repo root
[`README.md`](../README.md) and [`playbook/README.md`](../playbook/README.md)
for how to add them (a MASVS-only index works too if you skip them).

## How it fits together

```
browser ──POST /api/scan (apk + mode + key)──►  FastAPI (server.py)
   ▲                                              │ background thread:
   │  poll /api/status/{id}                        │   analyze()  → decompile
   │  GET  /api/report/{id}                         │   analyze_agentic() / analyze_with_ai()
   └───────────── report JSON ◄────────────────────┘   (progress pushed to job state)
```

`server.py` is a thin wrapper — all analysis is the existing
`apk_analyst` package. Scans run in a background thread; job state is in memory.

## Scope

This is a local, single-user tool — no auth, rate-limiting, or queue, and job
state is in memory (it doesn't survive a restart). A few input guards stay on
so a malicious APK can't wreck the machine: path-safety in the agent tools, a
decompression cap, a 200 MB upload cap (`MAX_APK_BYTES`), a decompiled-size cap
(`APK_ANALYST_MAX_WORKSPACE_MB`), and per-scan workspace cleanup. Exposing it to
the public internet would need real hardening (sandboxing untrusted uploads,
auth, rate limits, a persistent queue/store) — out of scope here.
