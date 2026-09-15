"""Web front-end for APKAnalyst.

Wraps the existing analysis engine (apk_analyst.pipeline.analyze +
apk_analyst.ai.agent / analyst) behind a small FastAPI service:

  POST /api/scan        multipart: apk file + mode + optional api_key
                        -> starts a background scan, returns {job_id}
  GET  /api/status/{id} -> {stage, iteration, ...}  (poll this)
  GET  /api/report/{id} -> the finished report JSON
  GET  /                -> the drag-and-drop UI

Design notes
------------
- Scans are long (minutes) and CPU/network heavy, so each runs in a background
  thread and the UI polls status. Job state lives in memory (fine for a single
  local process; a public deployment would use a real queue + store).
- **Bring-your-own-key:** the caller may supply an Anthropic API key with the
  upload; it is used only to build that scan's client and is never written to
  the job record, logs, or disk. If omitted, the server falls back to its own
  .env key (handy locally).
- Uploaded APKs are untrusted input fed to decompilers. That is fine locally;
  before exposing this publicly, run scans in a sandbox/container and add
  auth + rate limiting (see webapp/README.md).
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import anthropic
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from dotenv import load_dotenv

from apk_analyst.ai.analyst import analyze_with_ai, report_to_dict
from apk_analyst.errors import ScanCancelled
from apk_analyst.pipeline import analyze

HERE = Path(__file__).resolve().parent
load_dotenv(HERE.parent / ".env")   # read keys/token from .env at startup
STATIC = HERE / "static"
JOBS_DIR = HERE / "_jobs"          # per-scan workspaces (git-ignored)
JOBS_DIR.mkdir(exist_ok=True)

MAX_APK_BYTES = 200 * 1024 * 1024  # 200 MB upload cap

# --- simple first-party usage metrics (no third-party trackers) ---------------
METRICS_FILE = HERE / "_metrics.json"   # git-ignored; survives restarts
_METRICS_LOCK = threading.Lock()


def _bump_metric(key: str) -> None:
    """Increment one counter in the metrics file (visits / scans by mode)."""
    with _METRICS_LOCK:
        try:
            data = json.loads(METRICS_FILE.read_text()) if METRICS_FILE.exists() else {}
        except Exception:
            data = {}
        data[key] = int(data.get(key, 0)) + 1
        try:
            METRICS_FILE.write_text(json.dumps(data))
        except Exception:
            pass

# docs_url disabled so /docs serves our user-facing documentation page instead of
# FastAPI's built-in Swagger UI (the interactive API schema is a dev-only convenience).
app = FastAPI(title="APKAnalyst", docs_url=None, redoc_url=None)


# --- job state ----------------------------------------------------------------

@dataclass
class Job:
    id: str
    mode: str                       # "agent" | "ai"
    stage: str = "queued"           # queued|decompiling|analyzing|finalizing|done|error|cancelled
    iteration: int = 0
    max_iterations: int = 0
    tool_calls: int = 0
    error: Optional[str] = None
    report: Optional[dict] = None   # report_to_dict payload once done
    app_name: Optional[str] = None
    cancel: bool = False            # set by /api/cancel; polled by the scan
    verbose: bool = False           # log agent reasoning + full tool inputs
    log: list[str] = field(default_factory=list)  # streamed activity lines
    _t0: float = field(default_factory=time.monotonic)

    _MAX_LOG = 250  # keep memory bounded on long agentic runs

    def add_log(self, line: str) -> None:
        """Append one timestamped activity line (thread-safe, capped)."""
        stamp = f"{time.monotonic() - self._t0:6.1f}s"
        with _LOCK:
            self.log.append(f"{stamp}  {line}")
            if len(self.log) > self._MAX_LOG:
                del self.log[: len(self.log) - self._MAX_LOG]

    def public(self) -> dict:
        """Status view (never includes the report body or any key)."""
        return {
            "id": self.id, "mode": self.mode, "stage": self.stage,
            "iteration": self.iteration, "max_iterations": self.max_iterations,
            "tool_calls": self.tool_calls, "error": self.error,
            "app_name": self.app_name,
            "done": self.stage in ("done", "error", "cancelled"),
            "log": list(self.log),
        }


_JOBS: dict[str, Job] = {}
_LOCK = threading.Lock()


# --- the background scan ------------------------------------------------------

def _run_scan(job: Job, apk_path: Path, api_key: Optional[str],
              voyage_key: Optional[str] = None) -> None:
    """Executed in a worker thread. `api_key`/`voyage_key` stay local to this
    function — never written to the job record, logs, or disk."""
    try:
        client = anthropic.Anthropic(api_key=api_key) if api_key else None

        job.stage = "decompiling"
        job.add_log(f"Unpacking {apk_path.name}…")
        _cancelled = lambda: job.cancel
        summary = analyze(str(apk_path), workspace=str(apk_path.parent / "workspace"),
                          on_step=job.add_log, should_cancel=_cancelled)
        job.app_name = summary["apk"]["name"]

        job.stage = "analyzing"
        if job.mode == "ai":
            job.add_log("Single-call mode: sending the extracted facts to the model "
                        "for one structured pass…")
            job.add_log("Waiting for the model's analysis (no tool exploration in this "
                        "mode — this can take ~15-30s)…")
            report = analyze_with_ai(summary, client=client)
            job.add_log("Model responded — parsing structured findings…")
            payload = report_to_dict(report)
            payload["_meta"] = {"mode": "single-call"}
        else:
            from apk_analyst.ai.agent import analyze_agentic

            job.add_log("Agent starting investigation — planning first moves "
                        "(each iteration streams below as it runs)…")

            def _progress(i: int, mx: int, infos: list[dict], thought: str = "") -> None:
                job.iteration, job.max_iterations = i, mx
                job.tool_calls += len(infos)
                if job.verbose and thought:
                    job.add_log(f"  thinking: {thought}")
                for t in infos:
                    job.add_log(f"iter {i}/{mx} · {t['display']}")
                    if job.verbose:
                        job.add_log(f"    input: {json.dumps(t['input'])[:300]}")

            # Unattended: on_expensive_retry left as default (auto-retries once).
            result = analyze_agentic(summary, client=client, verbose=False,
                                     on_progress=_progress, should_cancel=_cancelled,
                                     voyage_api_key=voyage_key)
            job.stage = "finalizing"
            job.add_log(f"Investigation done ({result.iterations} iterations, "
                        f"{len(result.tool_calls)} tool calls) — writing the report…")
            payload = report_to_dict(result.report)
            payload["_meta"] = {"mode": "agentic", "iterations": result.iterations,
                                "tool_calls": result.tool_calls}

        job.add_log(f"Report ready: {len(payload.get('findings', []))} finding(s).")
        job.report = payload
        job.stage = "done"
    except ScanCancelled:
        job.add_log("Scan stopped by user.")
        job.stage = "cancelled"
    except anthropic.AuthenticationError:
        job.error = "Anthropic rejected the API key. Check the key and try again."
        job.stage = "error"
    except anthropic.APIStatusError as e:  # rate limit, quota, etc.
        job.error = f"Anthropic API error: {getattr(e, 'message', str(e))}"
        job.stage = "error"
    except Exception as e:
        job.error = f"{type(e).__name__}: {e}"
        job.stage = "error"
    finally:
        # Drop the bulky decompiled trees; keep nothing sensitive on disk.
        shutil.rmtree(apk_path.parent, ignore_errors=True)


# --- endpoints ----------------------------------------------------------------

def _grounding_warning(voyage_key: Optional[str] = None) -> Optional[str]:
    """If agentic RAG grounding can't actually run, explain why (else None).

    Agentic scans call `search_knowledge`, which needs both a built index and a
    Voyage key to embed the query. When either is missing the tool quietly no-ops
    and the report is produced *without* real retrieval — so we warn before the
    (paid) model calls start, letting the caller decide whether to continue. A
    caller-supplied Voyage key counts, so the warning clears once one is given."""
    try:
        from apk_analyst.knowledge.store import KnowledgeBase
        has_index = KnowledgeBase.exists()
    except Exception:
        has_index = False
    has_voyage = bool(voyage_key) or bool(os.getenv("VOYAGE_API_KEY"))
    if not has_index:
        return ("No knowledge-base index found, so findings won't be grounded in "
                "OWASP MASVS / methodology (build it once with `--build-kb`).")
    if not has_voyage:
        return ("No VOYAGE_API_KEY set, so search_knowledge can't embed queries — "
                "the scan runs but findings won't be grounded in the knowledge base.")
    return None


@app.post("/api/scan")
async def scan(apk: UploadFile = File(...), mode: str = Form("agent"),
               api_key: str = Form(""), voyage_key: str = Form(""),
               verbose: str = Form(""), ack: str = Form("")) -> JSONResponse:
    if mode not in ("agent", "ai"):
        raise HTTPException(400, "mode must be 'agent' or 'ai'")
    name = (apk.filename or "").strip()
    if not name.lower().endswith(".apk"):
        raise HTTPException(400, "please upload a .apk file")

    voyage = voyage_key.strip() or None

    # Pre-charge grounding check: warn (once) before any paid model call so the
    # caller can decide to continue ungrounded or fix the KB first.
    acked = ack.lower() in ("1", "true", "on", "yes")
    if mode == "agent" and not acked:
        warn = _grounding_warning(voyage)
        if warn:
            return JSONResponse(status_code=409,
                                content={"needs_ack": True, "warning": warn})

    job_id = uuid.uuid4().hex[:12]
    work = JOBS_DIR / job_id
    work.mkdir(parents=True, exist_ok=True)
    dest = work / Path(name).name

    size = 0
    with dest.open("wb") as f:
        while chunk := await apk.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_APK_BYTES:
                f.close()
                shutil.rmtree(work, ignore_errors=True)
                raise HTTPException(413, "APK exceeds the 200 MB upload limit")
            f.write(chunk)

    job = Job(id=job_id, mode=mode, verbose=verbose.lower() in ("1", "true", "on", "yes"))
    with _LOCK:
        _JOBS[job_id] = job
    key = api_key.strip() or None
    _bump_metric(f"scan_{mode}")   # scan_ai / scan_agent
    threading.Thread(target=_run_scan, args=(job, dest, key, voyage),
                     daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/status/{job_id}")
async def status(job_id: str) -> JSONResponse:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return JSONResponse(job.public())


@app.post("/api/cancel/{job_id}")
async def cancel(job_id: str) -> JSONResponse:
    """Request cancellation. The worker stops at its next checkpoint (between
    decompile stages / agent iterations), so 'cancelling' may lag a few seconds."""
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    if job.stage not in ("done", "error", "cancelled"):
        job.cancel = True
        job.add_log("Stop requested — finishing the current step…")
    return JSONResponse({"ok": True, "stage": job.stage})


@app.get("/api/report/{job_id}")
async def report(job_id: str) -> JSONResponse:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    if job.stage != "done" or job.report is None:
        raise HTTPException(409, "report not ready")
    return JSONResponse(job.report)


@app.get("/")
async def index() -> FileResponse:
    _bump_metric("visits")
    return FileResponse(STATIC / "index.html")


@app.get("/metrics")
async def metrics(token: str = "") -> JSONResponse:
    """First-party usage counters (visits + scans by mode). Gated by a secret:
    set METRICS_TOKEN in the environment and pass it as ?token=… . If no token
    is configured, the endpoint is hidden (404)."""
    import hmac
    configured = os.getenv("METRICS_TOKEN", "")
    supplied = token or ""
    if not configured or not hmac.compare_digest(supplied, configured):
        raise HTTPException(404, "not found")
    with _METRICS_LOCK:
        try:
            data = json.loads(METRICS_FILE.read_text()) if METRICS_FILE.exists() else {}
        except Exception:
            data = {}
    return JSONResponse({
        "visits": int(data.get("visits", 0)),
        "scans_single_call": int(data.get("scan_ai", 0)),
        "scans_agentic": int(data.get("scan_agent", 0)),
    })


@app.get("/docs")
async def docs() -> FileResponse:
    """User-facing documentation: how it works, why it needs API keys, and how
    keys/data are handled."""
    return FileResponse(STATIC / "docs.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
