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

import shutil
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import anthropic
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from apk_analyst.ai.analyst import analyze_with_ai, report_to_dict
from apk_analyst.pipeline import analyze

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
JOBS_DIR = HERE / "_jobs"          # per-scan workspaces (git-ignored)
JOBS_DIR.mkdir(exist_ok=True)

MAX_APK_BYTES = 200 * 1024 * 1024  # 200 MB upload cap

app = FastAPI(title="APKAnalyst")


# --- job state ----------------------------------------------------------------

@dataclass
class Job:
    id: str
    mode: str                       # "agent" | "ai"
    stage: str = "queued"           # queued|decompiling|analyzing|finalizing|done|error
    iteration: int = 0
    max_iterations: int = 0
    tool_calls: int = 0
    error: Optional[str] = None
    report: Optional[dict] = None   # report_to_dict payload once done
    app_name: Optional[str] = None

    def public(self) -> dict:
        """Status view (never includes the report body or any key)."""
        return {
            "id": self.id, "mode": self.mode, "stage": self.stage,
            "iteration": self.iteration, "max_iterations": self.max_iterations,
            "tool_calls": self.tool_calls, "error": self.error,
            "app_name": self.app_name, "done": self.stage in ("done", "error"),
        }


_JOBS: dict[str, Job] = {}
_LOCK = threading.Lock()


# --- the background scan ------------------------------------------------------

def _run_scan(job: Job, apk_path: Path, api_key: Optional[str]) -> None:
    """Executed in a worker thread. `api_key` stays local to this function."""
    try:
        client = anthropic.Anthropic(api_key=api_key) if api_key else None

        job.stage = "decompiling"
        summary = analyze(str(apk_path), workspace=str(apk_path.parent / "workspace"))
        job.app_name = summary["apk"]["name"]

        job.stage = "analyzing"
        if job.mode == "ai":
            report = analyze_with_ai(summary, client=client)
            payload = report_to_dict(report)
            payload["_meta"] = {"mode": "single-call"}
        else:
            from apk_analyst.ai.agent import analyze_agentic

            def _progress(i: int, mx: int, tools: list[str]) -> None:
                job.iteration, job.max_iterations = i, mx
                job.tool_calls += len(tools)

            # Unattended: on_expensive_retry left as default (auto-retries once).
            result = analyze_agentic(summary, client=client, verbose=False,
                                     on_progress=_progress)
            job.stage = "finalizing"
            payload = report_to_dict(result.report)
            payload["_meta"] = {"mode": "agentic", "iterations": result.iterations,
                                "tool_calls": result.tool_calls}

        job.report = payload
        job.stage = "done"
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

@app.post("/api/scan")
async def scan(apk: UploadFile = File(...), mode: str = Form("agent"),
               api_key: str = Form("")) -> JSONResponse:
    if mode not in ("agent", "ai"):
        raise HTTPException(400, "mode must be 'agent' or 'ai'")
    name = (apk.filename or "").strip()
    if not name.lower().endswith(".apk"):
        raise HTTPException(400, "please upload a .apk file")

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

    job = Job(id=job_id, mode=mode)
    with _LOCK:
        _JOBS[job_id] = job
    key = api_key.strip() or None
    threading.Thread(target=_run_scan, args=(job, dest, key), daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/status/{job_id}")
async def status(job_id: str) -> JSONResponse:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return JSONResponse(job.public())


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
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
