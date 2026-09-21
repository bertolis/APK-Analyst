"""Step 1 orchestrator: APK -> extracted facts on disk + one JSON summary.

No AI here. This produces the clean, structured input the LLM agent will
consume in Step 2. Output layout:

    workspace/<apk-stem>/
        jadx/            decompiled Java
        apktool/         smali + decoded resources/manifest
        extraction.json  machine-readable summary (this module's return value)
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Optional

from androguard import util as _ag_util

from .errors import ScanCancelled
from .manifest import extract_manifest
from .decompile import run_jadx, run_apktool
from .natives import inventory_natives
from .framework import detect_framework

_ag_util.set_log("ERROR")  # silence androguard's verbose loguru output

# Per-scan disk cap: abort if decompiled output balloons past this, so one big
# or malicious APK can't fill the shared scratch space and starve other workers.
MAX_WORKSPACE_MB = int(os.getenv("APK_ANALYST_MAX_WORKSPACE_MB", "2048"))
_MAX_WORKSPACE_BYTES = MAX_WORKSPACE_MB * 1024 * 1024


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def _guard_workspace_size(work: Path) -> None:
    if _dir_size(work) > _MAX_WORKSPACE_BYTES:
        raise RuntimeError(
            f"decompiled output exceeded the {MAX_WORKSPACE_MB} MB limit — "
            f"scan aborted (possible decompression bomb or oversized app)."
        )


def analyze(apk_path: str, workspace: str = "workspace",
            on_step: Optional[Callable[[str], None]] = None,
            should_cancel: Optional[Callable[[], bool]] = None) -> dict:
    """`on_step`, if given, is called with a short human-readable line before
    each extraction sub-stage so a UI can stream progress (unpacking, decompiling
    …). It must never raise into the pipeline.

    `should_cancel`, if given, is polled between sub-stages; when it returns True
    the pipeline raises ScanCancelled (a running jadx/apktool subprocess still
    finishes, but no further stage starts)."""
    def step(msg: str) -> None:
        if should_cancel is not None and should_cancel():
            raise ScanCancelled()
        if on_step is not None:
            try:
                on_step(msg)
            except Exception:
                pass  # a UI hook must never break the pipeline

    apk = Path(apk_path).resolve()
    if not apk.is_file():
        raise FileNotFoundError(apk)

    work = Path(workspace) / apk.stem
    work.mkdir(parents=True, exist_ok=True)

    step("Parsing AndroidManifest.xml (permissions, components)…")
    manifest = extract_manifest(str(apk))
    step("Detecting app framework (native / RN / Flutter / Xamarin)…")
    frameworks = detect_framework(str(apk))
    step("Inventorying native libraries (.so)…")
    natives = inventory_natives(str(apk), on_note=on_step)
    step("Decompiling Java with jadx…")
    jadx = run_jadx(str(apk), str(work / "jadx"))
    _guard_workspace_size(work)
    step("Unpacking smali + resources with apktool…")
    apktool = run_apktool(str(apk), str(work / "apktool"))
    _guard_workspace_size(work)

    # Guard: if BOTH decompilers produced no code the analyst would only see
    # resources and could emit a confident-but-worthless report. Fail clearly
    # instead of scanning an empty workspace. Keyed on both being empty so a
    # normal app never trips it. The tools' own error text is logged locally but
    # kept out of the user-facing message.
    if jadx.file_count == 0 and apktool.file_count == 0:
        print(f"[decompile] jadx: {jadx.note or 'no output'} | "
              f"apktool: {apktool.note or 'no output'}")
        raise RuntimeError(
            "Could not decompile this APK — no code was extracted. The file may "
            "be corrupt, unsupported, or not a standard Android app.")

    step("Extraction complete — handing off to the analyst.")

    summary = {
        "apk": {
            "path": str(apk),
            "name": apk.name,
            "size_bytes": apk.stat().st_size,
        },
        "frameworks": frameworks,
        "manifest": manifest.to_dict(),
        "natives": [asdict(n) for n in natives],
        "decompile": {
            "jadx": asdict(jadx),
            "apktool": asdict(apktool),
        },
        "workspace": str(work.resolve()),
    }

    out = work / "extraction.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary["summary_json"] = str(out.resolve())
    return summary
