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
from dataclasses import asdict
from pathlib import Path

from androguard import util as _ag_util

from .manifest import extract_manifest
from .decompile import run_jadx, run_apktool
from .natives import inventory_natives
from .framework import detect_framework

_ag_util.set_log("ERROR")  # silence androguard's verbose loguru output


def analyze(apk_path: str, workspace: str = "workspace") -> dict:
    apk = Path(apk_path).resolve()
    if not apk.is_file():
        raise FileNotFoundError(apk)

    work = Path(workspace) / apk.stem
    work.mkdir(parents=True, exist_ok=True)

    manifest = extract_manifest(str(apk))
    frameworks = detect_framework(str(apk))
    natives = inventory_natives(str(apk))
    jadx = run_jadx(str(apk), str(work / "jadx"))
    apktool = run_apktool(str(apk), str(work / "apktool"))

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
    out.write_text(json.dumps(summary, indent=2))
    summary["summary_json"] = str(out.resolve())
    return summary
