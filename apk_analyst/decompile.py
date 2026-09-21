"""Decompiler wrappers: jadx (Java) and apktool (smali + resources).

These shell out to the installed tools and drop output into the workspace.
We keep the raw trees on disk (the agent will read from them later) and return
lightweight summaries for the pipeline report.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DecompileResult:
    tool: str
    out_dir: str
    ok: bool
    file_count: int
    note: str = ""


def _tool_env(out_dir: str) -> dict:
    """jadx and apktool write config/plugins/framework cache under $HOME
    (~/.config/jadx, ~/.local/share/apktool). When the app runs in a hardened
    container with a read-only root filesystem, the real home isn't writable and
    the tools crash before producing any output. Point HOME (and the XDG dirs) at
    a writable cache beside the output — which lives on the job's writable tmpfs —
    so the tools can always initialise. Harmless locally (home is already
    writable; this just isolates their cache per run)."""
    cache = Path(out_dir).parent / ".toolcache"
    cache.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(cache)
    env["XDG_CONFIG_HOME"] = str(cache / ".config")
    env["XDG_DATA_HOME"] = str(cache / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(cache / ".cache")
    return env


def run_jadx(apk_path: str, out_dir: str, timeout: int = 600) -> DecompileResult:
    """Decompile to readable Java. --no-res keeps it fast; apktool handles resources."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cmd = ["jadx", "--no-res", "-d", str(out), apk_path]
    ok, note = _run(cmd, timeout, _tool_env(out_dir))
    java_files = _count(out, "*.java")
    return DecompileResult("jadx", str(out), ok or java_files > 0, java_files, note)


def run_apktool(apk_path: str, out_dir: str, timeout: int = 600) -> DecompileResult:
    """Decompile smali + decode resources/manifest (resolves resource refs)."""
    out = Path(out_dir)
    cmd = ["apktool", "d", "-f", "-o", str(out), apk_path]
    ok, note = _run(cmd, timeout, _tool_env(out_dir))
    smali_files = _count(out, "*.smali")
    return DecompileResult("apktool", str(out), ok or smali_files > 0, smali_files, note)


def _run(cmd: list[str], timeout: int, env: dict | None = None) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        if p.returncode != 0:
            return False, (p.stderr or p.stdout or "").strip().splitlines()[-1:][0] if (p.stderr or p.stdout) else "nonzero exit"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    except FileNotFoundError:
        return False, f"tool not found: {cmd[0]}"


def _count(root: Path, pattern: str) -> int:
    if not root.exists():
        return 0
    return sum(1 for _ in root.rglob(pattern))
