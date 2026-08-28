"""Context packing — turn the extracted facts into the model's input.

Step 2 is a single call, so we can't send 2968 decompiled files. We send:
  - the manifest facts (small, high-signal)
  - framework + native-lib inventory (with embedded URLs/strings)
  - the app's OWN Java (skipping R.java resource-id noise and library code)

`R.java` is excluded (hundreds of KB of resource constants). Library packages
(androidx, kotlin, ...) are excluded — Step 2 focuses on first-party code. The
agentic version (Step 3) will let the model pull more on demand.
"""
from __future__ import annotations

import json
from pathlib import Path

# rough char budget for included source (~ keeps one call well within context)
_SOURCE_CHAR_BUDGET = 120_000
_SKIP_FILES = {"R.java"}


def build_context(summary: dict) -> str:
    parts: list[str] = []

    manifest = summary["manifest"]
    parts.append("## APK\n" + json.dumps(summary["apk"], indent=2))
    parts.append("## Frameworks\n" + ", ".join(summary["frameworks"]))
    parts.append("## Manifest facts\n" + json.dumps(manifest, indent=2))

    if summary["natives"]:
        native_view = [
            {
                "path": n["path"],
                "abi": n["abi"],
                "size": n["size"],
                "urls": n["urls"],
                "sample_strings": n["sample_strings"][:15],
            }
            for n in summary["natives"]
        ]
        parts.append("## Native libraries (strings sample)\n" + json.dumps(native_view, indent=2))

    parts.append("## App source (first-party Java)\n" + _pack_app_source(summary))
    return "\n\n".join(parts)


def _pack_app_source(summary: dict) -> str:
    """Include first-party java from the jadx tree, under the app's package path."""
    jadx_dir = Path(summary["decompile"]["jadx"]["out_dir"]) / "sources"
    pkg_path = jadx_dir / Path(*summary["manifest"]["package"].split("."))
    if not pkg_path.exists():
        return "(no first-party source found under package path)"

    files = sorted(
        f for f in pkg_path.rglob("*.java")
        if f.name not in _SKIP_FILES
    )
    chunks: list[str] = []
    used = 0
    for f in files:
        text = f.read_text(errors="replace")
        rel = f.relative_to(jadx_dir)
        header = f"\n// ===== {rel} =====\n"
        if used + len(text) + len(header) > _SOURCE_CHAR_BUDGET:
            chunks.append(f"\n// [truncated — {len(files)} files, budget reached]")
            break
        chunks.append(header + text)
        used += len(text) + len(header)
    return "".join(chunks) if chunks else "(no first-party source included)"
