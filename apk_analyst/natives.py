"""Native code inventory: list .so libraries and pull ASCII/UTF strings.

Playbook step 10: native review starts with an inventory + strings sweep
(URLs, keys, root-check tokens hidden in .so files).
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Optional

# Rough interesting-string signals for a first pass (the AI refines later).
_URL = re.compile(rb"https?://[^\s\"'<>]{6,}")
_ASCII = re.compile(rb"[\x20-\x7e]{5,}")

# Cap how many *decompressed* bytes we ever pull from one .so. Reading via a
# streamed handle with a hard limit defuses decompression ("zip") bombs — a tiny
# compressed entry that would otherwise inflate to gigabytes and OOM the worker.
# 50 MB is far more than enough to string-scan any legitimate native library.
_MAX_SO_BYTES = 50 * 1024 * 1024


@dataclass
class NativeLib:
    path: str          # path inside the APK, e.g. lib/arm64-v8a/libnative.so
    abi: str
    size: int
    urls: list[str] = field(default_factory=list)
    sample_strings: list[str] = field(default_factory=list)


def inventory_natives(apk_path: str, max_strings: int = 40,
                      on_note: Optional[Callable[[str], None]] = None) -> list[NativeLib]:
    """`on_note`, if given, receives a short human-readable line (e.g. when a very
    large native library is capped) so a UI console can surface it. Never raises."""
    def note(msg: str) -> None:
        if on_note is not None:
            try:
                on_note(msg)
            except Exception:
                pass

    libs: list[NativeLib] = []
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            name = info.filename
            if not (name.startswith("lib/") and name.endswith(".so")):
                continue
            abi = name.split("/")[1] if "/" in name[4:] else "?"
            # Stream at most _MAX_SO_BYTES of *decompressed* data (bomb-safe);
            # read one extra byte only to note truncation.
            with z.open(name) as fh:
                data = fh.read(_MAX_SO_BYTES + 1)
            truncated = len(data) > _MAX_SO_BYTES
            if truncated:
                data = data[:_MAX_SO_BYTES]
                note(f"Large native library {name} — scanning first "
                     f"{_MAX_SO_BYTES // (1024*1024)} MB only.")
            urls = sorted({m.decode("ascii", "ignore") for m in _URL.findall(data)})
            samples = _sample_strings(data, max_strings)
            if truncated:
                samples.append(f"[.so scanned up to {_MAX_SO_BYTES // (1024*1024)} MB]")
            libs.append(
                NativeLib(path=name, abi=abi, size=info.file_size, urls=urls,
                          sample_strings=samples)
            )
    return libs


def _sample_strings(data: bytes, limit: int) -> list[str]:
    seen: list[str] = []
    for m in _ASCII.findall(data):
        s = m.decode("ascii", "ignore")
        if len(s) >= 6 and any(c.isalpha() for c in s):
            seen.append(s)
            if len(seen) >= limit:
                break
    return seen
