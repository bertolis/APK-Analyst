"""Native code inventory: list .so libraries and pull ASCII/UTF strings.

Playbook step 10: native review starts with an inventory + strings sweep
(URLs, keys, root-check tokens hidden in .so files).
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field

# Rough interesting-string signals for a first pass (the AI refines later).
_URL = re.compile(rb"https?://[^\s\"'<>]{6,}")
_ASCII = re.compile(rb"[\x20-\x7e]{5,}")


@dataclass
class NativeLib:
    path: str          # path inside the APK, e.g. lib/arm64-v8a/libnative.so
    abi: str
    size: int
    urls: list[str] = field(default_factory=list)
    sample_strings: list[str] = field(default_factory=list)


def inventory_natives(apk_path: str, max_strings: int = 40) -> list[NativeLib]:
    libs: list[NativeLib] = []
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            name = info.filename
            if not (name.startswith("lib/") and name.endswith(".so")):
                continue
            abi = name.split("/")[1] if "/" in name[4:] else "?"
            data = z.read(name)
            urls = sorted({m.decode("ascii", "ignore") for m in _URL.findall(data)})
            samples = _sample_strings(data, max_strings)
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
