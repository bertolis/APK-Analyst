"""Framework detection — the agent must know what it's looking at.

Playbook step 13: native Java/Kotlin vs React Native vs Flutter vs Xamarin/Cordova.
Detection is by signature files present in the APK zip.
"""
from __future__ import annotations

import zipfile


def detect_framework(apk_path: str) -> list[str]:
    names: list[str] = []
    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()

    found: list[str] = []
    for name in names:
        if name.endswith("index.android.bundle"):
            found.append("React Native")
        if name.endswith("libhermes.so"):
            found.append("React Native (Hermes)")
        if name.endswith("libflutter.so") or name.startswith("assets/flutter_assets/"):
            found.append("Flutter")
        if name.endswith("libmonodroid.so") or name.endswith(".dll"):
            found.append("Xamarin/.NET")
        if name.startswith("assets/www/") and name.endswith("cordova.js"):
            found.append("Cordova/Ionic")
        if name.endswith("libunity.so") or name.startswith("assets/bin/Data/"):
            found.append("Unity")

    if not found:
        found.append("Native (Java/Kotlin)")
    # de-dup, preserve order
    return list(dict.fromkeys(found))
