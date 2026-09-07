# SecureVault — bundled sample app

> ⚠️ **Intentionally vulnerable.** `SecureVault.apk` is a purpose-built,
> deliberately-insecure Android app. It exists only so you can run APKAnalyst
> end-to-end against a target with a **known ground truth**. Do not install it on
> a device with real data or reuse any of its behavior.

`SecureVault.apk` is a small, fully-functional personal-notes app (login → notes
→ encrypt → cloud sync → in-app help) written from scratch for this project. Because
it's first-party and every weakness is planted on purpose, it's a **zero-bias test
target**: the model has never seen it, so what the scanner finds can be checked
against the table below.

## Scan it

```bash
python3 run.py sample-app/SecureVault.apk --agent      # full agentic scan
# or drag it into the web app (webapp/) and pick "Full agentic"
```

## Ground truth — planted vulnerabilities

| # | Vulnerability | OWASP Mobile Top 10 | CWE |
|---|---------------|---------------------|-----|
| 1 | Insecure logging of credentials & tokens (logcat) | M6 | CWE-532 |
| 2 | Weak crypto — AES/ECB + hardcoded key; unsalted MD5 | M10 | CWE-327/328 |
| 3 | Cleartext HTTP (sync + WebView), `usesCleartextTraffic=true` | M5 | CWE-319 |
| 4 | Disabled TLS validation — trust-all `TrustManager` | M5 | CWE-295 |
| 5 | Insecure WebView — JS enabled + `addJavascriptInterface` over HTTP | M4/M7 | CWE-749 |
| 6 | Exported activity, no permission (`QuickAddActivity`) | M8 | CWE-926 |
| 7 | Mutable, implicit `PendingIntent` | M8 | CWE-927 |
| 8 | `allowBackup=true` | M9 | CWE-530 |
| 9 | Plaintext credentials/token in SharedPreferences | M9 | CWE-312 |
| 10 | Hardcoded secrets in native `libsecurevault.so` | M1/M7 | CWE-798 |
| 11 | Client-side authentication against a hardcoded hash | M3 | CWE-603 |

*A good scan should surface most of these plus incidental secondary issues.*

## Sample report

See what APKAnalyst actually produces on this app:
**[SecureVault_Report.pdf](../docs/SecureVault_Report.pdf)** — a full agentic scan
(21 findings; all 11 planted vulns caught, plus secondary issues), each finding
with evidence, exploit path, remediation, and MASVS/course citations.

## App details

- **Stack:** Java + Material UI, with a small JNI/C++ library.
- **Demo credentials** (if you run the app): `admin` / `letmein`
- **Source:** the full Android Studio project is maintained separately; only the
  built APK is bundled here as a ready-to-scan target.
