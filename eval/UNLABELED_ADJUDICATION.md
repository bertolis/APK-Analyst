# Unlabeled Findings — Real vs. False-Positive Adjudication

> **What this is:** every finding the tool reported *beyond* the one graded vuln per app.
> The scorer can't auto-check these (no answer key). You decide each one.
>
> **How to mark:** `R` (real issue) / `FP` (false positive) / `INFO` (negative/inventory note, not counted).
>
> **At the end:** False-positive rate = (# FP) / (# real findings + # FP).
> Graded vulns (the 6 known answers) are already confirmed real and are NOT listed here.

Generated: 2026-08-30 · Baseline: 6/6 recall · 74 unlabeled findings

**✅ LOCKED — the author reviewed & accepted the draft as-is (2026-09-04).** All 6 borderline
calls confirmed (CA host/port = FP; the IL/WV NPE crashes and the three PI resilience items
stay R). Every mark is grounded in the quoted evidence in `workspace/<app>/agent_report.json`.
**Final FP rate = 1/48 ≈ 2.1%, 0 FP on the 6 graded vulns, 6/6 recall.**

---

## CA — CommsApp  (11 unlabeled)

- [R] Static (reused) IV with AES-CBC enables ciphertext correlation and manipulation — fixed IV quoted from code; real crypto weakness
- [R] Chat messages transmitted over plaintext HTTP — hardcoded `http://` scheme in sendToServer()
- [R] Network security config globally re-enables cleartext traffic — `cleartextTrafficPermitted="true"` base-config quoted
- [R] Chat history stored in local SQLite database recoverable with the shipped key — key is hardcoded, so DB is trivially decryptable
- [R] allowBackup=true with permissive backup rules exposes the message database — empty `<full-backup-content/>` confirmed
- [R] Over-broad storage permissions requested but never used — READ/WRITE/MANAGE_EXTERNAL_STORAGE, no storage code
- [INFO] Native library libnative.so: obfuscated JNI entry point — "flagged for deeper native review" hedge, not a confident vuln
- [R] No integrity/authenticity check on server responses before decryption — real (low) design weakness, code-backed
- [FP] Server host and port fully attacker/user controllable with no validation — **(borderline)** the user intentionally types their own server IP/port; no attacker trust-boundary is crossed here, so this reads as intended behaviour rather than a vuln
- [INFO] Exported launcher activity (informational) — self-labeled informational; a launcher must be exported
- [INFO] Exported androidx ProfileInstallReceiver is permission-protected — negative/inventory note

## IL — Insecure Login  (14 unlabeled)

- [R] Exported NoteContentActivity reads attacker-controlled file path before the PIN check — smali ordering proves read precedes auth; path traversal
- [R] Hardcoded AES key, IV and PIN shipped inside the application (native libmyapp.so) — real secret-vault exposure
- [INFO] Native library libmyapp.so requires deeper reverse-engineering review — "constants not recoverable via strings" hedge
- [R] AES/CBC with a static hardcoded key and static IV, no authentication — real crypto, smali-quoted
- [R] User notes stored unencrypted on external storage with predictable filenames — code-backed
- [R] MANAGE_EXTERNAL_STORAGE and legacy READ/WRITE requested but not needed — over-privilege
- [R] Note contents and AES-decrypted plaintext written to logcat in a release build — Log.d quoted from smali
- [R] allowBackup="true" with empty backup/data-extraction rule files — confirmed
- [R] Secret PIN propagated between activities as a plaintext Intent extra — `putExtra("userPin", pin)` quoted; real (low)
- [R] Unhandled NPE in exported NoteContentActivity (crash from untrusted intent) — **(borderline)** real reachable crash/DoS but very low severity
- [INFO] No network security configuration declared (INTERNET held, no network code) — negative observation
- [INFO] No anti-tampering, root, debugger or integrity checks present — negative observation
- [INFO] Exported components review: launcher + ProfileInstallReceiver adequately constrained — negative/inventory
- [INFO] No injection, WebView or dynamic code-loading sinks; no malware — negative result

## EA — Exported Activity  (14 unlabeled)

- [R] Path traversal / arbitrary file read via attacker-controlled 'filename' intent extra — FileReader on attacker path, quoted
- [R] Hardcoded PIN recoverable from the native library with `strings` — literal `8937393` extracted; real (likely)
- [R] Client-side-only PIN authentication, trivially patchable, PIN passed as intent extra — code-backed
- [R] Hardcoded AES key and static IV supplied by JNI — real crypto
- [INFO] Native library libmyapp.so holds all app secrets — "flagged for deeper native review" hedge
- [R] User notes written unencrypted to external storage, content-hash filenames — code-backed
- [R] MANAGE_EXTERNAL_STORAGE (All Files Access) requested but never needed — over-privilege
- [R] android:allowBackup="true" with empty backup/data-extraction rules — confirmed
- [INFO] INTERNET permission declared but no networking code exists — negative result
- [INFO] Exported ProfileInstallReceiver is adequately protected — agent's own "summary-fact false positive" correction; not a claimed vuln
- [INFO] No anti-tampering, root, debugger or Frida detection — negative result
- [INFO] Unused JNI entry point n64a32() declared but never invoked — dead-code observation, not a security issue
- [INFO] No injection, WebView or SQL attack surface observed — negative result
- [INFO] No malware, telemetry or supply-chain indicators found — negative result

## PI — Pending Intent  (13 unlabeled)

- [R] Exported MenuActivity exposes a client-side authorization gate to SecretActivity via a boolean intent extra — manifest + code quoted
- [R] Implicit broadcast leaks app data to any listening application every 5 seconds — sendBroadcast with no receiverPermission
- [R] Secret-gating relies on getReferrer() and a debug-flag check — trivially spoofable client-side control
- [R] Integrity/anti-tamper anchors (cert MD5, DEX CRC32, package name) stored in plaintext resources — **(borderline)** weakens the resilience control; an attacker repacking would patch these too
- [R] MD5 used to fingerprint the app signing certificate — **(borderline)** weak-algo use, low real-world impact for a self-fingerprint
- [R] android:allowBackup=true permits extraction of app private data via ADB backup — confirmed
- [INFO] No network security configuration declared (cleartext left to platform default) — negative observation, no network code found
- [INFO] Secret material shipped inside libsecrets.so — "flagged for deeper native review" hedge
- [R] Root/emulator/ADB detection is Java-only, XOR-obfuscated, with a soft delayed response — **(borderline)** real M7 resilience weakness (weak/soft control)
- [INFO] Runtime.exec() used to shell out to getprop for ADB-port detection — fixed-string getprop, no injection; describes mechanism, not a vuln
- [INFO] MainActivity exported + integrity failure only exits after a 5s delay — behavioural observation on the (weak) anti-tamper
- [INFO] Sensitive user input collected with no declared storage/transport/masking — agent tagged tentative; input isn't actually stored or sent
- [INFO] UsbDebugDetectReceiver acts on any incoming broadcast and kills the process — tentative; minor at most

## SP — SSL Pinning  (11 unlabeled)

- [R] Hardcoded AES secret key in string resources — literal key value quoted from strings.xml
- [R] Hardcoded, static initialization vector for AES/CBC — literal IV quoted
- [R] Encryption without integrity protection (AES-CBC, no MAC/AEAD) — real crypto weakness
- [R] Chat messages persisted to a local SQLite database recoverable in plaintext — key hardcoded
- [R] Backups enabled with empty backup/data-extraction rules — confirmed
- [R] Network security config permits cleartext traffic for all domains — base-config quoted
- [R] Unvalidated user-supplied port concatenated into the request URL (host substitution) — ties to a concrete pinning-bypass path; real
- [R] Over-broad storage permissions including MANAGE_EXTERNAL_STORAGE — over-privilege
- [INFO] Certificate pin supplied by native library: obfuscation-only, unverifiable statically — "flagged for deeper native review" hedge
- [INFO] Exported launcher activity and ProfileInstallReceiver — reviewed, no exploitable IPC exposure — negative/inventory
- [INFO] No anti-analysis, root/debugger detection, or code obfuscation present — negative result

## WV — WebView  (11 unlabeled)

- [R] WebView shouldOverrideUrlLoading returns false — off-origin navigation keeps the JS bridge attached — part of a real exploit chain, code-quoted
- [R] Authentication endpoint contacted over plaintext HTTP with parameters in the URL — `http://...` URL quoted
- [R] Network security config permits cleartext traffic to all destinations — base-config quoted
- [R] Session token stored unencrypted in SharedPreferences — saveToken() quoted
- [R] Backups enabled with empty rule files — token-bearing preferences are exported — confirmed
- [R] Session token written to logcat in a release build — `Log.d("UserToken", ...)` with no DEBUG guard
- [INFO] Native library libmyapp.so generates the session token — "flagged for deeper native review" hedge
- [R] Over-broad storage permissions (MANAGE_EXTERNAL_STORAGE) with no storage code — over-privilege
- [R] Unvalidated user-supplied host/port concatenated into the WebView URL — feeds the attacker-URL WebView path; real
- [R] Null-token NullPointerException reachable from the exported activity — **(borderline)** real reachable crash, very low severity
- [INFO] Informational: exported components inventory and clean-check results — negative/inventory

---

## Tally  (DRAFT — Claude's first pass; review & adjust)

| App | Real (R) | False-Positive (FP) | Info (not counted) |
|-----|----------|---------------------|--------------------|
| CA  | 7        | 1                   | 3                  |
| IL  | 9        | 0                   | 5                  |
| EA  | 7        | 0                   | 7                  |
| PI  | 7        | 0                   | 6                  |
| SP  | 8        | 0                   | 3                  |
| WV  | 9        | 0                   | 2                  |
| **Total** | **47** | **1**          | **26**             |

**False-positive rate = FP / (R + FP) = 1 / 48 = ~2.1%**  (0 FP on graded vulns; 6/6 recall)

> **Draft reading of the story:** of 74 findings beyond the graded vuln, ~47 are genuine
> secondary issues, 26 are honest negative/inventory notes (hedges the tool did NOT assert as
> confirmed vulns), and 1 is a false positive (CA host/port — intended user behaviour). That's a
> ~2% FP rate on discretionary findings with 0 on the graded set.
>
> **Borderline calls to review** (flip freely): CA host/port (FP), IL/WV null-pointer crashes,
> and the three PI resilience items (MD5 fingerprint, plaintext integrity anchors, soft Java-only
> root detection). Reasonable analysts differ on whether low-severity resilience/robustness notes
> count as "real findings" or "info" — your call decides the headline number.
>
> Note: "flagged for deeper native review" and "no X observed / negative result" items are honest
> hedges, marked INFO rather than FP since the tool explicitly did NOT assert them as confirmed vulns.
