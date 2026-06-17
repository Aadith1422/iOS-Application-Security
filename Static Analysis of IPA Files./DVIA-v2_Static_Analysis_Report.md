# iOS Mobile Application Security Assessment Report
## Static Analysis — DVIA-v2 (Damn Vulnerable iOS Application v2)

---

| Field | Details |
|---|---|
| **Report Title** | iOS Static Analysis — Penetration Test Report |
| **Target Application** | DVIA-v2 (Damn Vulnerable iOS App v2) |
| **Assessment Type** | Static Analysis / Black-Box Review |
| **Binary Architecture** | ARM64 (Mach-O 64-bit) |
| **Testing Date** | June 2025 |
| **Prepared By** | Aadith (Security Researcher) |
| **Report Classification** | Confidential |
| **Report Version** | 1.1 |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope](#2-scope)
3. [Methodology](#3-methodology)
4. [Tools Used](#4-tools-used)
5. [Application Overview](#5-application-overview)
6. [Findings Summary](#6-findings-summary)
7. [Detailed Findings](#7-detailed-findings)
8. [Remediation Recommendations](#8-remediation-recommendations)
9. [Conclusion](#9-conclusion)

---

## 1. Executive Summary

A static security analysis was performed on the iOS application **DVIA-v2** (Damn Vulnerable iOS Application version 2), a deliberately vulnerable iOS application designed for security training purposes. The assessment focused exclusively on **static analysis techniques** — no runtime instrumentation or dynamic testing was performed during this engagement.

The analysis identified **10 security findings** across three severity levels:

| Severity | Count |
|---|---|
| 🔴 High | 3 |
| 🟡 Medium | 5 |
| 🔵 Low | 2 |
| **Total** | **10** |

Critical issues include **hardcoded credentials** recoverable directly from the binary, a **hardcoded encryption password**, and **weak key derivation** parameters. These findings collectively represent significant risk and would allow an attacker with physical access to the application binary to compromise authentication, decrypt stored data, and access internal endpoints.

---

## 2. Scope

### In Scope

| Item | Details |
|---|---|
| **Application** | DVIA-v2.ipa |
| **Binary** | DVIA-v2 (Mach-O ARM64) |
| **Configuration File** | Info.plist |
| **Embedded Frameworks** | Parse.framework, Bolts.framework, Realm.framework, RealmSwift.framework |
| **Assessment Type** | Static Analysis Only |
| **OWASP Reference** | OWASP Mobile Application Security Verification Standard (MASVS) / MASTG |

### Out of Scope

- Dynamic analysis / runtime instrumentation
- Network traffic interception
- Server-side / backend security testing
- Third-party framework source code review

---

## 3. Methodology

The assessment followed the **OWASP Mobile Application Security Testing Guide (MASTG)** methodology for iOS static analysis. The following phases were executed:

```
Phase 1: IPA Extraction & Reconnaissance
         └── Unzip IPA → inspect directory structure → locate binary

Phase 2: Binary Metadata Analysis
         └── file command → verify architecture, binary type, protections

Phase 3: App Structure Analysis
         └── Enumerate storyboards → identify feature modules → list frameworks

Phase 4: Sensitive String Discovery
         └── strings extraction → grep filtering → keyword mapping

Phase 5: Reverse Engineering
         └── Ghidra import → auto-analysis → Defined Strings → XREF tracing → decompilation

Phase 6: Configuration Review
         └── Info.plist inspection → ATS settings → permission keys

Phase 7: Cryptographic Review
         └── Identify hash functions → evaluate key derivation parameters
```

**Standards Referenced:**

- OWASP MASVS v2
- OWASP MASTG (iOS)
- CWE (Common Weakness Enumeration)
- CVSS v3.1 (for severity scoring)

---

## 4. Tools Used

| Tool | Version | Purpose |
|---|---|---|
| **unzip** | System | IPA extraction |
| **file** | System | Binary type identification |
| **strings** | System | Sensitive string extraction from binary |
| **grep** | System | Keyword filtering |
| **Ghidra** | 11.x | Reverse engineering, decompilation, XREF analysis |
| **plistlib (Python)** | 3.x | Info.plist parsing |
| **plutil** | System | Binary plist conversion |
| **xxd / hexdump** | System | Hex inspection |

---

## 5. Application Overview

### Binary Information

| Property | Value |
|---|---|
| **File Name** | DVIA-v2 |
| **Binary Type** | Mach-O 64-bit executable |
| **Architecture** | ARM64 |
| **PIE Enabled** | Yes |
| **IPA Location** | Payload/DVIA-v2.app/DVIA-v2 |

### Application Modules (Storyboards Identified)

| Module |
|---|
| InsecureDataStorage.storyboardc |
| BrokenCryptography.storyboardc |
| TransportLayerProtection.storyboardc |
| RuntimeManipulation.storyboardc |
| SensitiveInformation.storyboardc |
| + additional modules |

### Embedded Frameworks

| Framework | Notes |
|---|---|
| Parse.framework | Backend API / BaaS SDK |
| Bolts.framework | Task management (Parse dependency) |
| Realm.framework | Local database (NoSQL) |
| RealmSwift.framework | Swift wrapper for Realm |

---

## 6. Findings Summary

| # | Finding | Severity | OWASP MASVS | CWE |
|---|---|---|---|---|
| F-01 | Hardcoded Credentials in Binary | 🔴 High | MSTG-STORAGE-14 | CWE-798 |
| F-02 | Hardcoded Encryption Password | 🔴 High | MSTG-CRYPTO-1 | CWE-321 |
| F-03 | Weak Key Derivation (PBKDF2 — 500 iterations) | 🔴 High | MSTG-CRYPTO-4 | CWE-916 |
| F-04 | Authentication State Stored in NSUserDefaults | 🟡 Medium | MSTG-STORAGE-1 | CWE-312 |
| F-05 | Weak Cryptographic Algorithms (MD5, SHA-1) | 🟡 Medium | MSTG-CRYPTO-4 | CWE-327 |
| F-06 | Sensitive Data in Local Storage | 🟡 Medium | MSTG-STORAGE-2 | CWE-312 |
| F-07 | Internal Endpoint Path Disclosure | 🟡 Medium | MSTG-RESILIENCE-1 | CWE-200 |
| F-08 | ATS Exception Configured (NSAllowsArbitraryLoads) | 🟡 Medium | MSTG-NETWORK-2 | CWE-319 |
| F-09 | Source Code Path Disclosure | 🔵 Low | MSTG-RESILIENCE-1 | CWE-200 |
| F-10 | Debug Logging Present in Production Binary | 🔵 Low | MSTG-RESILIENCE-2 | CWE-215 |

---

## 7. Detailed Findings

---

### F-01 — Hardcoded Credentials in Binary

| Field | Detail |
|---|---|
| **Severity** | 🔴 High |
| **CVSS Score** | 8.4 (High) |
| **OWASP MASVS** | MSTG-STORAGE-14 |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **Tool** | strings, Ghidra |

**Description**

Plaintext credentials were discovered embedded directly within the application binary. Using the `strings` command and subsequent verification in Ghidra via Defined Strings and XREF analysis, the following credentials were recovered:

**Evidence**

```
Username : admin13412
Password : S@g@rm@7h@8848
```

These strings were confirmed to be used in an authentication comparison function decompiled in Ghidra. The function directly compares user-supplied input against these hardcoded values.

**Impact**

Any actor with access to the IPA file can recover the credentials in under five minutes without any special knowledge, bypassing the application's authentication entirely.

**Affected Location**

`Payload/DVIA-v2.app/DVIA-v2` — Authentication module (confirmed via Ghidra XREF)

**Mitigation**

- Remove all hardcoded credentials from the binary immediately — credentials must never be embedded in client-side code or resources.
- Implement **server-side authentication** exclusively; the client should supply credentials to the server, which validates them against a securely stored (hashed + salted) credential store.
- If a default test account is needed for development, manage it through a separate, non-distributed configuration and rotate credentials before any build is distributed.
- Use a secrets scanner (e.g. `truffleHog`, `gitleaks`) in the CI/CD pipeline to detect accidental credential commits going forward.

---

### F-02 — Hardcoded Encryption Password

| Field | Detail |
|---|---|
| **Severity** | 🔴 High |
| **CVSS Score** | 8.1 (High) |
| **OWASP MASVS** | MSTG-CRYPTO-1 |
| **CWE** | CWE-321: Use of Hard-coded Cryptographic Key |
| **Tool** | strings, Ghidra |

**Description**

A hardcoded password used for data encryption was found embedded in the binary. This password serves as the encryption key (or key derivation input) for encrypted local storage.

**Evidence**

```
@daloq3as$qweasdlasasjdnj
```

**Impact**

With the encryption password recovered from the binary, any encrypted files produced by the application can be decrypted offline by an attacker without device access, completely defeating the purpose of encryption.

**Mitigation**

- Never embed cryptographic keys or key-derivation passwords in the application binary or any bundled resource file.
- Generate encryption keys at runtime using the **iOS Secure Enclave** or derive them from a user-supplied passphrase via a strong KDF (PBKDF2, Argon2, or scrypt) with a securely generated random salt.
- Store derived or generated keys exclusively in the **iOS Keychain** with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` to ensure keys are device-bound and only accessible when the device is unlocked.
- For data that must remain accessible without user interaction (e.g. background refresh), use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` as the least permissive option that satisfies the use case.

---

### F-03 — Weak Key Derivation (PBKDF2 — 500 Iterations)

| Field | Detail |
|---|---|
| **Severity** | 🔴 High |
| **CVSS Score** | 7.5 (High) |
| **OWASP MASVS** | MSTG-CRYPTO-4 |
| **CWE** | CWE-916: Use of Password Hash with Insufficient Computational Effort |
| **Tool** | Ghidra |

**Description**

The application uses PBKDF2 for key derivation with only **500 iterations**. NIST SP 800-132 recommends a minimum of **210,000 iterations** for PBKDF2-HMAC-SHA256 (2023 guidance). Modern hardware can trivially brute-force keys derived with such low iteration counts.

**Evidence**

```
PBKDF2 iterations = 500
```

(Identified in Ghidra decompiler output within the cryptographic module)

**Impact**

Brute-force attacks against derived keys are highly feasible. Combined with F-02 (hardcoded password), the encryption is effectively broken.

**Mitigation**

- Increase PBKDF2 iteration count to a minimum of **210,000 iterations** using PBKDF2-HMAC-SHA256, in line with NIST SP 800-132 (2023).
- If migrating existing users, implement a migration path: re-derive and re-encrypt stored data with the new parameters upon the user's next authenticated session.
- Consider adopting **Argon2id** (winner of the Password Hashing Competition) as a more memory-hard alternative that is more resistant to GPU/ASIC-based brute-force attacks, if supported by the target iOS deployment.
- Use a cryptographically random salt of at least **16 bytes** (128 bits), generated fresh per key derivation operation and stored alongside the derived key material.

---

### F-04 — Authentication State Stored in NSUserDefaults

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **CVSS Score** | 5.5 (Medium) |
| **OWASP MASVS** | MSTG-STORAGE-1 |
| **CWE** | CWE-312: Cleartext Storage of Sensitive Information |
| **Tool** | strings |

**Description**

The authentication state of the user is persisted using `NSUserDefaults` under the key `loggedIn`. NSUserDefaults is stored in a plaintext `.plist` file at:

```
/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/<BundleID>.plist
```

On a jailbroken device — or via an iTunes/iCloud backup — this file is trivially accessible and readable.

**Evidence**

```
loggedIn       ← key identified via strings extraction
NSUserDefaults ← confirmed by string reference
```

**Impact**

An attacker with file system access (jailbroken device, malicious backup restore) can set `loggedIn = true` to bypass authentication without providing any credentials.

**Mitigation**

- Move the authentication state flag (and any other security-relevant values) from `NSUserDefaults` to the **iOS Keychain**, using `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` so the value is inaccessible outside the authenticated device.
- Never use `NSUserDefaults` for any security-sensitive data — it is plaintext, included in backups by default, and offers no access control.
- Complement client-side session state with **server-side session validation**: the app should verify session validity with the backend on each sensitive action, not rely solely on a local `loggedIn` flag.
- Ensure Keychain items used for auth state are excluded from iCloud/iTunes backup by setting `kSecAttrSynchronizable` to `false`.

---

### F-05 — Weak Cryptographic Algorithms (MD5, SHA-1)

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **CVSS Score** | 5.9 (Medium) |
| **OWASP MASVS** | MSTG-CRYPTO-4 |
| **CWE** | CWE-327: Use of a Broken or Risky Cryptographic Algorithm |
| **Tool** | strings, Ghidra |

**Description**

References to both **MD5** and **SHA-1** cryptographic algorithms were identified within the binary. Both algorithms are considered cryptographically broken:

- **MD5** — Collision vulnerabilities demonstrated; deprecated for all security uses since 2008 (RFC 6151).
- **SHA-1** — SHAttered attack (2017) demonstrated practical collision attacks; deprecated by NIST.

**Evidence**

```
MD5
SHA1
HMAC-SHA1
```

(Identified via `strings` and confirmed in Ghidra Defined Strings view)

**Impact**

Data integrity checks using these algorithms can be bypassed. Passwords hashed with MD5/SHA-1 are vulnerable to rainbow table and brute-force attacks.

**Mitigation**

- Replace all uses of MD5 and SHA-1 with **SHA-256** or **SHA-3 (SHA3-256)** for integrity hashing and general-purpose digest operations.
- For password hashing specifically, use an adaptive, salted password hashing function: **bcrypt**, **scrypt**, or **Argon2id** — never a raw SHA digest.
- For MAC operations, replace HMAC-SHA1 with **HMAC-SHA256** or **HMAC-SHA512**.
- Use Apple's **CryptoKit** framework (available iOS 13+) which provides modern, audited implementations of SHA-256, SHA-512, HMAC, AES-GCM, and ChaCha20-Poly1305, reducing the risk of cryptographic misuse.
- Audit all use sites in Ghidra (via XREF on `CC_MD5`, `CC_SHA1`, `CCHmac`) to ensure no remaining references persist after remediation.

---

### F-06 — Sensitive Data in Local Storage

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **CVSS Score** | 5.5 (Medium) |
| **OWASP MASVS** | MSTG-STORAGE-2 |
| **CWE** | CWE-312: Cleartext Storage of Sensitive Information |
| **Tool** | strings |

**Description**

References to sensitive local file paths and storage mechanisms were found in the binary, indicating that the application stores sensitive data locally without adequate protection.

**Evidence**

```
/secret-data
/v324dsa13qasd.enc
```

Additionally, the application uses both **Realm** (local NoSQL database) and **SQLite**, whose database files may contain sensitive user data accessible without decryption on a compromised device.

**Impact**

On a jailbroken device or via backup extraction, an attacker can access these files and recover sensitive application data.

**Mitigation**

- Apply **iOS Data Protection** to all sensitive files by setting `NSFileProtectionComplete` (or at minimum `NSFileProtectionCompleteUnlessOpen`) as the file attribute at creation time, ensuring files are encrypted when the device is locked.
- For Realm databases, enable **Realm Encryption** using a 64-byte AES-256 key stored in the Keychain — Realm natively supports full database encryption via its configuration object.
- For SQLite databases, use **SQLCipher** (an encrypted SQLite extension) to encrypt the entire database file at rest.
- Avoid writing sensitive data to paths accessible outside the app sandbox (e.g. shared containers, `Documents` if iCloud backup is enabled); use `Library/Application Support` with backup exclusion for sensitive non-user files.
- Exclude sensitive local files from iCloud and iTunes backups by setting `NSURLIsExcludedFromBackupKey = true` on the file URL.

---

### F-07 — Internal Endpoint Path Disclosure

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **CVSS Score** | 5.3 (Medium) |
| **OWASP MASVS** | MSTG-RESILIENCE-1 |
| **CWE** | CWE-200: Exposure of Sensitive Information |
| **Tool** | strings |

**Description**

An internal API endpoint path was discovered hardcoded within the binary:

**Evidence**

```
/secret-data
```

**Impact**

Exposing internal endpoint paths aids attackers in mapping server-side attack surface and facilitates targeted API abuse, especially if combined with the hardcoded credentials found in F-01.

**Mitigation**

- Do not hardcode internal API endpoint paths in the binary. Load all API routes dynamically from a server-side configuration endpoint that is fetched at runtime after authenticated session establishment.
- Apply **server-side authorization** on all endpoints regardless of whether their paths are known — security through obscurity alone is not a valid control.
- If endpoint paths must be bundled client-side, consider obfuscating them; however, this is a secondary control and not a substitute for proper server-side access control.
- Regularly audit the binary for hardcoded strings (endpoint paths, environment URLs, internal hostnames) as part of the pre-release security review process.

---

### F-08 — ATS Exception Configured (NSAllowsArbitraryLoads)

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **CVSS Score** | 5.9 (Medium) |
| **OWASP MASVS** | MSTG-NETWORK-2 |
| **CWE** | CWE-319: Cleartext Transmission of Sensitive Information |
| **Tool** | strings, plistlib |

**Description**

The application's `Info.plist` contains the `NSAppTransportSecurity` dictionary with the `NSAllowsArbitraryLoads` key present. If set to `true`, this disables Apple's App Transport Security (ATS) globally, allowing the application to communicate over unencrypted HTTP connections.

**Evidence**

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <!-- value requires runtime confirmation -->
</dict>
```

**Impact**

If `NSAllowsArbitraryLoads` is set to `true`, all network traffic is permitted over HTTP, enabling man-in-the-middle (MitM) attacks to intercept and modify data in transit. Severity escalates to **High** if value is confirmed `true`.

**Note:** Full confirmation of the boolean value requires:

```bash
python3 -c "
import plistlib
with open('Info.plist','rb') as f:
    p=plistlib.load(f)
print(p.get('NSAppTransportSecurity'))
"
```

**Mitigation**

- Remove the `NSAllowsArbitraryLoads` key entirely from `Info.plist` to restore default ATS enforcement (TLS 1.2+ required for all connections).
- If specific third-party domains require HTTP (e.g. a legacy CDN), use **domain-specific ATS exceptions** (`NSExceptionDomains`) scoped to exactly those domains, rather than a global bypass.
- Enforce **TLS 1.2 as a minimum** across all domains the app communicates with; prefer TLS 1.3 where supported.
- Validate ATS compliance using Apple's diagnostic tool: `nscurl --ats-diagnostics https://yourdomain.com` to confirm all endpoints are reachable under strict ATS settings before shipping.
- Combine with **certificate/public key pinning** on security-critical endpoints to further harden against MitM attacks even on compromised network paths.

---

### F-09 — Source Code Path Disclosure

| Field | Detail |
|---|---|
| **Severity** | 🔵 Low |
| **CVSS Score** | 2.7 (Low) |
| **OWASP MASVS** | MSTG-RESILIENCE-1 |
| **CWE** | CWE-200: Exposure of Sensitive Information |
| **Tool** | strings |

**Description**

Developer filesystem paths were found embedded in the binary, leaking the developer's local build environment path.

**Evidence**

```
/Users/PrateekGianchandani/...
```

**Impact**

While low severity on its own, this information can assist attackers in:
- Confirming the developer's identity
- Correlating with other OSINT information
- Understanding build environment structure

**Mitigation**

- Enable the following Xcode build settings in the **Release** configuration to strip debug symbols and embedded path information from production binaries:
  - `DEPLOYMENT_POSTPROCESSING = YES`
  - `STRIP_INSTALLED_PRODUCT = YES`
  - `STRIP_STYLE = all`
  - `DEBUG_INFORMATION_FORMAT = dwarf-with-dsym` (keeps symbolication data in a separate `.dSYM` bundle, not in the binary)
- Store `.dSYM` bundles securely for crash symbolication, but never ship them alongside the IPA.
- Run `strings` against production builds as part of the pre-release checklist to verify that developer paths, internal hostnames, and build-environment details are not present.

---

### F-10 — Debug Logging Present in Production Binary

| Field | Detail |
|---|---|
| **Severity** | 🔵 Low |
| **CVSS Score** | 3.1 (Low) |
| **OWASP MASVS** | MSTG-RESILIENCE-2 |
| **CWE** | CWE-215: Insertion of Sensitive Information into Log File |
| **Tool** | strings |

**Description**

Debug logging mechanisms remain active in the production binary. References to `NSLog` and the `traceExecution` flag indicate that verbose logging may expose sensitive runtime information.

**Evidence**

```
NSLog
traceExecution
```

**Impact**

On a jailbroken device, debug logs can be captured via the device console and may expose sensitive data including authentication tokens, user inputs, or internal state information during runtime.

**Mitigation**

- Wrap all `NSLog` and `print` statements in compile-time debug guards so they are completely excluded from Release builds:

  ```swift
  #if DEBUG
  print("Token: \(token)")
  NSLog("User: %@", username)
  #endif
  ```

- Disable or remove the `traceExecution` flag in production configuration; if it controls a logging verbosity level, ensure the default for Release builds is `none` or `off`.
- Consider replacing ad-hoc `NSLog` usage with a structured logging framework (e.g. **OSLog** / `os_log`) that supports privacy annotations (`%{private}@`) to redact sensitive values from logs even in debug builds:

  ```swift
  import os
  let logger = Logger(subsystem: "com.app", category: "auth")
  logger.debug("User token: \(token, privacy: .private)")
  ```

- Audit all logging call sites before each release and establish a policy that PII, tokens, credentials, and session data are never written to any log regardless of build configuration.

---

## 8. Remediation Recommendations

### High Priority (Immediate)

| Finding | Recommendation |
|---|---|
| F-01: Hardcoded Credentials | Remove all hardcoded credentials from the binary. Implement server-side authentication. Store no credentials client-side. |
| F-02: Hardcoded Encryption Key | Never embed encryption keys in the binary. Use iOS Keychain Services to store cryptographic keys securely. Consider key derivation from user-provided secrets combined with device-bound secrets. |
| F-03: Weak PBKDF2 Iterations | Increase PBKDF2 iterations to a minimum of **210,000** (NIST 2023 recommendation for PBKDF2-HMAC-SHA256). Re-derive and migrate existing stored data. |

### Medium Priority (Next Sprint)

| Finding | Recommendation |
|---|---|
| F-04: NSUserDefaults Auth State | Store authentication state in the **iOS Keychain** with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Never use NSUserDefaults for security-sensitive values. |
| F-05: Weak Crypto (MD5/SHA-1) | Replace MD5 and SHA-1 with **SHA-256** or **SHA-3** for hashing. Use **AES-256-GCM** for symmetric encryption. Use Apple's CryptoKit. |
| F-06: Sensitive Local Storage | Encrypt all local sensitive files using iOS Data Protection (`NSFileProtectionComplete`). Enable Realm encryption. Use SQLCipher for SQLite. |
| F-07: Endpoint Disclosure | Do not hardcode internal endpoint paths. Load configuration from a server-side configuration endpoint authenticated at runtime. |
| F-08: ATS Exception | Remove `NSAllowsArbitraryLoads` entirely. Enforce TLS 1.2+ for all connections. Use domain-specific ATS exceptions if strictly necessary. |

### Low Priority (Backlog)

| Finding | Recommendation |
|---|---|
| F-09: Source Path Disclosure | Enable `DEPLOYMENT_POSTPROCESSING`, `STRIP_INSTALLED_PRODUCT`, and `STRIP_STYLE = all` in Xcode Release build settings. |
| F-10: Debug Logging | Gate all `NSLog`/`print` statements behind `#if DEBUG`. Use `os_log` with privacy annotations. Audit all log call sites before each release. |

---

## 9. Conclusion

The static analysis of **DVIA-v2** revealed **10 security vulnerabilities**, including **3 critical/high severity** issues that would directly enable an attacker to compromise authentication, decrypt stored data, and access internal API endpoints — all without any dynamic interaction with the application.

The most critical issues — hardcoded credentials, hardcoded encryption passwords, and weak key derivation — represent fundamental design flaws that cannot be patched with minor fixes; they require architectural changes to the application's authentication and cryptographic design.

The application also demonstrates several classes of vulnerabilities commonly seen in real-world iOS applications:

- Insecure local storage (NSUserDefaults for auth state, unprotected files)
- Deprecated cryptographic algorithms (MD5, SHA-1)
- Disabled platform security controls (ATS bypass)
- Information disclosure through binary artifacts (source paths, endpoints, debug logging)

### OWASP Mobile Top 10 Coverage

| OWASP Mobile Top 10 (2024) | Finding(s) |
|---|---|
| M1 — Improper Credential Usage | F-01, F-02 |
| M2 — Inadequate Supply Chain Security | — |
| M3 — Insecure Authentication/Authorization | F-01, F-04 |
| M4 — Insufficient Input/Output Validation | — |
| M5 — Insecure Communication | F-08 |
| M6 — Inadequate Privacy Controls | F-06 |
| M7 — Insufficient Binary Protections | F-09, F-10 |
| M8 — Security Misconfiguration | F-08 |
| M9 — Insecure Data Storage | F-04, F-06 |
| M10 — Insufficient Cryptography | F-03, F-05 |

---

*This report was prepared as part of an iOS mobile application security assessment for educational and portfolio purposes using DVIA-v2, a deliberately vulnerable application designed for security training.*

*Report prepared by: Aadith | B.Tech Computer Science | Cybersecurity Researcher*
*Date: June 2025 | Version 1.1 — Added per-finding mitigation steps*

---
**END OF REPORT**