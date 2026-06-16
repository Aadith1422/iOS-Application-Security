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
| **Report Version** | 1.0 |

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
| F-05: Weak Crypto (MD5/SHA-1) | Replace MD5 and SHA-1 with **SHA-256** or **SHA-3** for hashing. Use **AES-256-GCM** for symmetric encryption. |
| F-06: Sensitive Local Storage | Encrypt all local sensitive files using the iOS Data Protection API (`NSFileProtectionComplete`). Use Keychain for small secrets. |
| F-07: Endpoint Disclosure | Do not hardcode internal endpoint paths. Load configuration from a server-side configuration endpoint authenticated at runtime. |
| F-08: ATS Exception | Remove `NSAllowsArbitraryLoads` entirely. Enforce TLS 1.2+ for all connections. If specific domains require exceptions, use domain-specific ATS exceptions rather than a global bypass. |

### Low Priority (Backlog)

| Finding | Recommendation |
|---|---|
| F-09: Source Path Disclosure | Build the application with release/distribution settings that strip debug symbols and path information. Use `DEPLOYMENT_POSTPROCESSING = YES` and `STRIP_INSTALLED_PRODUCT = YES` in Xcode build settings. |
| F-10: Debug Logging | Disable `NSLog` and all debug logging in production builds. Use compile-time macros (`#if DEBUG`) to gate all log statements. Audit use of `traceExecution`. |

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
*Date: June 2025*

---
**END OF REPORT**
