# OWASP Mobile Application Security — iOS Focus
### Vulnerable vs. Secure Implementations Reference Guide

---

## Table of Contents

1. [OWASP Mobile AppSec Checklist — iOS Controls](#1-owasp-mobile-appsec-checklist--ios-controls)
2. [Vulnerability Categories Overview](#2-vulnerability-categories-overview)
3. [Insecure Data Storage](#3-insecure-data-storage)
4. [Insecure Communication](#4-insecure-communication)
5. [Authentication Flaws](#5-authentication-flaws)
6. [Weak Cryptographic Implementations](#6-weak-cryptographic-implementations)
7. [Additional iOS-Specific Vulnerabilities](#7-additional-ios-specific-vulnerabilities)
8. [Quick Reference: MASVS Mapping](#8-quick-reference-masvs-mapping)

---

## 1. OWASP Mobile AppSec Checklist — iOS Controls

OWASP's **Mobile Application Security Verification Standard (MASVS)** defines security requirements for mobile apps. The companion **Mobile Security Testing Guide (MSTG)** provides testing procedures.

### MASVS Security Levels

| Level | Name | Description |
|-------|------|-------------|
| L1 | Basic Security | Minimum baseline for all apps |
| L2 | Defense-in-Depth | Sensitive data apps (banking, health) |
| R | Resiliency | Apps requiring anti-tampering/reverse-engineering resistance |

### iOS-Specific MASVS Domains

| Domain | MASVS ID | Focus Area |
|--------|----------|------------|
| Architecture | MASVS-ARCH | Secure design, threat modeling |
| Storage | MASVS-STORAGE | Data-at-rest protection |
| Crypto | MASVS-CRYPTO | Key management, algorithms |
| Auth | MASVS-AUTH | Authentication, session management |
| Network | MASVS-NETWORK | TLS, certificate pinning |
| Platform | MASVS-PLATFORM | iOS API misuse, IPC security |
| Code Quality | MASVS-CODE | Secure coding, anti-debug |
| Resilience | MASVS-RESILIENCE | Jailbreak detection, obfuscation |

### Key iOS Platform Controls (Checklist)

- [ ] **Keychain usage** — Sensitive data stored in Keychain with appropriate `kSecAttrAccessible` flags
- [ ] **Data Protection API** — Files classified with `NSFileProtectionComplete` or stronger
- [ ] **ATS (App Transport Security)** — No `NSAllowsArbitraryLoads` in Info.plist
- [ ] **Certificate/Public Key Pinning** — Remote endpoints validated against pinned certs
- [ ] **Biometric Auth** — LocalAuthentication used correctly; fallback not bypassable
- [ ] **Clipboard Protection** — Sensitive fields set `UIPasteboardName` restrictions
- [ ] **Screenshot Prevention** — Sensitive screens blur on app backgrounding
- [ ] **Jailbreak Detection** — Runtime checks for jailbreak indicators
- [ ] **Anti-Debug** — `PT_DENY_ATTACH` or equivalent applied
- [ ] **Binary Protections** — PIE, stack canaries, ARC enabled in build settings
- [ ] **No hardcoded secrets** — No API keys, passwords, or tokens in source
- [ ] **Secure IPC** — URL scheme and Universal Link handlers validate input
- [ ] **Memory management** — Sensitive data zeroed from memory after use

---

## 2. Vulnerability Categories Overview

```
┌─────────────────────────────────────────────────────────┐
│              OWASP Mobile Top 10 (2024)                  │
├─────────────────────────────────────────────────────────┤
│  M1  │ Improper Credential Usage                         │
│  M2  │ Inadequate Supply Chain Security                  │
│  M3  │ Insecure Authentication / Authorization           │
│  M4  │ Insufficient Input/Output Validation              │
│  M5  │ Insecure Communication                            │
│  M6  │ Inadequate Privacy Controls                       │
│  M7  │ Insufficient Binary Protections                   │
│  M8  │ Security Misconfiguration                         │
│  M9  │ Insecure Data Storage                             │
│  M10 │ Insufficient Cryptography                         │
└─────────────────────────────────────────────────────────┘
```

This document focuses on the four most exploited categories in real-world iOS assessments:
- **Insecure Data Storage** (M9)
- **Insecure Communication** (M5)
- **Authentication Flaws** (M3)
- **Weak Cryptographic Implementations** (M10)

---

## 3. Insecure Data Storage

### Overview

iOS provides multiple storage mechanisms. Each has different security properties and must be used appropriately.

| Storage Location | Backed Up? | Encrypted? | Risk Level |
|-----------------|------------|------------|------------|
| NSUserDefaults | ✅ Yes | ❌ No | High for secrets |
| SQLite (default) | ✅ Yes | ❌ No | High |
| Keychain | ✅ Yes (encrypted) | ✅ Yes | Low (if configured correctly) |
| Files (NSFileProtectionNone) | ✅ Yes | ❌ No | High |
| Files (NSFileProtectionComplete) | ✅ Yes | ✅ Yes (when locked) | Low |
| CoreData (no encryption) | ✅ Yes | ❌ No | High |

---

### 3.1 NSUserDefaults Misuse

**Vulnerability:** Storing sensitive data in `NSUserDefaults`. This data is stored in a plaintext `.plist` file accessible on jailbroken devices and in iTunes/iCloud backups.

#### ❌ Vulnerable Implementation (Swift)

```swift
// INSECURE: Storing credentials in UserDefaults
class LoginManager {
    func saveCredentials(username: String, password: String, authToken: String) {
        let defaults = UserDefaults.standard
        defaults.set(username, forKey: "username")
        defaults.set(password, forKey: "userPassword")      // ← CRITICAL: plaintext password
        defaults.set(authToken, forKey: "authToken")        // ← CRITICAL: plaintext token
        defaults.set(true, forKey: "isLoggedIn")
        defaults.synchronize()
    }
    
    func getAuthToken() -> String? {
        return UserDefaults.standard.string(forKey: "authToken")
    }
}
```

**Why it's vulnerable:**
- Data stored at: `~/Library/Preferences/<bundle_id>.plist`
- Readable with `plutil` or any plist viewer on jailbroken device
- Included in unencrypted iTunes backups
- No access control — any process can read shared defaults

---

#### ✅ Secure Implementation (Swift)

```swift
import Security

class SecureCredentialManager {
    
    enum KeychainError: Error {
        case duplicateItem
        case itemNotFound
        case unexpectedStatus(OSStatus)
    }
    
    // Store sensitive data in Keychain with strong access control
    func saveToken(_ token: String, forKey key: String) throws {
        guard let tokenData = token.data(using: .utf8) else { return }
        
        // Delete existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.myapp.auth",
            kSecAttrAccount as String: key
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // Add new item with strict access control
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,   // ← NOT synced to iCloud
            .userPresence,                                   // ← Requires biometric/passcode
            nil
        )
        
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.myapp.auth",
            kSecAttrAccount as String: key,
            kSecValueData as String: tokenData,
            kSecAttrAccessControl as String: accessControl as Any,
            kSecUseAuthenticationContext as String: LAContext()
        ]
        
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    func retrieveToken(forKey key: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.myapp.auth",
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            throw KeychainError.itemNotFound
        }
        return token
    }
}
```

**Key security controls:**
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — not synced to iCloud, only accessible when unlocked
- `SecAccessControlCreateWithFlags` with `.userPresence` — requires biometric or passcode
- Item deleted before re-adding to prevent duplicates leaking old values

---

### 3.2 Plaintext SQLite / CoreData

#### ❌ Vulnerable Implementation

```swift
// INSECURE: Storing sensitive data in unencrypted CoreData
class PatientDataManager {
    func savePatientRecord(name: String, diagnosis: String, ssn: String) {
        let context = persistentContainer.viewContext
        let record = PatientRecord(context: context)
        record.fullName = name
        record.diagnosis = diagnosis
        record.socialSecurityNumber = ssn      // ← Stored plaintext in .sqlite file
        record.creditCardNumber = "4111-1111-1111-1111"  // ← PII in cleartext
        
        try? context.save()
        // File lives at: ~/Library/Application Support/<app>/app.sqlite
        // Fully readable with any SQLite browser on jailbroken device
    }
}
```

---

#### ✅ Secure Implementation

```swift
// SECURE: Encrypt sensitive fields before storage using CryptoKit
import CryptoKit

class SecurePatientDataManager {
    private let encryptionKey: SymmetricKey
    
    init() {
        // Retrieve or generate encryption key from Keychain
        self.encryptionKey = SecurePatientDataManager.getOrCreateKey()
    }
    
    private static func getOrCreateKey() -> SymmetricKey {
        // Key stored in Keychain — see Section 6 for full implementation
        return SymmetricKey(size: .bits256)
    }
    
    func encryptField(_ plaintext: String) throws -> Data {
        let data = Data(plaintext.utf8)
        let sealedBox = try AES.GCM.seal(data, using: encryptionKey)
        return sealedBox.combined!
    }
    
    func decryptField(_ ciphertext: Data) throws -> String {
        let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
        let decryptedData = try AES.GCM.open(sealedBox, using: encryptionKey)
        return String(data: decryptedData, encoding: .utf8)!
    }
    
    func savePatientRecord(name: String, diagnosis: String, ssn: String) throws {
        let context = persistentContainer.viewContext
        let record = PatientRecord(context: context)
        record.fullName = name                                      // Non-sensitive: OK
        record.encryptedDiagnosis = try encryptField(diagnosis)    // ← Encrypted at rest
        record.encryptedSSN = try encryptField(ssn)                // ← Encrypted at rest
        
        // Also enable file-level protection on the store
        let storeURL = persistentContainer.persistentStoreDescriptions.first!.url!
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: storeURL.path
        )
        
        try context.save()
    }
}
```

---

### 3.3 Logging Sensitive Data

#### ❌ Vulnerable Implementation

```swift
// INSECURE: Logging sensitive data visible in Console.app and crash reports
func processPayment(cardNumber: String, cvv: String, amount: Double) {
    print("Processing payment for card: \(cardNumber), CVV: \(cvv)")   // ← In system logs
    NSLog("Payment amount: $\(amount) for user token: \(authToken)")   // ← Persistent logs
    os_log("Card last 4: %@, Amount: %f", cardNumber.suffix(4), amount)
    
    // Any connected Mac running Console.app can read this in real-time
}
```

#### ✅ Secure Implementation

```swift
import os.log

// SECURE: Redact sensitive values in logs using OSLog privacy
let paymentLogger = Logger(subsystem: "com.myapp", category: "payments")

func processPayment(cardNumber: String, cvv: String, amount: Double) {
    // Mark sensitive values as private — redacted in logs unless debugging
    paymentLogger.info("Processing payment: card ending \(cardNumber.suffix(4), privacy: .public), amount \(amount, privacy: .sensitive)")
    
    // CVV should NEVER be logged, even redacted
    // paymentLogger.debug("CVV: \(cvv)")   ← Never do this
    
    // Use .private for PII (shown as <private> in production logs)
    paymentLogger.debug("User ID: \(userID, privacy: .private)")
}
```

---

## 4. Insecure Communication

### Overview

iOS enforces App Transport Security (ATS) by default, but developers often disable it. Insecure communication vulnerabilities allow network interception via MITM attacks.

---

### 4.1 ATS Disabled / HTTP Traffic

#### ❌ Vulnerable Info.plist

```xml
<!-- INSECURE: Completely disabling ATS -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- This single key disables ALL transport security -->
    <key>NSAllowsArbitraryLoads</key>
    <true/>
    
    <!-- Allows HTTP (plaintext) connections to ANY domain -->
    <!-- All traffic is unencrypted and interceptable -->
</dict>
```

```swift
// INSECURE: Explicit HTTP request
let url = URL(string: "http://api.mybank.com/v1/transfer")!  // ← HTTP, not HTTPS
var request = URLRequest(url: url)
request.httpMethod = "POST"
request.httpBody = try? JSONEncoder().encode(transferData)   // ← Sent in plaintext

URLSession.shared.dataTask(with: request) { data, response, error in
    // Response also in plaintext
}.resume()
```

---

#### ✅ Secure Info.plist

```xml
<!-- SECURE: ATS enabled with strict settings -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Only allow specific exceptions if absolutely required -->
    <key>NSExceptionDomains</key>
    <dict>
        <!-- Example: Only allow specific legacy domain with documented justification -->
        <key>legacy-api.internal.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.3</string>
        </dict>
    </dict>
    <!-- NSAllowsArbitraryLoads intentionally omitted (defaults to false) -->
</dict>
```

```swift
// SECURE: HTTPS with certificate pinning
let url = URL(string: "https://api.mybank.com/v1/transfer")!
var request = URLRequest(url: url)
request.httpMethod = "POST"

// Configure session with pinning delegate
let session = URLSession(
    configuration: .default,
    delegate: CertificatePinningDelegate(),
    delegateQueue: nil
)

session.dataTask(with: request) { data, response, error in
    guard let httpResponse = response as? HTTPURLResponse,
          httpResponse.statusCode == 200 else { return }
    // Handle response
}.resume()
```

---

### 4.2 Certificate Pinning

#### ❌ Vulnerable Implementation (No Pinning)

```swift
// INSECURE: Accepting any certificate — MITM trivially possible
class InsecureNetworkManager: NSObject, URLSessionDelegate {
    
    // This delegate method should NEVER be implemented like this
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // ← CRITICAL FLAW: Accepting ALL certificates without validation
        let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, credential)
        
        // An attacker with a self-signed cert can now MITM all traffic
    }
}
```

---

#### ✅ Secure Implementation (Public Key Pinning)

```swift
import CommonCrypto

// SECURE: Public Key Pinning — more flexible than cert pinning (survives cert rotation)
class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    
    // SHA-256 hash of the server's SubjectPublicKeyInfo
    // Generate with: openssl s_client -connect api.mybank.com:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
    private let pinnedPublicKeyHashes: Set<String> = [
        "abc123def456...",    // Primary certificate
        "backup789ghi...",    // Backup certificate (for rotation)
    ]
    
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 1: Validate the certificate chain normally first
        var secResult = SecTrustResultType.invalid
        SecTrustEvaluate(serverTrust, &secResult)
        guard secResult == .unspecified || secResult == .proceed else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 2: Extract and hash the server's public key
        guard let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0),
              let serverPublicKey = SecCertificateCopyKey(serverCert),
              let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 3: Add the ASN.1 header for RSA-2048/EC public key (required for proper SPKI hash)
        let rsa2048Header: [UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        ]
        var spkiData = Data(rsa2048Header)
        spkiData.append(serverPublicKeyData)
        
        // Step 4: SHA-256 hash and Base64 encode
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        spkiData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(spkiData.count), &hash)
        }
        let serverKeyHash = Data(hash).base64EncodedString()
        
        // Step 5: Compare against pinned hashes
        if pinnedPublicKeyHashes.contains(serverKeyHash) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            // Pin mismatch — possible MITM attack
            completionHandler(.cancelAuthenticationChallenge, nil)
            // Alert security team / log to SIEM
            SecurityEventLogger.log(event: .pinMismatch, domain: challenge.protectionSpace.host)
        }
    }
}
```

---

## 5. Authentication Flaws

### Overview

Authentication vulnerabilities on iOS include insecure biometric implementation, bypassable local auth, broken session management, and improper token storage.

---

### 5.1 Broken Local Authentication (Biometrics)

#### ❌ Vulnerable Implementation

```swift
import LocalAuthentication

// INSECURE: Client-side only authentication decision
class InsecureAuthManager {
    
    var isAuthenticated = false  // ← Local boolean, trivially patchable
    
    func authenticateWithBiometrics(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Login to your account"
            ) { success, error in
                DispatchQueue.main.async {
                    if success {
                        self.isAuthenticated = true   // ← Set local flag only
                        completion(true)
                        // No server-side token validation
                        // Patching isAuthenticated to true bypasses ALL auth
                    } else {
                        completion(false)
                    }
                }
            }
        }
    }
    
    func accessSensitiveData() {
        guard isAuthenticated else { return }  // ← Trivially bypassed on jailbroken device
        // Show sensitive data...
    }
}
```

**Attack vector:** On a jailbroken device, attacker patches `isAuthenticated` to `true` using a Frida script in seconds.

---

#### ✅ Secure Implementation

```swift
import LocalAuthentication
import Security
import CryptoKit

// SECURE: Biometrics gate a Keychain-protected private key
// Authentication happens cryptographically, not as a boolean flag
class SecureAuthManager {
    
    private let keyTag = "com.myapp.biometric.privatekey"
    
    // Step 1: Generate key pair at enrollment — private key is biometric-protected
    func enrollBiometrics() throws {
        // Access control: private key only accessible after biometric success
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .privateKeyUsage],  // .biometryCurrentSet: invalidated if biometrics change
            nil
        )!
        
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,  // ← Hardware-backed in Secure Enclave
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: accessControl
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) != nil else {
            throw error!.takeRetainedValue()
        }
        
        // Get public key and register with server
        let publicKey = try getPublicKey()
        try registerPublicKeyWithServer(publicKey)
    }
    
    // Step 2: Authentication — sign a server-issued challenge with biometric-protected key
    func authenticate(serverChallenge: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        let context = LAContext()
        context.localizedReason = "Sign in to MyBank"
        
        // Retrieve private key — this triggers biometric prompt
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: keyTag,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
        
        guard status == errSecSuccess, let privateKey = keyRef as! SecKey? else {
            completion(.failure(AuthError.keyNotFound))
            return
        }
        
        // Sign the challenge with the Secure Enclave key
        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            serverChallenge as CFData,
            &signError
        ) else {
            completion(.failure(signError!.takeRetainedValue()))
            return
        }
        
        // Send signature to server for verification
        // Server verifies: if signature valid → session token issued
        completion(.success(signature as Data))
    }
    
    // Step 3: Server verifies signature against registered public key
    // No local boolean flag — auth state is entirely server-validated
}
```

---

### 5.2 Insecure Session Token Storage & Expiry

#### ❌ Vulnerable Implementation

```swift
// INSECURE: Multiple session management flaws
class InsecureSessionManager {
    
    // Flaw 1: Token stored in UserDefaults (see Section 3)
    func saveToken(_ token: String) {
        UserDefaults.standard.set(token, forKey: "session_token")
    }
    
    // Flaw 2: Token never expires
    func isSessionValid() -> Bool {
        return UserDefaults.standard.string(forKey: "session_token") != nil
        // No expiry check, no revocation check
    }
    
    // Flaw 3: Token not cleared on logout
    func logout() {
        // Forgot to clear token!
        navigateToLogin()
    }
    
    // Flaw 4: Token sent in URL parameters (logged in server access logs)
    func makeAuthenticatedRequest() {
        let token = UserDefaults.standard.string(forKey: "session_token")!
        let url = URL(string: "https://api.example.com/data?token=\(token)")!
        URLSession.shared.dataTask(with: url).resume()
    }
}
```

---

#### ✅ Secure Implementation

```swift
// SECURE: Proper session lifecycle management
class SecureSessionManager {
    
    private let tokenKey = "com.myapp.session.token"
    private let tokenExpiryKey = "com.myapp.session.expiry"
    private let maxSessionDuration: TimeInterval = 3600  // 1 hour
    
    func saveToken(_ token: String) throws {
        // Store in Keychain with expiry metadata
        let expiry = Date().addingTimeInterval(maxSessionDuration)
        let sessionData: [String: Any] = [
            "token": token,
            "expiry": expiry.timeIntervalSince1970,
            "deviceID": UIDevice.current.identifierForVendor!.uuidString
        ]
        let data = try JSONSerialization.data(withJSONObject: sessionData)
        try KeychainManager.shared.save(data: data, forKey: tokenKey)
    }
    
    func getValidToken() throws -> String? {
        guard let data = try KeychainManager.shared.load(forKey: tokenKey),
              let session = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = session["token"] as? String,
              let expiryTimestamp = session["expiry"] as? TimeInterval else {
            return nil
        }
        
        // Check expiry
        let expiry = Date(timeIntervalSince1970: expiryTimestamp)
        guard Date() < expiry else {
            try? clearSession()  // Auto-clear expired session
            return nil
        }
        
        return token
    }
    
    func makeAuthenticatedRequest(to url: URL) throws -> URLRequest {
        guard let token = try getValidToken() else {
            throw AuthError.sessionExpired
        }
        
        var request = URLRequest(url: url)
        // Send token in Authorization header, NOT URL parameters
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return request
    }
    
    func logout() throws {
        // Securely clear all session data
        try KeychainManager.shared.delete(forKey: tokenKey)
        
        // Clear sensitive data from memory
        URLSession.shared.configuration.urlCache?.removeAllCachedResponses()
        HTTPCookieStorage.shared.removeCookies(since: Date.distantPast)
        
        // Notify server to invalidate server-side session
        Task {
            try await APIClient.shared.revokeToken()
        }
    }
}
```

---

## 6. Weak Cryptographic Implementations

### Overview

Cryptographic weaknesses in iOS apps typically involve outdated algorithms, hardcoded keys, improper IV/nonce reuse, or using encryption where authenticated encryption is required.

---

### 6.1 Broken / Outdated Algorithms

#### ❌ Vulnerable Implementation

```swift
import CommonCrypto

// INSECURE: Using MD5 for password hashing — broken for decades
func hashPassword(_ password: String) -> String {
    let data = Data(password.utf8)
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
    return digest.map { String(format: "%02x", $0) }.joined()
    // MD5 cracks in milliseconds on modern hardware
    // No salt = rainbow table attack trivial
}

// INSECURE: DES encryption (56-bit key, broken since 1999)
func encryptWithDES(data: Data, key: Data) -> Data? {
    var outputBytes = [UInt8](repeating: 0, count: data.count + kCCBlockSizeDES)
    var outputLength = 0
    
    CCCrypt(CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmDES),     // ← DES: 56-bit, crackable in hours
            CCOptions(kCCOptionECBMode),       // ← ECB mode: patterns visible in ciphertext
            (key as NSData).bytes, kCCKeySizeDES,
            nil,                              // ← No IV in ECB mode
            (data as NSData).bytes, data.count,
            &outputBytes, outputBytes.count, &outputLength)
    
    return Data(bytes: outputBytes, count: outputLength)
}
```

---

#### ✅ Secure Implementation

```swift
import CryptoKit

// SECURE: Argon2 / PBKDF2 for password hashing with salt
func hashPassword(_ password: String, salt: Data? = nil) throws -> (hash: Data, salt: Data) {
    // Generate cryptographically random salt
    let saltData = salt ?? Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    
    // PBKDF2-SHA256 with high iteration count (minimum 100,000 for 2024)
    var derivedKey = [UInt8](repeating: 0, count: 32)
    let result = saltData.withUnsafeBytes { saltBytes in
        password.withCString { passwordBytes in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                passwordBytes, password.utf8.count,
                saltBytes.baseAddress, saltData.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                310_000,            // ← OWASP 2024 minimum: 210,000 for PBKDF2-SHA256; use 310k for margin
                &derivedKey, derivedKey.count
            )
        }
    }
    
    guard result == kCCSuccess else { throw CryptoError.derivationFailed }
    return (Data(derivedKey), saltData)
}

// SECURE: AES-256-GCM — authenticated encryption (confidentiality + integrity)
func encryptData(_ plaintext: Data, using key: SymmetricKey) throws -> Data {
    // AES-GCM generates a random 96-bit nonce automatically
    let sealedBox = try AES.GCM.seal(plaintext, using: key)
    // sealedBox.combined = nonce (12B) + ciphertext + authentication tag (16B)
    return sealedBox.combined!
    // If authentication tag is tampered, decryption FAILS — data integrity guaranteed
}

func decryptData(_ ciphertext: Data, using key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
    return try AES.GCM.open(sealedBox, using: key)
    // Will throw if ciphertext OR auth tag is modified
}
```

---

### 6.2 Hardcoded Cryptographic Keys

#### ❌ Vulnerable Implementation

```swift
// INSECURE: Hardcoded key visible to anyone who reverse-engineers the binary
class InsecureCrypto {
    
    // ← Extractable with `strings` command or Hopper/Ghidra in 30 seconds
    private let encryptionKey = "MySecretKey12345678901234567890!!"
    private let apiKey = "sk-prod-abcdef1234567890abcdef1234567890"
    private let privateKeyPEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHABEqDJBf8B2p0sZW3t84...
    -----END RSA PRIVATE KEY-----
    """
    
    func encrypt(_ data: Data) -> Data? {
        let keyData = encryptionKey.data(using: .utf8)!  // Static key
        // Same key for all users, all time
        return try? encryptData(data, using: SymmetricKey(data: keyData))
    }
}
```

---

#### ✅ Secure Implementation

```swift
import CryptoKit

// SECURE: Keys generated, never hardcoded; stored in Secure Enclave
class SecureKeyManager {
    
    private let masterKeyTag = "com.myapp.crypto.masterkey"
    
    // Generate a new encryption key and store it in the Secure Enclave
    func generateAndStoreMasterKey() throws {
        // Check if key already exists
        if (try? loadMasterKey()) != nil { return }
        
        // Generate 256-bit symmetric key
        let key = SymmetricKey(size: .bits256)
        
        // Store in Keychain with hardware-backed protection
        let keyData = key.withUnsafeBytes { Data($0) }
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeAES,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationTag as String: masterKeyTag,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave  // Hardware-backed
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw CryptoError.keyStorageFailed(status)
        }
    }
    
    func loadMasterKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: masterKeyTag,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let keyData = result as? Data else {
            throw CryptoError.keyNotFound
        }
        
        return SymmetricKey(data: keyData)
    }
    
    // API keys: retrieve from server at runtime, store in Keychain
    func refreshAPIKey() async throws {
        let serverToken = try await authService.getAPIKey()  // Fetched at runtime
        try KeychainManager.shared.save(serverToken, forKey: "api_key")
        // Never compiled into binary
    }
}
```

---

### 6.3 IV/Nonce Reuse

#### ❌ Vulnerable Implementation

```swift
// INSECURE: Reusing IV destroys confidentiality in CBC mode
class InsecureCBCEncryption {
    
    private let key = Data(repeating: 0x42, count: 32)       // Hardcoded key
    private let iv = Data(repeating: 0x00, count: 16)        // ← Static IV: catastrophic
    
    func encrypt(_ data: Data) -> Data {
        var result = Data(count: data.count + kCCBlockSizeAES128)
        var resultLength = 0
        
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                (key as NSData).bytes, key.count,
                (iv as NSData).bytes,           // ← Same IV every call
                (data as NSData).bytes, data.count,
                result.mutableBytes, result.count, &resultLength)
        
        // With static IV + CBC: encrypting same plaintext → same ciphertext
        // Attacker can detect patterns, XOR ciphertexts to recover plaintexts
        return result.prefix(resultLength)
    }
}
```

---

#### ✅ Secure Implementation

```swift
import CryptoKit

// SECURE: AES-GCM auto-generates a random 96-bit nonce per operation
class SecureEncryption {
    
    func encrypt(_ plaintext: Data, using key: SymmetricKey) throws -> EncryptedPayload {
        // CryptoKit generates a random nonce automatically — never reused
        let nonce = AES.GCM.Nonce()  // 96-bit random nonce
        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        
        return EncryptedPayload(
            nonce: Data(nonce),               // Store nonce alongside ciphertext
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag               // Authentication tag
        )
    }
    
    func decrypt(_ payload: EncryptedPayload, using key: SymmetricKey) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: payload.nonce)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: payload.ciphertext,
            tag: payload.tag
        )
        return try AES.GCM.open(sealedBox, using: key)
    }
}

struct EncryptedPayload: Codable {
    let nonce: Data        // Sent alongside ciphertext — not secret, must be unique
    let ciphertext: Data
    let tag: Data
}
```

---

## 7. Additional iOS-Specific Vulnerabilities

### 7.1 Clipboard Data Leakage

#### ❌ Vulnerable
```swift
// Password field whose content is copied to system clipboard
// Any app with background access can read UIPasteboard.general
let passwordField = UITextField()
passwordField.isSecureTextEntry = true
// isSecureTextEntry doesn't prevent copy — users can still long-press and copy
// Banking apps, password managers, etc. should prevent clipboard entirely
```

#### ✅ Secure
```swift
class SecureTextField: UITextField {
    // Prevent copy/paste operations on sensitive fields
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        let sensitiveActions: [Selector] = [
            #selector(copy(_:)),
            #selector(cut(_:)),
            #selector(paste(_:)),
            #selector(select(_:)),
            #selector(selectAll(_:))
        ]
        if sensitiveActions.contains(action) { return false }
        return super.canPerformAction(action, withSender: sender)
    }
}
```

---

### 7.2 Backgrounding Screenshot Leakage

#### ❌ Vulnerable
```swift
// App screenshot captured when user presses Home button — visible in App Switcher
// iOS saves a screenshot in ~/Library/Caches/Snapshots/ — readable on jailbroken devices
class SensitiveViewController: UIViewController {
    // No background protection = banking screen screenshot stored on disk
}
```

#### ✅ Secure
```swift
class SensitiveViewController: UIViewController {
    
    private var blurView: UIVisualEffectView?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Observe app lifecycle
        NotificationCenter.default.addObserver(self, selector: #selector(appWillResignActive),
                                               name: UIApplication.willResignActiveNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(appDidBecomeActive),
                                               name: UIApplication.didBecomeActiveNotification, object: nil)
    }
    
    @objc private func appWillResignActive() {
        // Cover sensitive content before screenshot is taken
        let blur = UIVisualEffectView(effect: UIBlurEffect(style: .dark))
        blur.frame = view.bounds
        blur.tag = 999
        view.addSubview(blur)
        blurView = blur
    }
    
    @objc private func appDidBecomeActive() {
        blurView?.removeFromSuperview()
        blurView = nil
    }
}
```

---

### 7.3 Jailbreak Detection

#### ✅ Defense-in-Depth Detection (Not foolproof — use as one layer)

```swift
class JailbreakDetector {
    
    static func isDeviceJailbroken() -> Bool {
        return checkFileSystem() || checkURLSchemes() || checkWriteAccess() || checkDynamicLibraries()
    }
    
    private static func checkFileSystem() -> Bool {
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
            "/private/var/lib/apt/"
        ]
        return jailbreakPaths.contains { FileManager.default.fileExists(atPath: $0) }
    }
    
    private static func checkURLSchemes() -> Bool {
        return UIApplication.shared.canOpenURL(URL(string: "cydia://")!)
    }
    
    private static func checkWriteAccess() -> Bool {
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true  // Was able to write outside sandbox
        } catch {
            return false
        }
    }
    
    private static func checkDynamicLibraries() -> Bool {
        let suspiciousLibs = ["substrate", "cycript", "FridaGadget"]
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName).lowercased()
                if suspiciousLibs.contains(where: { name.contains($0) }) { return true }
            }
        }
        return false
    }
}
```

---

## 8. Quick Reference: MASVS Mapping

| Vulnerability | MASVS ID | OWASP Mobile Top 10 | Severity |
|---------------|----------|---------------------|----------|
| NSUserDefaults for secrets | MASVS-STORAGE-1 | M9 | 🔴 Critical |
| Plaintext SQLite/CoreData | MASVS-STORAGE-1 | M9 | 🔴 Critical |
| Sensitive data in logs | MASVS-STORAGE-2 | M9 | 🟠 High |
| ATS disabled (HTTP) | MASVS-NETWORK-1 | M5 | 🔴 Critical |
| No certificate pinning | MASVS-NETWORK-2 | M5 | 🟠 High |
| Client-only biometric auth | MASVS-AUTH-1 | M3 | 🔴 Critical |
| Token never expires | MASVS-AUTH-2 | M3 | 🟠 High |
| MD5/SHA1 for passwords | MASVS-CRYPTO-1 | M10 | 🔴 Critical |
| Hardcoded crypto keys | MASVS-CRYPTO-2 | M10 | 🔴 Critical |
| DES/RC4/ECB usage | MASVS-CRYPTO-1 | M10 | 🔴 Critical |
| Static IV in CBC | MASVS-CRYPTO-1 | M10 | 🔴 Critical |
| Clipboard leakage | MASVS-PLATFORM-4 | M6 | 🟡 Medium |
| Screenshot on background | MASVS-STORAGE-2 | M6 | 🟡 Medium |

---

### Recommended Tools for iOS Security Testing

| Tool | Purpose |
|------|---------|
| **Frida** | Dynamic instrumentation, runtime hooking |
| **objection** | Runtime mobile exploration (built on Frida) |
| **Burp Suite** | Intercepting HTTP/S proxy |
| **MobSF** | Automated static + dynamic analysis |
| **Ghidra / IDA Pro** | Binary reverse engineering |
| **iProxy / SSH** | On-device exploration via jailbreak |
| **Keychain-Dumper** | Extract Keychain items on jailbroken device |
| **Needle** | iOS security testing framework |
| **class-dump** | Extract Objective-C class headers from binary |

---

### References

- [OWASP MASVS](https://mas.owasp.org/MASVS/) — Mobile Application Security Verification Standard
- [OWASP MASTG](https://mas.owasp.org/MASTG/) — Mobile Application Security Testing Guide
- [Apple Security Guide](https://support.apple.com/en-gb/guide/security/welcome/web) — iOS Platform Security
- [Apple Secure Coding Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/) — Developer guidance
- [CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit) — Apple's modern crypto framework
- [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/)

---

*Document prepared for SOC Analyst / Mobile Security Assessment study — OWASP MASVS v2.x aligned*
