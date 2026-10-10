# Module 15 — Ransomware Simulation

## ⚠️ Important Context

Companies run ransomware simulations to:
- Test backup and recovery procedures
- Measure detection and response time
- Train incident response teams
- Validate EDR configurations

A simulation NEVER actually destroys files. It encrypts to a TEMP location
or uses a clearly-labelled test directory, and ALWAYS provides instant recovery.

---

## 1. How Real Ransomware Works

```
Phase 1: Initial Access
  Download via phishing / exploit / stolen RDP creds

Phase 2: Privilege Escalation
  Elevate to admin to encrypt system files and shadow copies

Phase 3: Defense Evasion
  Disable Windows Defender: "Set-MpPreference -DisableRealTimeMonitoring $true"
  Delete shadow copies: "vssadmin delete shadows /all /quiet"
  Clear event logs: "wevtutil cl System / Security / Application"

Phase 4: Discovery
  Enumerate network shares, mapped drives, backup targets

Phase 5: Encryption
  Enumerate files matching *.doc, *.xls, *.pdf, *.jpg, *.db etc.
  Generate random AES-256 key per file (or per session)
  Encrypt files in-place or to a temp location
  Encrypt the AES key with attacker's RSA public key
  Delete original with secure wipe (or just delete)
  Drop ransom note: README_DECRYPT.txt in every directory

Phase 6: Extortion
  Exfiltrate data first (double extortion model) — upload to attacker C2
  Display ransom demand
```

---

## 2. File Encryption Architecture

A good ransomware design uses:

```
Attacker generates: RSA-2048 key pair (public key embedded in binary, private key kept)

Per-session:        Random AES-256 session key generated on victim
                    Session key encrypted with attacker RSA public key → stored in ransom note

Per-file:           Random IV for AES-CBC or AES-GCM
                    File encrypted with session key + IV
                    IV stored in file header or alongside encrypted file

Recovery:
  Victim pays → attacker sends RSA private key
  Victim uses private key to decrypt session key → decrypt all files
```

**Why this matters:**
- Without the RSA private key, breaking AES-256 is computationally infeasible
- The per-file IV prevents pattern attacks (identical files encrypt differently)
- Attackers never need to store the AES key anywhere recoverable

---

## 3. Simulation — Safe Implementation Pattern

For a COMPANY-APPROVED simulation:

```cpp
// Safe simulation: operates ONLY on a dedicated test directory
// Never touches real user files
// Provides instant recovery button
// Logs every action for incident response training

const char* TEST_DIR = "C:\\RansomwareSimTest\\";  // created by user beforehand

struct SimConfig {
    bool  dryRun     = true;   // if true: log but don't encrypt
    bool  encrypt    = false;  // must be explicitly enabled
    bool  canRecover = true;   // always true in simulation
};

void simulateRansomware(const SimConfig& cfg) {
    // 1. Check test directory exists and contains "SIM_APPROVED.flag" sentinel
    if (!fileExists(std::string(TEST_DIR) + "SIM_APPROVED.flag")) {
        printf("[SIM] Safety check failed — SIM_APPROVED.flag not found in test dir\n");
        return;
    }

    // 2. Enumerate files in TEST_DIR
    for (const auto& entry : std::filesystem::recursive_directory_iterator(TEST_DIR)) {
        if (!entry.is_regular_file()) continue;
        printf("[SIM] Would encrypt: %s\n", entry.path().string().c_str());
        if (cfg.encrypt && !cfg.dryRun) {
            encryptFile(entry.path().string(), sessionKey);
        }
    }

    // 3. Drop simulated ransom note
    if (!cfg.dryRun) {
        std::ofstream note(std::string(TEST_DIR) + "README_DECRYPT.txt");
        note << "*** RANSOMWARE SIMULATION ***\n";
        note << "This is a company-authorised test. Your files are safe.\n";
        note << "Contact IT Security to recover your test files.\n";
    }
}
```

---

## 4. AES-256 File Encryption with Windows CNG

```cpp
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// Encrypt a buffer using AES-256-CBC
std::vector<BYTE> aesEncrypt(const std::vector<BYTE>& plaintext,
                              const BYTE key[32], const BYTE iv[16]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);

    // Get output size (rounds up to block size)
    ULONG cipherLen = 0;
    BYTE ivCopy[16];
    memcpy(ivCopy, iv, 16);
    BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                  nullptr, ivCopy, 16, nullptr, 0, &cipherLen, BCRYPT_BLOCK_PADDING);

    std::vector<BYTE> cipher(cipherLen);
    memcpy(ivCopy, iv, 16);
    BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                  nullptr, ivCopy, 16, cipher.data(), cipherLen, &cipherLen, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return cipher;
}
```

**CNG (Cryptography Next Generation)** is Microsoft's modern crypto API.
Prefer it over the older CryptoAPI (`CryptEncrypt` etc.).

---

## 5. Detection Signatures for Ransomware

As a defender, watch for:

| Behaviour | EDR Rule |
|-----------|----------|
| Mass file renames (add extension) | `FileRename` event rate > 10/second |
| Shadow copy deletion | `vssadmin` or WMI `Win32_ShadowCopy` Delete |
| Defender disabled via PowerShell | `Set-MpPreference` + `-Disable` flags |
| AES key generation (BCryptGenRandom) | `ProcessAccess` on bcrypt.dll |
| `CreateFile` + `WriteFile` + `DeleteFile` triple on same file | Encrypt-in-place pattern |

---

## Exercises

- `ex01_aes_encrypt_file.cpp` — encrypt/decrypt a single file with AES-256-CBC (CNG)
- `ex02_file_enumerator.cpp` — enumerate files by extension in a directory tree
- `ex03_ransomware_sim.cpp` — safe simulation using test directory + sentinel file
- `ex04_recovery_tool.cpp` — decrypt files encrypted by ex03 using stored key
