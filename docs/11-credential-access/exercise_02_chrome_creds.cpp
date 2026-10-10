/*
 * Exercise 02 — Chrome Saved Passwords
 * Module 11: Credential Access
 *
 * Task: Locate Chrome's Login Data SQLite file, copy it to a temp path
 * (Chrome holds an exclusive lock on the original while running), open the
 * copy, query saved logins, and DPAPI-decrypt each password blob.
 *
 * AUTHORIZED USE ONLY — run only against your own browser on your own machine.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o ex02.exe exercise_02_chrome_creds.cpp -ladvapi32 -lcrypt32
 *
 * External dependency:
 *   sqlite3.exe must be in PATH (download the precompiled binary from
 *   https://www.sqlite.org/download.html and place it on your PATH).
 *   Alternatively, add sqlite3.h + sqlite3.c (amalgamation) to your build
 *   and link them in — see the NOTE below.
 *
 * NOTE on Chrome 80+ encryption:
 *   Since Chrome 80, passwords are encrypted with AES-256-GCM using an
 *   "App-Bound" key that lives inside the browser process. Blobs whose first
 *   3 bytes are "v10" or "v11" use this scheme and cannot be decrypted with
 *   DPAPI alone. This exercise handles only the older DPAPI path; v10/v11
 *   blobs will be flagged as [ENCRYPTED — App-Bound key required].
 */

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// =========================================================================
// NOTE on SQLite:
//   We use popen("sqlite3.exe ...") to avoid shipping the full SQLite library.
//   If sqlite3.exe is not available you can alternatively:
//     1. Download the SQLite amalgamation (sqlite3.h + sqlite3.c) from
//        https://www.sqlite.org/download.html
//     2. Add both files to your build:
//          g++ ... exercise_02_chrome_creds.cpp sqlite3.c -ladvapi32 -lcrypt32
//     3. Replace QueryLoginData() with sqlite3_open / sqlite3_prepare /
//        sqlite3_step / sqlite3_finalize calls.
// =========================================================================

// ----------------------------------------------------------------------------
// Helper: return temp path for the copied database
// ----------------------------------------------------------------------------
std::string GetTempDbPath() {
    char tempDir[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, tempDir);
    return std::string(tempDir) + "chrome_login_copy.db";
}

// ----------------------------------------------------------------------------
// Helper: print bytes as hex
// ----------------------------------------------------------------------------
void PrintHex(const BYTE* data, DWORD len, DWORD maxBytes = 32) {
    DWORD show = (len < maxBytes) ? len : maxBytes;
    for (DWORD i = 0; i < show; i++) printf("%02X", data[i]);
    if (len > maxBytes) printf("...+%lu", len - maxBytes);
}

// ----------------------------------------------------------------------------
// Helper: hex string -> raw bytes (hex string has no spaces, even length)
// ----------------------------------------------------------------------------
std::vector<BYTE> HexToBytes(const std::string& hex) {
    std::vector<BYTE> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int b = 0;
        sscanf(hex.c_str() + i, "%02X", &b);
        out.push_back((BYTE)b);
    }
    return out;
}

// =========================================================================
// TODO 1 — Build the path to Chrome's Login Data file.
//
//   The file lives at:
//     %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
//
//   Steps:
//     a) Call SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buf)
//        where buf is a char[MAX_PATH].  Check return value (S_OK = 0).
//     b) Append  "\\Google\\Chrome\\User Data\\Default\\Login Data"  to buf.
//     c) Return the result as a std::string.
//
//   Return an empty string on failure.
// =========================================================================
std::string GetChromeLoginDataPath() {
    char localAppData[MAX_PATH] = {0};

    // >>> YOUR CODE FOR TODO 1 HERE <<<

    return ""; // replace this with the constructed path
}

// =========================================================================
// TODO 2 — Copy the Login Data file to a temporary location.
//
//   Chrome keeps the database open while it is running, so we must work on
//   a copy.
//
//   Steps:
//     a) Call CopyFileA(srcPath.c_str(), dstPath.c_str(), FALSE).
//        The third argument FALSE means "overwrite if destination exists".
//     b) If it fails, print the error from GetLastError() and return false.
//     c) Return true on success.
//
//   Error to watch for: ERROR_SHARING_VIOLATION (32) means Chrome has the
//   file open in a mode that prevents copying — close Chrome and retry.
// =========================================================================
bool CopyLoginDatabase(const std::string& srcPath, const std::string& dstPath) {

    // >>> YOUR CODE FOR TODO 2 HERE <<<

    return false; // replace with actual success/failure
}

// =========================================================================
// TODO 3 — Query the logins table via sqlite3.exe.
//
//   Build and run this command (using popen / _popen):
//     sqlite3.exe <dbPath> "SELECT origin_url,username_value,hex(password_value) FROM logins;"
//
//   Read all output lines. Each line is pipe-delimited:
//     https://example.com|username|AABBCC...  (hex of the password blob)
//
//   Return the lines in a vector<string>.  Return an empty vector on error.
//
//   Hint for popen usage:
//     FILE* fp = _popen(cmd.c_str(), "r");
//     if (!fp) { ... }
//     char line[4096];
//     while (fgets(line, sizeof(line), fp)) { ... }
//     _pclose(fp);
// =========================================================================
std::vector<std::string> QueryLoginData(const std::string& dbPath) {
    std::vector<std::string> rows;

    // >>> YOUR CODE FOR TODO 3 HERE <<<

    return rows;
}

// =========================================================================
// TODO 4 — Process one row: parse it, DPAPI-decrypt the password, print result.
//
//   Each row string has the format:  url|username|hexPasswordBlob
//
//   Steps:
//     a) Split the row on '|' to get url, username, hexPassword.
//        (Use std::string::find / substr, or std::istringstream with getline.)
//
//     b) Convert hexPassword to raw bytes using HexToBytes().
//
//     c) If the blob is empty, print the row with "[NO PASSWORD STORED]".
//
//     d) Check whether the first 3 bytes equal "v10" or "v11":
//          if (bytes.size() >= 3 &&
//              bytes[0]=='v' &&
//              (bytes[1]=='1') &&
//              (bytes[2]=='0' || bytes[2]=='1'))
//        If so, print "[ENCRYPTED — Chrome App-Bound key required]".
//
//     e) Otherwise, attempt DPAPI decryption:
//          DATA_BLOB blobIn  = { (DWORD)bytes.size(), bytes.data() };
//          DATA_BLOB blobOut = {0};
//          BOOL ok = CryptUnprotectData(&blobIn, NULL, NULL, NULL, NULL, 0, &blobOut);
//        On success print the decrypted password (as a string if printable,
//        else as hex). On failure print "[DPAPI FAILED: <error code>]".
//        Free blobOut.pbData with LocalFree after use.
//
//     f) Print: %-50s | %-25s | %s  (url | username | password result)
// =========================================================================
void ProcessRow(const std::string& row) {

    // >>> YOUR CODE FOR TODO 4 HERE <<<

    printf("TODO: process row: %s\n", row.c_str());
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int main() {
    printf("=== Exercise 02: Chrome Saved Passwords ===\n");
    printf("AUTHORIZED USE ONLY — your own machine, your own browser.\n\n");

    // Build source path
    std::string dbSrc = GetChromeLoginDataPath();
    if (dbSrc.empty()) {
        printf("[!] TODO 1 not implemented, or LOCALAPPDATA unavailable.\n");
        return 1;
    }
    printf("[*] Login Data path : %s\n", dbSrc.c_str());

    // Check the file exists
    if (GetFileAttributesA(dbSrc.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] File not found — Chrome may not be installed or no profile exists.\n");
        return 1;
    }

    // Copy to temp
    std::string dbTemp = GetTempDbPath();
    printf("[*] Copying to temp : %s\n\n", dbTemp.c_str());

    if (!CopyLoginDatabase(dbSrc, dbTemp)) {
        printf("[!] TODO 2 not implemented, or copy failed.\n");
        printf("    If Chrome is running, close it and retry.\n");
        return 1;
    }

    // Query
    auto rows = QueryLoginData(dbTemp);
    if (rows.empty()) {
        printf("[!] No rows returned (TODO 3 not implemented, or no saved logins).\n");
    } else {
        printf("%-50s | %-25s | %s\n", "URL", "Username", "Password");
        printf("%s\n", std::string(110, '-').c_str());
        for (auto& row : rows) {
            if (!row.empty()) ProcessRow(row);
        }
    }

    // Cleanup
    DeleteFileA(dbTemp.c_str());
    printf("\n[*] Temp file deleted.\n");
    return 0;
}
