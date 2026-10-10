/*
 * Solution 01 — DPAPI Encrypt / Decrypt (Complete)
 * Module 11: Credential Access
 *
 * Implements three modes:
 *   sol01.exe encrypt <plaintext>   — DPAPI-encrypt the string, print base64 blob
 *   sol01.exe decrypt <base64blob>  — base64-decode the blob, DPAPI-decrypt, print
 *   sol01.exe test                  — self-test: encrypt "secret123", decrypt, verify
 *
 * Base64 is implemented inline (standard RFC 4648 table, no external library).
 * dwFlags = 0  →  current-user scope (must run as the encrypting user to decrypt).
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o sol01.exe sol01_dpapi.cpp -ladvapi32 -lcrypt32
 */

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// Base64 (RFC 4648) — no external library
// ============================================================================

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int B64_INV[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0x00-0x0F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0x10-0x1F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63, // 0x20-0x2F  (+ /)
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1, // 0x30-0x3F  (0-9, = as -2)
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 0x40-0x4F  (A-O)
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, // 0x50-0x5F  (P-Z)
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // 0x60-0x6F  (a-o)
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1, // 0x70-0x7F  (p-z)
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

std::string Base64Encode(const BYTE* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned int b = (unsigned int)data[i] << 16;
        if (i + 1 < len) b |= (unsigned int)data[i+1] << 8;
        if (i + 2 < len) b |= (unsigned int)data[i+2];
        out += B64_TABLE[(b >> 18) & 0x3F];
        out += B64_TABLE[(b >> 12) & 0x3F];
        out += (i + 1 < len) ? B64_TABLE[(b >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? B64_TABLE[(b     ) & 0x3F] : '=';
    }
    return out;
}

std::vector<BYTE> Base64Decode(const std::string& b64) {
    std::vector<BYTE> out;
    out.reserve((b64.size() / 4) * 3);
    int buf = 0, bits = 0;
    for (unsigned char c : b64) {
        int v = B64_INV[c];
        if (v == -1) continue; // skip whitespace / unknown
        if (v == -2) break;    // padding '='
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((BYTE)(buf >> bits));
            buf &= (1 << bits) - 1;
        }
    }
    return out;
}

// ============================================================================
// DPAPI helpers
// ============================================================================

// Encrypt plaintext bytes → base64 string.
// Returns empty string and prints error on failure.
std::string DPAPIEncrypt(const std::string& plaintext) {
    DATA_BLOB blobIn, blobOut;
    blobIn.pbData = (BYTE*)plaintext.data();
    blobIn.cbData = (DWORD)plaintext.size();
    blobOut        = {0};

    // dwFlags = 0 → user-scope (same user must decrypt)
    BOOL ok = CryptProtectData(
        &blobIn,
        L"sol01-dpapi",  // optional label stored in the blob
        NULL,            // no extra entropy
        NULL,            // reserved
        NULL,            // no UI prompt
        0,               // dwFlags
        &blobOut
    );

    if (!ok) {
        fprintf(stderr, "[!] CryptProtectData failed: %lu\n", GetLastError());
        return "";
    }

    std::string b64 = Base64Encode(blobOut.pbData, blobOut.cbData);
    LocalFree(blobOut.pbData);
    return b64;
}

// Decrypt base64 blob → plaintext string.
// Returns empty string and prints error on failure.
std::string DPAPIDecrypt(const std::string& b64blob) {
    std::vector<BYTE> raw = Base64Decode(b64blob);
    if (raw.empty()) {
        fprintf(stderr, "[!] Base64 decode produced no bytes.\n");
        return "";
    }

    DATA_BLOB blobIn, blobOut;
    blobIn.pbData = raw.data();
    blobIn.cbData = (DWORD)raw.size();
    blobOut        = {0};

    LPWSTR pDescription = NULL;

    BOOL ok = CryptUnprotectData(
        &blobIn,
        &pDescription,  // receives optional label
        NULL,           // no extra entropy
        NULL,           // reserved
        NULL,           // no UI prompt
        0,              // dwFlags: 0 = user scope
        &blobOut
    );

    if (!ok) {
        fprintf(stderr, "[!] CryptUnprotectData failed: %lu\n", GetLastError());
        if (pDescription) LocalFree(pDescription);
        return "";
    }

    // Print the description if present
    if (pDescription && wcslen(pDescription) > 0) {
        wprintf(L"    Description : %s\n", pDescription);
        LocalFree(pDescription);
    }

    std::string result((char*)blobOut.pbData, blobOut.cbData);
    LocalFree(blobOut.pbData);
    return result;
}

// ============================================================================
// Modes
// ============================================================================

int ModeEncrypt(const char* plaintext) {
    printf("[*] Encrypting: \"%s\"\n", plaintext);
    std::string b64 = DPAPIEncrypt(plaintext);
    if (b64.empty()) return 1;
    printf("[+] Base64 blob:\n%s\n", b64.c_str());
    return 0;
}

int ModeDecrypt(const char* b64) {
    printf("[*] Decrypting base64 blob (%zu chars)...\n", strlen(b64));
    std::string plain = DPAPIDecrypt(b64);
    if (plain.empty()) return 1;

    printf("[+] Plaintext (%zu bytes): \"%s\"\n", plain.size(), plain.c_str());

    // Also print hex for non-printable content
    bool allPrintable = true;
    for (unsigned char c : plain) {
        if (c < 0x20 || c > 0x7E) { allPrintable = false; break; }
    }
    if (!allPrintable) {
        printf("    Hex: ");
        for (unsigned char c : plain) printf("%02X ", c);
        printf("\n");
    }
    return 0;
}

int ModeTest() {
    printf("[*] Self-test: encrypt then decrypt \"secret123\"...\n");

    std::string original = "secret123";
    std::string b64 = DPAPIEncrypt(original);
    if (b64.empty()) {
        printf("[-] FAIL: encryption returned empty blob.\n");
        return 1;
    }
    printf("    Encrypted blob (%zu chars): %s\n", b64.size(), b64.c_str());

    std::string recovered = DPAPIDecrypt(b64);
    if (recovered.empty()) {
        printf("[-] FAIL: decryption returned empty string.\n");
        return 1;
    }
    printf("    Recovered      : \"%s\"\n", recovered.c_str());

    if (recovered == original) {
        printf("[+] PASS: round-trip successful.\n");
        return 0;
    } else {
        printf("[-] FAIL: recovered \"%s\" != original \"%s\".\n",
               recovered.c_str(), original.c_str());
        return 1;
    }
}

// ============================================================================
// main
// ============================================================================
int main(int argc, char* argv[]) {
    printf("=== Solution 01: DPAPI Encrypt/Decrypt ===\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  sol01.exe encrypt <plaintext>   -- encrypt and print base64 blob\n");
        printf("  sol01.exe decrypt <base64blob>  -- decrypt a base64 DPAPI blob\n");
        printf("  sol01.exe test                  -- self-test round-trip\n");
        return 1;
    }

    if (_stricmp(argv[1], "encrypt") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: sol01.exe encrypt <plaintext>\n"); return 1; }
        return ModeEncrypt(argv[2]);
    }
    if (_stricmp(argv[1], "decrypt") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: sol01.exe decrypt <base64blob>\n"); return 1; }
        return ModeDecrypt(argv[2]);
    }
    if (_stricmp(argv[1], "test") == 0) {
        return ModeTest();
    }

    fprintf(stderr, "[!] Unknown mode: %s\n", argv[1]);
    return 1;
}
