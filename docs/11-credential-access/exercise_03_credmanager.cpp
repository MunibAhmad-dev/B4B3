/*
 * Exercise 03 — Windows Credential Manager Enumeration
 * Module 11: Credential Access
 *
 * Task: Use the Windows Credential API to enumerate all entries stored in the
 * Windows Credential Manager (Control Panel → Credential Manager) and print
 * their metadata and, where possible, their stored secret.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o ex03.exe exercise_03_credmanager.cpp -ladvapi32
 *
 * Usage:
 *   ex03.exe
 *
 * Key API:
 *   CredEnumerateA  — enumerate all credentials matching a filter
 *   PCREDENTIAL     — pointer to a CREDENTIAL structure
 *   CredFree        — release memory allocated by credential APIs
 *
 * Credential types (DWORD Type field):
 *   1  CRED_TYPE_GENERIC                 — application-defined credentials
 *   2  CRED_TYPE_DOMAIN_PASSWORD         — Windows domain / network passwords
 *   3  CRED_TYPE_DOMAIN_CERTIFICATE      — certificate-based domain creds
 *   4  CRED_TYPE_DOMAIN_VISIBLE_PASSWORD — domain creds visible to the user
 *   5  CRED_TYPE_GENERIC_CERTIFICATE     — certificate-based generic creds
 *
 * AUTHORIZED USE ONLY — run against your own user session.
 */

#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <string>
#include <ctype.h>

#pragma comment(lib, "advapi32.lib")

// ----------------------------------------------------------------------------
// Helper: map credential Type DWORD to a readable name
// ----------------------------------------------------------------------------
const char* CredTypeName(DWORD type) {
    switch (type) {
        case CRED_TYPE_GENERIC:                  return "GENERIC";
        case CRED_TYPE_DOMAIN_PASSWORD:          return "DOMAIN_PASSWORD";
        case CRED_TYPE_DOMAIN_CERTIFICATE:       return "DOMAIN_CERTIFICATE";
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:  return "DOMAIN_VISIBLE_PASSWORD";
        case CRED_TYPE_GENERIC_CERTIFICATE:      return "GENERIC_CERTIFICATE";
        default:                                  return "UNKNOWN";
    }
}

// ----------------------------------------------------------------------------
// Helper: check if a byte buffer contains only printable ASCII
// ----------------------------------------------------------------------------
bool IsPrintableA(const BYTE* data, DWORD len) {
    for (DWORD i = 0; i < len; i++) {
        if (data[i] < 0x20 || data[i] > 0x7E) return false;
    }
    return true;
}

// =========================================================================
// TODO 1 — Enumerate all Credential Manager entries.
//
//   Call CredEnumerateA with a NULL filter to list every stored credential:
//
//     DWORD        count = 0;
//     PCREDENTIALA* ppCreds = NULL;
//     BOOL ok = CredEnumerateA(
//         NULL,       // filter: NULL = all entries
//         0,          // dwFlags: must be 0
//         &count,     // receives the number of credentials
//         &ppCreds    // receives pointer to array of PCREDENTIALA
//     );
//
//   On failure check GetLastError():
//     ERROR_NOT_FOUND (1168) — the vault is empty (not really an error)
//     Other codes           — genuine API error
//
//   On success, ppCreds is an array of count pointers to CREDENTIAL structs.
//   After processing, free the array with CredFree(ppCreds).
//
//   Return the count of entries found (0 if empty or error).
// =========================================================================

// =========================================================================
// TODO 2 — For each CREDENTIAL entry, print the following fields:
//
//   a) TargetName  (LPSTR, always present)
//   b) Type        (DWORD) — use CredTypeName() to turn it into a string
//   c) UserName    (LPSTR, may be NULL — print "(none)" if so)
//   d) CredentialBlobSize  (DWORD) — byte length of the secret
//   e) CredentialBlob      (LPBYTE) — the raw secret bytes
//
//   For (e), apply this logic:
//     - If CredentialBlobSize == 0: print "[no blob stored]"
//     - Else if IsPrintableA(blob, size): print as string
//       (the blob may actually be UTF-16; attempt narrow printing first,
//        then wprintf the wide version if narrow shows garbage — see hint)
//     - Else: print the first min(size, 32) bytes as hex, then count if more
//
//   Hint for UTF-16 blob:
//     CREDENTIAL blobs for DOMAIN_PASSWORD are UTF-16LE.  To print them:
//       wprintf(L"  Blob (UTF-16): %.*s\n",
//               (int)(cred->CredentialBlobSize / sizeof(WCHAR)),
//               (WCHAR*)cred->CredentialBlob);
// =========================================================================

// =========================================================================
// TODO 3 — Call CredFree on the array when done.
//
//   CredFree(ppCreds);
//
//   Note: CredFree frees the entire array and all nested strings in one call.
//   Do NOT attempt to free individual CREDENTIAL pointers or their fields.
// =========================================================================

// Placeholder PrintCredential — replace TODOs with real implementation
void PrintCredential(PCREDENTIALA cred, int index) {
    printf("\n[%d] TargetName : %s\n", index,
           cred->TargetName ? cred->TargetName : "(null)");

    // TODO 2a-c: print Type, UserName
    printf("    Type       : %lu (TODO: print name using CredTypeName)\n", cred->Type);
    printf("    UserName   : %s\n", cred->UserName ? cred->UserName : "(none)");

    // TODO 2d-e: print blob
    printf("    BlobSize   : %lu bytes (TODO: print blob contents)\n",
           cred->CredentialBlobSize);
}

int main() {
    printf("=== Exercise 03: Windows Credential Manager ===\n\n");

    DWORD         count   = 0;
    PCREDENTIALA* ppCreds = NULL;

    // TODO 1: Call CredEnumerateA here
    // BOOL ok = CredEnumerateA(NULL, 0, &count, &ppCreds);

    BOOL ok = FALSE; // replace this

    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_FOUND) {
            printf("Credential Manager is empty (no entries stored).\n");
        } else {
            printf("CredEnumerateA failed: %lu\n", err);
        }
        return (err == ERROR_NOT_FOUND) ? 0 : 1;
    }

    printf("Found %lu credential(s).\n", count);

    for (DWORD i = 0; i < count; i++) {
        PrintCredential(ppCreds[i], (int)i + 1);
    }

    // TODO 3: Free the credential array
    // CredFree(ppCreds);

    printf("\nDone. Remember to implement TODO 1, 2, and 3.\n");
    return 0;
}
