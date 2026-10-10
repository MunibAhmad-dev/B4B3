/*
 * Exercise 01 — DPAPI Decrypt
 * Module 11: Credential Access
 *
 * Task: Use CryptUnprotectData to decrypt a DPAPI-protected blob.
 *
 * IMPORTANT NOTE ON DPAPI:
 *   DPAPI (Data Protection API) ties encryption to the currently logged-in
 *   user. The key is derived from the user's login password and their master
 *   key stored in their profile. You MUST run this program as the same user
 *   who originally encrypted the data. Running as SYSTEM, a different user,
 *   or in a different session will cause CryptUnprotectData to fail with
 *   ERROR_INVALID_PARAMETER or NTE_BAD_KEY.
 *
 * This exercise encrypts a test string first (so you have a real blob to work
 * with), then asks you to implement the decryption.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o ex01.exe exercise_01_dpapi.cpp -ladvapi32 -lcrypt32
 *
 * Usage:
 *   ex01.exe
 */

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// Print raw bytes as a two-digit hex dump.
void PrintHex(const BYTE* data, DWORD len) {
    for (DWORD i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// Return true if every byte in [data, data+len) is printable ASCII.
bool IsPrintable(const BYTE* data, DWORD len) {
    for (DWORD i = 0; i < len; i++) {
        if (data[i] < 0x20 || data[i] > 0x7E) return false;
    }
    return true;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int main() {
    printf("=== Exercise 01: DPAPI Decrypt ===\n\n");

    // -------------------------------------------------------------------------
    // SETUP: Encrypt a known string so we have a real DPAPI blob to decrypt.
    // You do not need to modify this section.
    // -------------------------------------------------------------------------
    const char* testPlaintext = "Hello, DPAPI! (Module 11 exercise)";

    DATA_BLOB plainIn;
    plainIn.pbData = (BYTE*)testPlaintext;
    plainIn.cbData = (DWORD)strlen(testPlaintext);

    DATA_BLOB cipherOut = {0};

    // Encrypt. dwFlags=0 means current-user scope (can only decrypt as same user).
    if (!CryptProtectData(
            &plainIn,          // input
            L"M11-Exercise01", // optional description label
            NULL,              // optional extra entropy
            NULL,              // reserved
            NULL,              // optional prompt
            0,                 // dwFlags: 0 = user-scope
            &cipherOut))       // output blob
    {
        printf("CryptProtectData failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Plaintext  : %s\n", testPlaintext);
    printf("Encrypted blob (%lu bytes):\n", cipherOut.cbData);
    PrintHex(cipherOut.pbData, cipherOut.cbData);
    printf("\n");

    // -------------------------------------------------------------------------
    // TODO 1 — Set up the DATA_BLOB input struct for decryption.
    //
    //   Create a DATA_BLOB called blobIn.
    //   Set blobIn.pbData to point at the encrypted bytes (cipherOut.pbData).
    //   Set blobIn.cbData to the number of encrypted bytes (cipherOut.cbData).
    //
    //   Hint:
    //     DATA_BLOB blobIn;
    //     blobIn.pbData = ???;
    //     blobIn.cbData = ???;
    // -------------------------------------------------------------------------

    DATA_BLOB blobIn;
    // >>> YOUR CODE FOR TODO 1 HERE <<<



    DATA_BLOB blobOut = {0};
    LPWSTR    pDescription = NULL;

    // -------------------------------------------------------------------------
    // TODO 2 — Call CryptUnprotectData to decrypt blobIn into blobOut.
    //
    //   Signature:
    //     BOOL CryptUnprotectData(
    //         DATA_BLOB*          pDataIn,       // encrypted input
    //         LPWSTR*             ppszDataDescr, // receives optional description
    //         DATA_BLOB*          pOptionalEntropy, // NULL (no extra entropy)
    //         PVOID               pvReserved,    // NULL
    //         CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, // NULL
    //         DWORD               dwFlags,       // 0 = current user
    //         DATA_BLOB*          pDataOut       // decrypted output
    //     );
    //
    //   - Pass &blobIn as pDataIn
    //   - Pass &pDescription to receive the label set during encryption
    //   - Pass &blobOut to receive decrypted bytes
    //   - dwFlags = 0
    //
    //   Check the return value (BOOL). On failure print GetLastError() and
    //   jump to cleanup. On success, blobOut.pbData / blobOut.cbData hold the
    //   decrypted data.
    // -------------------------------------------------------------------------

    // >>> YOUR CODE FOR TODO 2 HERE <<<
    BOOL ok = FALSE; // remove this placeholder; set ok from CryptUnprotectData



    if (!ok) {
        printf("CryptUnprotectData failed: %lu\n", GetLastError());
        LocalFree(cipherOut.pbData);
        return 1;
    }

    // -------------------------------------------------------------------------
    // TODO 3 — Print the decrypted output.
    //
    //   a) If pDescription is not NULL, print it as a wide string:
    //        wprintf(L"Description: %s\n", pDescription);
    //
    //   b) Print the decrypted bytes as hex using PrintHex().
    //
    //   c) If IsPrintable(blobOut.pbData, blobOut.cbData) is true, also print
    //      the data as a plain string:
    //        printf("String: %.*s\n", (int)blobOut.cbData, (char*)blobOut.pbData);
    //
    //   d) Free blobOut.pbData with LocalFree after printing.
    //   e) Free pDescription with LocalFree if it is not NULL.
    // -------------------------------------------------------------------------

    printf("\n--- Decrypted output (%lu bytes) ---\n", blobOut.cbData);

    // >>> YOUR CODE FOR TODO 3 HERE <<<



    // Cleanup memory allocated by CryptProtectData
    LocalFree(cipherOut.pbData);

    printf("\nDone.\n");
    return 0;
}
