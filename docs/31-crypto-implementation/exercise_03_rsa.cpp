// exercise_03_rsa.cpp
// Module 31 — Crypto Implementation
// Exercise: RSA-2048 key generation, encrypt, decrypt using Windows CNG
//
// Compile: g++ -std=c++17 -Wall -o ex03.exe exercise_03_rsa.cpp -lbcrypt
//
// Your task: fill in the four TODO sections to produce a working
// RSA-2048 encrypt/decrypt demo.

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <string>

#pragma comment(lib, "bcrypt.lib")

// Helper: print hex
static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; ++i) printf("%02x", data[i]);
    if (len > 32) printf("...");
    printf("\n");
}

// Helper: check NTSTATUS
static void checkStatus(NTSTATUS status, const char* msg) {
    if (!BCRYPT_SUCCESS(status)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: NTSTATUS=0x%08X", msg, (unsigned)status);
        throw std::runtime_error(buf);
    }
}

// ============================================================
// RsaKeyPair: holds algorithm provider and both key handles
// ============================================================
struct RsaKeyPair {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKeyPair = nullptr;  // full key pair (pub + priv)
    BCRYPT_KEY_HANDLE hPubOnly = nullptr;  // re-imported public key only

    // TODO 1: Generate RSA-2048 key pair
    //
    // Steps:
    //   a) BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0)
    //   b) BCryptGenerateKeyPair(hAlg, &hKeyPair, 2048, 0)
    //   c) BCryptFinalizeKeyPair(hKeyPair, 0)
    //
    void generate() {
        // TODO 1a: Open algorithm provider

        // TODO 1b: Generate key pair (2048 bits)

        // TODO 1c: Finalize (actually generates the key material)
    }

    // TODO 2: Export the public key as a BCRYPT_RSAPUBLIC_BLOB
    //
    // Steps:
    //   a) Query size: BCryptExportKey(hKeyPair, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cbBlob, 0)
    //   b) Allocate buffer and export
    //   c) Return the blob bytes
    //
    // The blob layout (BCRYPT_RSAKEY_BLOB header + data):
    //   DWORD Magic    = BCRYPT_RSAPUBLIC_MAGIC (0x31415352)
    //   DWORD BitLen   = 2048
    //   DWORD cbPublicExp  (typically 4)
    //   DWORD cbModulus    (typically 256)
    //   DWORD cbPrime1 = 0
    //   DWORD cbPrime2 = 0
    //   followed by: PublicExponent bytes || Modulus bytes
    //
    std::vector<uint8_t> exportPublicKey() {
        // TODO 2: export public key
        return {};  // remove when implemented
    }

    // TODO 3: Re-import public key blob as a separate key handle (hPubOnly)
    //         so encryption can use just the public key
    //
    //   BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB,
    //                       &hPubOnly, blob, blobLen, 0)
    //
    void importPublicKey(const std::vector<uint8_t>& blob) {
        // TODO 3: import public key into hPubOnly
        (void)blob;
    }

    void close() {
        if (hPubOnly)  { BCryptDestroyKey(hPubOnly);  hPubOnly  = nullptr; }
        if (hKeyPair)  { BCryptDestroyKey(hKeyPair);  hKeyPair  = nullptr; }
        if (hAlg)      { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; }
    }
};

// ============================================================
// TODO 4a: Encrypt plaintext with RSA public key (PKCS#1 v1.5 padding)
//
// Use hPubOnly (the re-imported public key).
// Steps:
//   a) Set up BCRYPT_PKCS1_PADDING_INFO with pszAlgId = NULL (raw PKCS1)
//   b) Query output size: BCryptEncrypt(hPubOnly, plaintext, ptLen,
//                                       &paddingInfo, NULL, 0, NULL, 0, &cbOut,
//                                       BCRYPT_PAD_PKCS1)
//   c) Allocate and encrypt
//
// Note: max plaintext for RSA-2048 PKCS1 is 245 bytes (256 - 11 overhead)
// ============================================================
static std::vector<uint8_t> rsaEncrypt(BCRYPT_KEY_HANDLE hPubKey,
                                        const uint8_t* plaintext, ULONG ptLen)
{
    // TODO 4a: implement RSA encrypt
    (void)hPubKey; (void)plaintext; (void)ptLen;
    return {};
}

// ============================================================
// TODO 4b: Decrypt ciphertext with RSA private key (PKCS#1 v1.5 padding)
//
// Use hKeyPair.
// BCryptDecrypt(hKeyPair, ciphertext, ctLen, &paddingInfo, NULL, 0,
//               plaintext, ptBufLen, &cbResult, BCRYPT_PAD_PKCS1)
// ============================================================
static std::vector<uint8_t> rsaDecrypt(BCRYPT_KEY_HANDLE hPrivKey,
                                        const uint8_t* ciphertext, ULONG ctLen)
{
    // TODO 4b: implement RSA decrypt
    (void)hPrivKey; (void)ciphertext; (void)ctLen;
    return {};
}

// ============================================================
// Main — do not modify
// ============================================================
int main() {
    try {
        printf("Generating RSA-2048 key pair...\n");
        RsaKeyPair rsa;
        rsa.generate();

        if (!rsa.hKeyPair) {
            printf("TODO 1 not yet implemented — fill in generate().\n");
            return 1;
        }
        printf("Key pair generated.\n");

        // Export and re-import public key
        auto pubBlob = rsa.exportPublicKey();
        if (pubBlob.empty()) {
            printf("TODO 2 not yet implemented — fill in exportPublicKey().\n");
            rsa.close();
            return 1;
        }
        printHex("Public key blob", pubBlob.data(), pubBlob.size());

        rsa.importPublicKey(pubBlob);
        if (!rsa.hPubOnly) {
            printf("TODO 3 not yet implemented — fill in importPublicKey().\n");
            rsa.close();
            return 1;
        }

        // Encrypt a short message
        const char* message = "RSA test: Module 31!";
        size_t msgLen = strlen(message);
        printf("\nPlaintext:  %s\n", message);

        auto ciphertext = rsaEncrypt(rsa.hPubOnly, (const uint8_t*)message, (ULONG)msgLen);
        if (ciphertext.empty()) {
            printf("TODO 4a not yet implemented — fill in rsaEncrypt().\n");
            rsa.close();
            return 1;
        }
        printHex("Ciphertext", ciphertext.data(), ciphertext.size());

        // Decrypt
        auto recovered = rsaDecrypt(rsa.hKeyPair, ciphertext.data(), (ULONG)ciphertext.size());
        if (recovered.empty()) {
            printf("TODO 4b not yet implemented — fill in rsaDecrypt().\n");
            rsa.close();
            return 1;
        }
        recovered.push_back(0);
        printf("Decrypted:  %s\n", (char*)recovered.data());

        bool pass = (strcmp((char*)recovered.data(), message) == 0);
        printf("\n[%s] RSA-2048 round-trip\n", pass ? "PASS" : "FAIL");

        rsa.close();
    } catch (const std::exception& ex) {
        fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
    return 0;
}
