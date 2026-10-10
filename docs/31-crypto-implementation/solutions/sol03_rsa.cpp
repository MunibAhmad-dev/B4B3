// solutions/sol03_rsa.cpp
// Module 31 — Crypto Implementation
// Solution: RSA-2048 key generation, encrypt, decrypt using Windows CNG
//
// Compile: g++ -std=c++17 -Wall -o sol03.exe sol03_rsa.cpp -lbcrypt

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <string>

#pragma comment(lib, "bcrypt.lib")

// ---- helpers ----
static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; ++i) printf("%02x", data[i]);
    if (len > 32) printf("...");
    printf("\n");
}

static void checkStatus(NTSTATUS status, const char* msg) {
    if (!BCRYPT_SUCCESS(status)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: NTSTATUS=0x%08X", msg, (unsigned)status);
        throw std::runtime_error(buf);
    }
}

// ---- RSA key pair ----
struct RsaKeyPair {
    BCRYPT_ALG_HANDLE hAlg     = nullptr;
    BCRYPT_KEY_HANDLE hKeyPair = nullptr;  // private + public
    BCRYPT_KEY_HANDLE hPubOnly = nullptr;  // public only (re-imported)

    void generate() {
        NTSTATUS st;

        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
        checkStatus(st, "BCryptOpenAlgorithmProvider(RSA)");

        st = BCryptGenerateKeyPair(hAlg, &hKeyPair, 2048, 0);
        checkStatus(st, "BCryptGenerateKeyPair(2048)");

        // FinalizeKeyPair actually triggers the prime generation
        st = BCryptFinalizeKeyPair(hKeyPair, 0);
        checkStatus(st, "BCryptFinalizeKeyPair");
    }

    // Export the public key as BCRYPT_RSAPUBLIC_BLOB
    std::vector<uint8_t> exportPublicKey() const {
        ULONG cbBlob = 0;
        NTSTATUS st = BCryptExportKey(hKeyPair, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                       NULL, 0, &cbBlob, 0);
        checkStatus(st, "BCryptExportKey(pub, size query)");

        std::vector<uint8_t> blob(cbBlob);
        st = BCryptExportKey(hKeyPair, NULL, BCRYPT_RSAPUBLIC_BLOB,
                              blob.data(), cbBlob, &cbBlob, 0);
        checkStatus(st, "BCryptExportKey(pub)");
        return blob;
    }

    // Export the full (private) key as BCRYPT_RSAFULLPRIVATE_BLOB
    std::vector<uint8_t> exportPrivateKey() const {
        ULONG cbBlob = 0;
        NTSTATUS st = BCryptExportKey(hKeyPair, NULL, BCRYPT_RSAFULLPRIVATE_BLOB,
                                       NULL, 0, &cbBlob, 0);
        checkStatus(st, "BCryptExportKey(priv, size query)");

        std::vector<uint8_t> blob(cbBlob);
        st = BCryptExportKey(hKeyPair, NULL, BCRYPT_RSAFULLPRIVATE_BLOB,
                              blob.data(), cbBlob, &cbBlob, 0);
        checkStatus(st, "BCryptExportKey(priv)");
        return blob;
    }

    // Re-import public blob so we can simulate encrypt-only party
    void importPublicKey(const std::vector<uint8_t>& blob) {
        NTSTATUS st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                           &hPubOnly,
                                           (PUCHAR)blob.data(), (ULONG)blob.size(), 0);
        checkStatus(st, "BCryptImportKeyPair(pub)");
    }

    void close() {
        if (hPubOnly) { BCryptDestroyKey(hPubOnly); hPubOnly = nullptr; }
        if (hKeyPair) { BCryptDestroyKey(hKeyPair); hKeyPair = nullptr; }
        if (hAlg)     { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; }
    }
};

// ---- RSA encrypt (PKCS#1 v1.5) using public key ----
static std::vector<uint8_t> rsaEncrypt(BCRYPT_KEY_HANDLE hPubKey,
                                        const uint8_t* plaintext, ULONG ptLen)
{
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = NULL;  // NULL means no hash (raw PKCS1 type 2)

    // Query output size
    ULONG cbOut = 0;
    BCryptEncrypt(hPubKey, (PUCHAR)plaintext, ptLen,
                  &paddingInfo, NULL, 0, NULL, 0, &cbOut, BCRYPT_PAD_PKCS1);

    std::vector<uint8_t> cipher(cbOut);
    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(hPubKey, (PUCHAR)plaintext, ptLen,
                                 &paddingInfo, NULL, 0,
                                 cipher.data(), cbOut, &cbResult, BCRYPT_PAD_PKCS1);
    checkStatus(st, "BCryptEncrypt(RSA)");
    cipher.resize(cbResult);
    return cipher;
}

// ---- RSA decrypt (PKCS#1 v1.5) using private key ----
static std::vector<uint8_t> rsaDecrypt(BCRYPT_KEY_HANDLE hPrivKey,
                                        const uint8_t* ciphertext, ULONG ctLen)
{
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = NULL;

    ULONG cbOut = 0;
    BCryptDecrypt(hPrivKey, (PUCHAR)ciphertext, ctLen,
                  &paddingInfo, NULL, 0, NULL, 0, &cbOut, BCRYPT_PAD_PKCS1);

    std::vector<uint8_t> plain(cbOut);
    ULONG cbResult = 0;
    NTSTATUS st = BCryptDecrypt(hPrivKey, (PUCHAR)ciphertext, ctLen,
                                 &paddingInfo, NULL, 0,
                                 plain.data(), cbOut, &cbResult, BCRYPT_PAD_PKCS1);
    checkStatus(st, "BCryptDecrypt(RSA)");
    plain.resize(cbResult);
    return plain;
}

// ---- main ----
int main() {
    printf("=== RSA-2048 (Windows CNG) ===\n\n");

    try {
        // Generate key pair
        printf("Generating RSA-2048 key pair (this may take a moment)...\n");
        RsaKeyPair rsa;
        rsa.generate();
        printf("Key pair generated.\n\n");

        // Export and display public key blob info
        auto pubBlob  = rsa.exportPublicKey();
        auto privBlob = rsa.exportPrivateKey();

        // Parse the public blob header (BCRYPT_RSAKEY_BLOB)
        if (pubBlob.size() >= sizeof(BCRYPT_RSAKEY_BLOB)) {
            auto* hdr = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(pubBlob.data());
            printf("Public key: Magic=0x%08X, BitLength=%u, cbPubExp=%u, cbModulus=%u\n",
                   hdr->Magic, hdr->BitLength, hdr->cbPublicExp, hdr->cbModulus);
        }
        printHex("Public blob  ", pubBlob.data(),  pubBlob.size());
        printf("Private blob: %zu bytes (not printed for security)\n\n", privBlob.size());

        // Re-import public key
        rsa.importPublicKey(pubBlob);

        // Encrypt a message with public key only
        const char* message = "Hello from RSA-2048! Module 31.";
        size_t msgLen = strlen(message);
        printf("Plaintext:  %s\n", message);

        auto ciphertext = rsaEncrypt(rsa.hPubOnly, (const uint8_t*)message, (ULONG)msgLen);
        printHex("Ciphertext", ciphertext.data(), ciphertext.size());

        // Decrypt with private key
        auto recovered = rsaDecrypt(rsa.hKeyPair, ciphertext.data(), (ULONG)ciphertext.size());
        recovered.push_back(0);
        printf("Decrypted:  %s\n\n", (char*)recovered.data());

        bool pass = (strcmp((char*)recovered.data(), message) == 0);
        printf("[%s] RSA-2048 PKCS#1 v1.5 round-trip\n", pass ? "PASS" : "FAIL");

        // Demonstrate that wrong key fails to decrypt
        printf("\nAttempting decrypt with wrong (re-generated) key...\n");
        try {
            RsaKeyPair rsa2;
            rsa2.generate();
            auto badDecrypt = rsaDecrypt(rsa2.hKeyPair, ciphertext.data(), (ULONG)ciphertext.size());
            // If we reach here, check if data is different
            badDecrypt.push_back(0);
            bool different = (strcmp((char*)badDecrypt.data(), message) != 0);
            printf("[%s] Wrong key produced different output\n", different ? "PASS" : "FAIL");
            rsa2.close();
        } catch (const std::exception& ex) {
            printf("[PASS] Wrong key threw exception (expected): %s\n", ex.what());
        }

        rsa.close();
    } catch (const std::exception& ex) {
        fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
    return 0;
}
