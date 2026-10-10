// solutions/sol01_aes.cpp
// Module 31 — Crypto Implementation
// Solution: AES-256-CBC encrypt/decrypt using Windows CNG
//
// Compile: g++ -std=c++17 -Wall -o sol01.exe sol01_aes.cpp -lbcrypt

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
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    printf("\n");
}

static void checkStatus(NTSTATUS status, const char* msg) {
    if (!BCRYPT_SUCCESS(status)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: NTSTATUS=0x%08X", msg, (unsigned)status);
        throw std::runtime_error(buf);
    }
}

// ---- AES context ----
struct AesContext {
    BCRYPT_ALG_HANDLE hAlg  = nullptr;
    BCRYPT_KEY_HANDLE hKey  = nullptr;
    std::vector<uint8_t> keyObj;

    void open(const uint8_t* key, size_t keyLen) {
        NTSTATUS st;

        // Open AES provider
        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        checkStatus(st, "BCryptOpenAlgorithmProvider");

        // Set CBC mode
        st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        checkStatus(st, "BCryptSetProperty(CBC)");

        // Query key object size
        DWORD cbKeyObj = 0, cbResult = 0;
        st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                               (PBYTE)&cbKeyObj, sizeof(cbKeyObj), &cbResult, 0);
        checkStatus(st, "BCryptGetProperty(OBJECT_LENGTH)");
        keyObj.resize(cbKeyObj);

        // Import the key
        st = BCryptGenerateSymmetricKey(hAlg, &hKey,
                                         keyObj.data(), (ULONG)keyObj.size(),
                                         (PUCHAR)key, (ULONG)keyLen, 0);
        checkStatus(st, "BCryptGenerateSymmetricKey");
    }

    void close() {
        if (hKey) { BCryptDestroyKey(hKey); hKey = nullptr; }
        if (hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; }
    }
};

// ---- generate random IV ----
static std::vector<uint8_t> generateIV() {
    std::vector<uint8_t> iv(16);
    NTSTATUS st = BCryptGenRandom(NULL, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    checkStatus(st, "BCryptGenRandom(IV)");
    return iv;
}

// ---- AES-256-CBC encrypt ----
// Returns: IV (16 bytes) || ciphertext (PKCS7-padded)
static std::vector<uint8_t> aesEncrypt(const uint8_t key32[32],
                                        const uint8_t* plaintext,
                                        size_t ptLen)
{
    AesContext ctx;
    ctx.open(key32, 32);

    auto iv = generateIV();
    uint8_t ivCopy[16];
    memcpy(ivCopy, iv.data(), 16);

    // Query output size
    ULONG cbCipher = 0;
    BCryptEncrypt(ctx.hKey, (PUCHAR)plaintext, (ULONG)ptLen, NULL,
                  ivCopy, 16, NULL, 0, &cbCipher, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> cipher(cbCipher);
    memcpy(ivCopy, iv.data(), 16);  // reset IV (BCryptEncrypt modifies it)

    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(ctx.hKey, (PUCHAR)plaintext, (ULONG)ptLen, NULL,
                                 ivCopy, 16, cipher.data(), cbCipher,
                                 &cbResult, BCRYPT_BLOCK_PADDING);
    checkStatus(st, "BCryptEncrypt");
    cipher.resize(cbResult);

    ctx.close();

    // Prepend IV
    std::vector<uint8_t> output(iv.begin(), iv.end());
    output.insert(output.end(), cipher.begin(), cipher.end());
    return output;
}

// ---- AES-256-CBC decrypt ----
// Input: IV (16 bytes) || ciphertext
static std::vector<uint8_t> aesDecrypt(const uint8_t key32[32],
                                        const uint8_t* ivAndCipher,
                                        size_t totalLen)
{
    if (totalLen < 17) throw std::runtime_error("Input too short");

    const uint8_t* iv         = ivAndCipher;
    const uint8_t* ciphertext = ivAndCipher + 16;
    size_t         cipherLen  = totalLen - 16;

    AesContext ctx;
    ctx.open(key32, 32);

    uint8_t ivCopy[16];
    memcpy(ivCopy, iv, 16);

    ULONG cbPlain = 0;
    BCryptDecrypt(ctx.hKey, (PUCHAR)ciphertext, (ULONG)cipherLen, NULL,
                  ivCopy, 16, NULL, 0, &cbPlain, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> plain(cbPlain);
    memcpy(ivCopy, iv, 16);

    ULONG cbResult = 0;
    NTSTATUS st = BCryptDecrypt(ctx.hKey, (PUCHAR)ciphertext, (ULONG)cipherLen, NULL,
                                 ivCopy, 16, plain.data(), cbPlain,
                                 &cbResult, BCRYPT_BLOCK_PADDING);
    checkStatus(st, "BCryptDecrypt");
    plain.resize(cbResult);
    ctx.close();
    return plain;
}

// ---- main ----
int main() {
    // AES-256 key: 0x00..0x1F
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;

    const char* message = "Hello, World!";
    size_t msgLen = strlen(message);

    printf("=== AES-256-CBC (Windows CNG) ===\n");
    printf("Plaintext:  %s\n", message);
    printHex("Key       ", key, 32);

    try {
        // Encrypt
        auto encrypted = aesEncrypt(key, (const uint8_t*)message, msgLen);
        printHex("IV+Cipher ", encrypted.data(), encrypted.size());

        // Decrypt
        auto decrypted = aesDecrypt(key, encrypted.data(), encrypted.size());
        decrypted.push_back(0);
        printf("Decrypted:  %s\n", (char*)decrypted.data());

        bool pass = (strcmp((char*)decrypted.data(), message) == 0);
        printf("\n[%s] AES-256-CBC round-trip\n", pass ? "PASS" : "FAIL");

        // Additional test: modifying ciphertext should not decrypt to same plaintext
        auto tampered = encrypted;
        tampered[20] ^= 0xFF;
        try {
            auto decTampered = aesDecrypt(key, tampered.data(), tampered.size());
            decTampered.push_back(0);
            bool different = (strcmp((char*)decTampered.data(), message) != 0);
            printf("[%s] Tampered ciphertext decrypts differently (expected)\n",
                   different ? "PASS" : "FAIL");
        } catch (...) {
            printf("[PASS] Tampered ciphertext caused padding error (expected)\n");
        }
    } catch (const std::exception& ex) {
        fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
    return 0;
}
