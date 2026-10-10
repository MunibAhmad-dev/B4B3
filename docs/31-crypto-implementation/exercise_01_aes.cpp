// exercise_01_aes.cpp
// Module 31 — Crypto Implementation
// Exercise: AES-256-CBC using Windows CNG (BCrypt API)
//
// Compile: g++ -std=c++17 -Wall -o ex01.exe exercise_01_aes.cpp -lbcrypt
//
// Your task: fill in each TODO block to produce a working AES-256-CBC
// encrypt/decrypt round-trip. The main() at the bottom drives the test.

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <string>

#pragma comment(lib, "bcrypt.lib")

// Helper: print bytes as hex
static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    printf("\n");
}

// Helper: check NTSTATUS
static void checkStatus(NTSTATUS status, const char* msg) {
    if (!BCRYPT_SUCCESS(status)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s failed: NTSTATUS=0x%08X", msg, (unsigned)status);
        throw std::runtime_error(buf);
    }
}

// ============================================================
// TODO 1: Open AES algorithm provider and set CBC chaining mode
//   - BCryptOpenAlgorithmProvider with BCRYPT_AES_ALGORITHM
//   - BCryptSetProperty with BCRYPT_CHAINING_MODE = BCRYPT_CHAIN_MODE_CBC
//   - Query BCRYPT_OBJECT_LENGTH to know how many bytes to allocate for key object
// ============================================================
struct AesContext {
    BCRYPT_ALG_HANDLE hAlg   = nullptr;
    BCRYPT_KEY_HANDLE hKey   = nullptr;
    std::vector<uint8_t> keyObj;  // key object buffer (opaque, sized by CNG)

    void open(const uint8_t* key32, size_t keyLen) {
        // TODO 1a: Open the AES algorithm provider
        //   BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

        // TODO 1b: Set chaining mode to CBC
        //   BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        //                     (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

        // TODO 1c: Query BCRYPT_OBJECT_LENGTH and allocate keyObj
        //   DWORD cbKeyObj = 0, cbResult = 0;
        //   BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObj, sizeof(cbKeyObj), &cbResult, 0);
        //   keyObj.resize(cbKeyObj);

        // TODO 1d: Import the 32-byte key
        //   BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), (ULONG)keyObj.size(),
        //                              (PUCHAR)key32, (ULONG)keyLen, 0);

        (void)key32; (void)keyLen;  // remove when you implement above
    }

    void close() {
        if (hKey) { BCryptDestroyKey(hKey); hKey = nullptr; }
        if (hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; }
    }
};

// ============================================================
// TODO 2: Generate a random 16-byte IV using BCryptGenRandom
// ============================================================
static std::vector<uint8_t> generateIV() {
    std::vector<uint8_t> iv(16, 0);

    // TODO 2: Fill iv with random bytes
    //   BCryptGenRandom(NULL, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return iv;  // currently returns zeroed IV — fix this
}

// ============================================================
// TODO 3: Encrypt plaintext using AES-256-CBC
//   Input:  key (32 bytes), plaintext
//   Output: iv (16 bytes) prepended to ciphertext (stored in output)
//   Hint:   BCryptEncrypt with pbIV = iv.data(), dwFlags = BCRYPT_BLOCK_PADDING
// ============================================================
static std::vector<uint8_t> aesEncrypt(const uint8_t* key32,
                                        const uint8_t* plaintext,
                                        size_t ptLen)
{
    AesContext ctx;
    ctx.open(key32, 32);

    // TODO 3a: Generate IV
    // std::vector<uint8_t> iv = generateIV();

    // TODO 3b: Query output buffer size
    //   ULONG cbCipher = 0;
    //   BCryptEncrypt(ctx.hKey, (PUCHAR)plaintext, (ULONG)ptLen, NULL,
    //                 iv.data(), 16, NULL, 0, &cbCipher, BCRYPT_BLOCK_PADDING);

    // TODO 3c: Allocate and perform encryption
    //   std::vector<uint8_t> cipher(cbCipher);
    //   ULONG cbResult = 0;
    //   BCryptEncrypt(ctx.hKey, (PUCHAR)plaintext, (ULONG)ptLen, NULL,
    //                 iv.data(), 16, cipher.data(), cbCipher, &cbResult, BCRYPT_BLOCK_PADDING);

    // TODO 3d: Prepend iv to cipher and return
    //   std::vector<uint8_t> output(iv.begin(), iv.end());
    //   output.insert(output.end(), cipher.begin(), cipher.begin() + cbResult);
    //   return output;

    ctx.close();
    (void)plaintext; (void)ptLen;
    return {};  // remove when implemented
}

// ============================================================
// TODO 4: Decrypt ciphertext using AES-256-CBC
//   Input:  key (32 bytes), iv+ciphertext blob from aesEncrypt
//   Output: recovered plaintext
//   Hint:   First 16 bytes of input are the IV, remainder is ciphertext
//           BCryptDecrypt with dwFlags = BCRYPT_BLOCK_PADDING
// ============================================================
static std::vector<uint8_t> aesDecrypt(const uint8_t* key32,
                                        const uint8_t* ivAndCipher,
                                        size_t totalLen)
{
    if (totalLen < 17) throw std::runtime_error("Input too short");

    // TODO 4a: Split IV from ciphertext
    //   const uint8_t* iv = ivAndCipher;
    //   const uint8_t* cipher = ivAndCipher + 16;
    //   size_t cipherLen = totalLen - 16;

    AesContext ctx;
    ctx.open(key32, 32);

    // TODO 4b: Query output buffer size
    // TODO 4c: Perform decryption (BCryptDecrypt, BCRYPT_BLOCK_PADDING)
    // TODO 4d: Return plaintext

    ctx.close();
    (void)ivAndCipher; (void)totalLen;
    return {};  // remove when implemented
}

// ============================================================
// Main — do not modify; this drives the test
// ============================================================
int main() {
    // AES-256 key (32 bytes) — fixed for the exercise
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;

    const char* message = "Hello, AES-256-CBC! This is Module 31.";
    size_t msgLen = strlen(message);

    printf("Plaintext:  %s\n", message);
    printHex("Key       ", key, 32);

    try {
        // Encrypt
        std::vector<uint8_t> encrypted = aesEncrypt(key, (const uint8_t*)message, msgLen);
        if (encrypted.empty()) {
            printf("TODO not yet implemented — fill in the TODO blocks above.\n");
            return 1;
        }
        printHex("Encrypted ", encrypted.data(), encrypted.size());

        // Decrypt
        std::vector<uint8_t> decrypted = aesDecrypt(key, encrypted.data(), encrypted.size());
        decrypted.push_back(0);  // null terminate for printf
        printf("Decrypted:  %s\n", (char*)decrypted.data());

        if (strcmp((char*)decrypted.data(), message) == 0) {
            printf("\n[PASS] Round-trip succeeded.\n");
        } else {
            printf("\n[FAIL] Decrypted text does not match original.\n");
            return 1;
        }
    } catch (const std::exception& ex) {
        fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
    return 0;
}
