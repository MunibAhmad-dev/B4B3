// exercise_04_file_encryptor.cpp
// Module 31 — Crypto Implementation
// Exercise: File encryption tool with PBKDF2 key derivation + AES-256-CBC
//
// Compile: g++ -std=c++17 -Wall -o ex04.exe exercise_04_file_encryptor.cpp -lbcrypt
//
// Usage:
//   ex04.exe enc <infile> <outfile> <password>
//   ex04.exe dec <infile> <outfile> <password>
//
// File format: [salt 16B][IV 16B][ciphertext...]
//
// Your tasks:
//   TODO 1 — PBKDF2 key derivation (BCryptDeriveKeyPBKDF2)
//   TODO 2 — Encrypt file and write header (salt + IV + ciphertext)
//   TODO 3 — Decrypt file (read header, derive key, decrypt)

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <string>
#include <fstream>
#include <iterator>

#pragma comment(lib, "bcrypt.lib")

// ---- constants ----
static const size_t SALT_LEN = 16;
static const size_t IV_LEN   = 16;
static const size_t KEY_LEN  = 32;  // AES-256
static const ULONGLONG PBKDF2_ITERATIONS = 200000;

// Helper: check NTSTATUS
static void checkStatus(NTSTATUS status, const char* msg) {
    if (!BCRYPT_SUCCESS(status)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: NTSTATUS=0x%08X", msg, (unsigned)status);
        throw std::runtime_error(buf);
    }
}

// Helper: read entire file into vector
static std::vector<uint8_t> readFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error(std::string("Cannot open: ") + path);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// Helper: write vector to file
static void writeFile(const char* path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error(std::string("Cannot write: ") + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Helper: generate random bytes via CNG
static void genRandom(uint8_t* buf, size_t len) {
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    checkStatus(st, "BCryptGenRandom");
}

// ============================================================
// AES context setup (same pattern as exercise_01 — already done for you)
// ============================================================
struct AesContext {
    BCRYPT_ALG_HANDLE hAlg   = nullptr;
    BCRYPT_KEY_HANDLE hKey   = nullptr;
    std::vector<uint8_t> keyObj;

    void open(const uint8_t* key32, size_t keyLen) {
        NTSTATUS st;
        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        checkStatus(st, "BCryptOpenAlgorithmProvider");
        st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        checkStatus(st, "BCryptSetProperty(CBC)");
        DWORD cbKeyObj = 0, cbResult = 0;
        st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                               (PBYTE)&cbKeyObj, sizeof(cbKeyObj), &cbResult, 0);
        checkStatus(st, "BCryptGetProperty(OBJECT_LENGTH)");
        keyObj.resize(cbKeyObj);
        st = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), (ULONG)keyObj.size(),
                                         (PUCHAR)key32, (ULONG)keyLen, 0);
        checkStatus(st, "BCryptGenerateSymmetricKey");
    }

    void close() {
        if (hKey) { BCryptDestroyKey(hKey); hKey = nullptr; }
        if (hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; }
    }
};

// AES-CBC encrypt (returns ciphertext only, without IV)
static std::vector<uint8_t> aesCbcEncrypt(const uint8_t* key32,
                                            const uint8_t iv[16],
                                            const uint8_t* plaintext, size_t ptLen)
{
    AesContext ctx;
    ctx.open(key32, 32);

    // Make a mutable copy of IV (BCryptEncrypt modifies it)
    uint8_t ivCopy[16];
    memcpy(ivCopy, iv, 16);

    ULONG cbCipher = 0;
    BCryptEncrypt(ctx.hKey, (PUCHAR)plaintext, (ULONG)ptLen, NULL,
                  ivCopy, 16, NULL, 0, &cbCipher, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> cipher(cbCipher);
    ULONG cbResult = 0;
    memcpy(ivCopy, iv, 16);  // reset IV
    NTSTATUS st = BCryptEncrypt(ctx.hKey, (PUCHAR)plaintext, (ULONG)ptLen, NULL,
                                 ivCopy, 16, cipher.data(), cbCipher, &cbResult, BCRYPT_BLOCK_PADDING);
    checkStatus(st, "BCryptEncrypt");
    cipher.resize(cbResult);
    ctx.close();
    return cipher;
}

// AES-CBC decrypt
static std::vector<uint8_t> aesCbcDecrypt(const uint8_t* key32,
                                            const uint8_t iv[16],
                                            const uint8_t* ciphertext, size_t ctLen)
{
    AesContext ctx;
    ctx.open(key32, 32);

    uint8_t ivCopy[16];
    memcpy(ivCopy, iv, 16);

    ULONG cbPlain = 0;
    BCryptDecrypt(ctx.hKey, (PUCHAR)ciphertext, (ULONG)ctLen, NULL,
                  ivCopy, 16, NULL, 0, &cbPlain, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> plain(cbPlain);
    ULONG cbResult = 0;
    memcpy(ivCopy, iv, 16);
    NTSTATUS st = BCryptDecrypt(ctx.hKey, (PUCHAR)ciphertext, (ULONG)ctLen, NULL,
                                 ivCopy, 16, plain.data(), cbPlain, &cbResult, BCRYPT_BLOCK_PADDING);
    checkStatus(st, "BCryptDecrypt");
    plain.resize(cbResult);
    ctx.close();
    return plain;
}

// ============================================================
// TODO 1: Derive a 32-byte AES key from a password and salt using PBKDF2
//
// Steps:
//   a) Open HMAC-SHA256 provider:
//        BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL,
//                                    BCRYPT_ALG_HANDLE_HMAC_FLAG)
//   b) Call BCryptDeriveKeyPBKDF2:
//        BCryptDeriveKeyPBKDF2(hPrf,
//                              (PUCHAR)password, (ULONG)strlen(password),
//                              (PUCHAR)salt, (ULONG)SALT_LEN,
//                              PBKDF2_ITERATIONS,
//                              key, KEY_LEN, 0)
//   c) Close provider
//   d) Store result in key[KEY_LEN]
// ============================================================
static void deriveKey(const char* password,
                       const uint8_t salt[SALT_LEN],
                       uint8_t key[KEY_LEN])
{
    // TODO 1: implement PBKDF2 key derivation
    (void)password; (void)salt;
    memset(key, 0, KEY_LEN);  // remove when implemented — zeroed key is wrong
}

// ============================================================
// TODO 2: Encrypt a file
//
// File format: [salt 16B][IV 16B][ciphertext]
//
// Steps:
//   a) Generate random salt (genRandom)
//   b) Derive key from password + salt (deriveKey)
//   c) Generate random IV (genRandom)
//   d) Encrypt plaintext (aesCbcEncrypt)
//   e) Write salt + iv + ciphertext to outFile
// ============================================================
static void encryptFile(const char* inFile, const char* outFile, const char* password) {
    auto plaintext = readFile(inFile);

    // TODO 2a: Generate salt
    uint8_t salt[SALT_LEN]; // = { ... };

    // TODO 2b: Derive key
    uint8_t key[KEY_LEN]; // = { ... };

    // TODO 2c: Generate IV
    uint8_t iv[IV_LEN]; // = { ... };

    // TODO 2d: Encrypt
    // auto cipher = aesCbcEncrypt(key, iv, plaintext.data(), plaintext.size());

    // TODO 2e: Write [salt][iv][cipher] to outFile
    // std::vector<uint8_t> output;
    // output.insert(output.end(), salt, salt + SALT_LEN);
    // output.insert(output.end(), iv, iv + IV_LEN);
    // output.insert(output.end(), cipher.begin(), cipher.end());
    // writeFile(outFile, output);

    (void)outFile; (void)password;
    printf("TODO 2 not yet implemented — fill in encryptFile().\n");
}

// ============================================================
// TODO 3: Decrypt a file
//
// Steps:
//   a) Read the file
//   b) Split: first 16 bytes = salt, next 16 bytes = IV, rest = ciphertext
//   c) Derive key from password + salt
//   d) Decrypt ciphertext with aesCbcDecrypt
//   e) Write plaintext to outFile
// ============================================================
static void decryptFile(const char* inFile, const char* outFile, const char* password) {
    auto blob = readFile(inFile);
    if (blob.size() < SALT_LEN + IV_LEN + 16)
        throw std::runtime_error("File too small to be valid encrypted file");

    // TODO 3a: Split header
    // const uint8_t* salt       = blob.data();
    // const uint8_t* iv         = blob.data() + SALT_LEN;
    // const uint8_t* ciphertext = blob.data() + SALT_LEN + IV_LEN;
    // size_t cipherLen          = blob.size() - SALT_LEN - IV_LEN;

    // TODO 3b: Derive key
    // uint8_t key[KEY_LEN];
    // deriveKey(password, salt, key);

    // TODO 3c: Decrypt
    // auto plain = aesCbcDecrypt(key, iv, ciphertext, cipherLen);
    // writeFile(outFile, plain);

    (void)outFile; (void)password;
    printf("TODO 3 not yet implemented — fill in decryptFile().\n");
}

// ============================================================
// Main
// ============================================================
int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s enc <infile> <outfile> <password>\n", argv[0]);
        fprintf(stderr, "  %s dec <infile> <outfile> <password>\n", argv[0]);
        return 1;
    }
    const char* mode     = argv[1];
    const char* inFile   = argv[2];
    const char* outFile  = argv[3];
    const char* password = argv[4];

    try {
        if (strcmp(mode, "enc") == 0) {
            encryptFile(inFile, outFile, password);
            printf("Encrypted: %s -> %s\n", inFile, outFile);
        } else if (strcmp(mode, "dec") == 0) {
            decryptFile(inFile, outFile, password);
            printf("Decrypted: %s -> %s\n", inFile, outFile);
        } else {
            fprintf(stderr, "Unknown mode '%s'. Use 'enc' or 'dec'.\n", mode);
            return 1;
        }
    } catch (const std::exception& ex) {
        fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
    return 0;
}
