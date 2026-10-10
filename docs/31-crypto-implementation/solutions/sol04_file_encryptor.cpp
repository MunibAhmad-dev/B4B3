// solutions/sol04_file_encryptor.cpp
// Module 31 — Crypto Implementation
// Solution: File encryption tool with PBKDF2 + AES-256-CBC
//
// Compile: g++ -std=c++17 -Wall -o sol04.exe sol04_file_encryptor.cpp -lbcrypt
//
// Usage:
//   sol04.exe enc <infile> <outfile> <password>
//   sol04.exe dec <infile> <outfile> <password>
//
// File format: [salt 16B][IV 16B][ciphertext (PKCS7-padded)]

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
static const size_t SALT_LEN   = 16;
static const size_t IV_LEN     = 16;
static const size_t KEY_LEN    = 32;  // AES-256
static const ULONGLONG ITERS   = 200000;

// ---- helpers ----
static void checkStatus(NTSTATUS status, const char* msg) {
    if (!BCRYPT_SUCCESS(status)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: NTSTATUS=0x%08X", msg, (unsigned)status);
        throw std::runtime_error(buf);
    }
}

static std::vector<uint8_t> readFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error(std::string("Cannot open: ") + path);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

static void writeFile(const char* path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error(std::string("Cannot write: ") + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static void genRandom(uint8_t* buf, size_t len) {
    checkStatus(BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                "BCryptGenRandom");
}

// ---- AES-CBC context ----
struct AesCtx {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::vector<uint8_t> keyObj;

    void open(const uint8_t* key, size_t keyLen) {
        checkStatus(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0),
                    "BCryptOpenAlgorithmProvider");
        checkStatus(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                       (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                       sizeof(BCRYPT_CHAIN_MODE_CBC), 0),
                    "BCryptSetProperty(CBC)");
        DWORD cbKeyObj = 0, cbResult = 0;
        checkStatus(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                       (PBYTE)&cbKeyObj, sizeof(cbKeyObj), &cbResult, 0),
                    "BCryptGetProperty");
        keyObj.resize(cbKeyObj);
        checkStatus(BCryptGenerateSymmetricKey(hAlg, &hKey,
                                                keyObj.data(), (ULONG)keyObj.size(),
                                                (PUCHAR)key, (ULONG)keyLen, 0),
                    "BCryptGenerateSymmetricKey");
    }

    void close() {
        if (hKey) { BCryptDestroyKey(hKey); hKey = nullptr; }
        if (hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; }
    }
};

// ---- PBKDF2-HMAC-SHA256 key derivation ----
static void deriveKey(const char* password,
                       const uint8_t salt[SALT_LEN],
                       uint8_t key[KEY_LEN])
{
    BCRYPT_ALG_HANDLE hPrf = nullptr;
    checkStatus(BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL,
                                             BCRYPT_ALG_HANDLE_HMAC_FLAG),
                "BCryptOpenAlgorithmProvider(HMAC-SHA256)");

    checkStatus(BCryptDeriveKeyPBKDF2(hPrf,
                                       (PUCHAR)password, (ULONG)strlen(password),
                                       (PUCHAR)salt, (ULONG)SALT_LEN,
                                       ITERS,
                                       key, (ULONG)KEY_LEN, 0),
                "BCryptDeriveKeyPBKDF2");

    BCryptCloseAlgorithmProvider(hPrf, 0);
}

// ---- AES-CBC encrypt ----
static std::vector<uint8_t> aesCbcEncrypt(const uint8_t key[KEY_LEN],
                                            const uint8_t iv[IV_LEN],
                                            const uint8_t* pt, size_t ptLen)
{
    AesCtx ctx;
    ctx.open(key, KEY_LEN);

    uint8_t ivCopy[IV_LEN];
    memcpy(ivCopy, iv, IV_LEN);

    ULONG cbOut = 0;
    BCryptEncrypt(ctx.hKey, (PUCHAR)pt, (ULONG)ptLen, NULL,
                  ivCopy, (ULONG)IV_LEN, NULL, 0, &cbOut, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> out(cbOut);
    memcpy(ivCopy, iv, IV_LEN);
    ULONG cbResult = 0;
    checkStatus(BCryptEncrypt(ctx.hKey, (PUCHAR)pt, (ULONG)ptLen, NULL,
                               ivCopy, (ULONG)IV_LEN,
                               out.data(), cbOut, &cbResult, BCRYPT_BLOCK_PADDING),
                "BCryptEncrypt");
    out.resize(cbResult);
    ctx.close();
    return out;
}

// ---- AES-CBC decrypt ----
static std::vector<uint8_t> aesCbcDecrypt(const uint8_t key[KEY_LEN],
                                            const uint8_t iv[IV_LEN],
                                            const uint8_t* ct, size_t ctLen)
{
    AesCtx ctx;
    ctx.open(key, KEY_LEN);

    uint8_t ivCopy[IV_LEN];
    memcpy(ivCopy, iv, IV_LEN);

    ULONG cbOut = 0;
    BCryptDecrypt(ctx.hKey, (PUCHAR)ct, (ULONG)ctLen, NULL,
                  ivCopy, (ULONG)IV_LEN, NULL, 0, &cbOut, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> out(cbOut);
    memcpy(ivCopy, iv, IV_LEN);
    ULONG cbResult = 0;
    checkStatus(BCryptDecrypt(ctx.hKey, (PUCHAR)ct, (ULONG)ctLen, NULL,
                               ivCopy, (ULONG)IV_LEN,
                               out.data(), cbOut, &cbResult, BCRYPT_BLOCK_PADDING),
                "BCryptDecrypt");
    out.resize(cbResult);
    ctx.close();
    return out;
}

// ---- Encrypt file ----
static void encryptFile(const char* inFile, const char* outFile, const char* password) {
    auto plaintext = readFile(inFile);
    printf("Plaintext size: %zu bytes\n", plaintext.size());

    // Generate salt and IV
    uint8_t salt[SALT_LEN], iv[IV_LEN];
    genRandom(salt, SALT_LEN);
    genRandom(iv, IV_LEN);

    // Derive key
    uint8_t key[KEY_LEN];
    printf("Deriving key (PBKDF2-HMAC-SHA256, %llu iterations)...\n", ITERS);
    deriveKey(password, salt, key);

    // Encrypt
    auto cipher = aesCbcEncrypt(key, iv, plaintext.data(), plaintext.size());

    // Write [salt][iv][ciphertext]
    std::vector<uint8_t> output;
    output.reserve(SALT_LEN + IV_LEN + cipher.size());
    output.insert(output.end(), salt, salt + SALT_LEN);
    output.insert(output.end(), iv,   iv   + IV_LEN);
    output.insert(output.end(), cipher.begin(), cipher.end());

    writeFile(outFile, output);
    printf("Encrypted: %zu -> %zu bytes (salt+IV+cipher)\n",
           plaintext.size(), output.size());

    // Security: zero key material
    SecureZeroMemory(key, sizeof(key));
}

// ---- Decrypt file ----
static void decryptFile(const char* inFile, const char* outFile, const char* password) {
    auto blob = readFile(inFile);
    if (blob.size() < SALT_LEN + IV_LEN + 16)
        throw std::runtime_error("File too small; not a valid encrypted file");

    const uint8_t* salt       = blob.data();
    const uint8_t* iv         = blob.data() + SALT_LEN;
    const uint8_t* ciphertext = blob.data() + SALT_LEN + IV_LEN;
    size_t cipherLen          = blob.size() - SALT_LEN - IV_LEN;

    // Derive key from same salt
    uint8_t key[KEY_LEN];
    printf("Deriving key (PBKDF2-HMAC-SHA256, %llu iterations)...\n", ITERS);
    deriveKey(password, salt, key);

    // Decrypt
    auto plain = aesCbcDecrypt(key, iv, ciphertext, cipherLen);
    writeFile(outFile, plain);
    printf("Decrypted: %zu -> %zu bytes\n", blob.size(), plain.size());

    SecureZeroMemory(key, sizeof(key));
}

// ---- main ----
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
        } else if (strcmp(mode, "dec") == 0) {
            decryptFile(inFile, outFile, password);
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
