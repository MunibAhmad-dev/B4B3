// crypto_toolkit.cpp
// Module 31 — Crypto Implementation
// A complete, standalone crypto toolkit implementing:
//   - AES-256-CBC (Windows CNG, PBKDF2 key derivation, random IV)
//   - ChaCha20 stream cipher (pure C++, RFC 7539)
//   - RSA-2048 key generation, encrypt, decrypt (Windows CNG)
//
// Compile: g++ -std=c++17 -Wall -o crypto_toolkit.exe crypto_toolkit.cpp -lbcrypt
//
// Usage:
//   crypto_toolkit.exe aes enc    <infile> <outfile> <password>
//   crypto_toolkit.exe aes dec    <infile> <outfile> <password>
//   crypto_toolkit.exe chacha20 enc <infile> <outfile> <key_hex> <nonce_hex>
//   crypto_toolkit.exe rsa genkey  <privkey_file> <pubkey_file>
//   crypto_toolkit.exe rsa enc     <pubkey_file> <infile> <outfile>
//   crypto_toolkit.exe rsa dec     <privkey_file> <infile> <outfile>
//
// Key/nonce for chacha20 must be hex strings:
//   key_hex:   64 hex chars (32 bytes)
//   nonce_hex: 24 hex chars (12 bytes)

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <iterator>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

// ===========================================================
// Shared utilities
// ===========================================================

static void checkNT(NTSTATUS st, const char* msg) {
    if (!BCRYPT_SUCCESS(st)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: NTSTATUS=0x%08X", msg, (unsigned)st);
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
    f.write(reinterpret_cast<const char*>(data.data()), (std::streamsize)data.size());
    if (!f) throw std::runtime_error(std::string("Write failed: ") + path);
}

static void genRandom(uint8_t* buf, size_t len) {
    checkNT(BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG),
            "BCryptGenRandom");
}

// Hex encode/decode
static std::string toHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

static std::vector<uint8_t> fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::runtime_error("Hex string has odd length");
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int byte;
        if (sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1)
            throw std::runtime_error("Invalid hex character");
        out[i] = (uint8_t)byte;
    }
    return out;
}

// ===========================================================
// AES-256-CBC via Windows CNG
// File format: [magic 4B][salt 16B][IV 16B][ciphertext]
// ===========================================================

static const uint32_t AES_MAGIC      = 0x41455343u;  // "AESC"
static const size_t   AES_SALT_LEN   = 16;
static const size_t   AES_IV_LEN     = 16;
static const size_t   AES_KEY_LEN    = 32;
static const ULONGLONG AES_PBKDF2_IT = 200000;

struct AesCng {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::vector<uint8_t> keyObj;

    void open(const uint8_t* key, size_t keyLen) {
        checkNT(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0),
                "BCryptOpenAlgorithmProvider(AES)");
        checkNT(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                   (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                   sizeof(BCRYPT_CHAIN_MODE_CBC), 0),
                "BCryptSetProperty(CBC)");
        DWORD cbKeyObj = 0, cbRes = 0;
        checkNT(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                   (PBYTE)&cbKeyObj, sizeof(cbKeyObj), &cbRes, 0),
                "BCryptGetProperty(OBJECT_LENGTH)");
        keyObj.resize(cbKeyObj);
        checkNT(BCryptGenerateSymmetricKey(hAlg, &hKey,
                                            keyObj.data(), (ULONG)keyObj.size(),
                                            (PUCHAR)key, (ULONG)keyLen, 0),
                "BCryptGenerateSymmetricKey");
    }

    void close() {
        if (hKey) { BCryptDestroyKey(hKey); hKey = nullptr; }
        if (hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; }
    }
};

static void aesDerive(const char* password,
                       const uint8_t salt[AES_SALT_LEN],
                       uint8_t key[AES_KEY_LEN])
{
    BCRYPT_ALG_HANDLE hPrf = nullptr;
    checkNT(BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL,
                                         BCRYPT_ALG_HANDLE_HMAC_FLAG),
            "BCryptOpenAlgorithmProvider(HMAC-SHA256)");
    checkNT(BCryptDeriveKeyPBKDF2(hPrf,
                                   (PUCHAR)password, (ULONG)strlen(password),
                                   (PUCHAR)salt, (ULONG)AES_SALT_LEN,
                                   AES_PBKDF2_IT, key, (ULONG)AES_KEY_LEN, 0),
            "BCryptDeriveKeyPBKDF2");
    BCryptCloseAlgorithmProvider(hPrf, 0);
}

static std::vector<uint8_t> aesEncryptBuf(const uint8_t key[AES_KEY_LEN],
                                            const uint8_t iv[AES_IV_LEN],
                                            const uint8_t* pt, size_t ptLen)
{
    AesCng ctx;
    ctx.open(key, AES_KEY_LEN);
    uint8_t ivCopy[AES_IV_LEN];
    memcpy(ivCopy, iv, AES_IV_LEN);

    ULONG cbOut = 0;
    BCryptEncrypt(ctx.hKey, (PUCHAR)pt, (ULONG)ptLen, NULL,
                  ivCopy, (ULONG)AES_IV_LEN, NULL, 0, &cbOut, BCRYPT_BLOCK_PADDING);
    std::vector<uint8_t> out(cbOut);
    memcpy(ivCopy, iv, AES_IV_LEN);
    ULONG cbRes = 0;
    checkNT(BCryptEncrypt(ctx.hKey, (PUCHAR)pt, (ULONG)ptLen, NULL,
                           ivCopy, (ULONG)AES_IV_LEN,
                           out.data(), cbOut, &cbRes, BCRYPT_BLOCK_PADDING),
            "BCryptEncrypt");
    out.resize(cbRes);
    ctx.close();
    return out;
}

static std::vector<uint8_t> aesDecryptBuf(const uint8_t key[AES_KEY_LEN],
                                            const uint8_t iv[AES_IV_LEN],
                                            const uint8_t* ct, size_t ctLen)
{
    AesCng ctx;
    ctx.open(key, AES_KEY_LEN);
    uint8_t ivCopy[AES_IV_LEN];
    memcpy(ivCopy, iv, AES_IV_LEN);

    ULONG cbOut = 0;
    BCryptDecrypt(ctx.hKey, (PUCHAR)ct, (ULONG)ctLen, NULL,
                  ivCopy, (ULONG)AES_IV_LEN, NULL, 0, &cbOut, BCRYPT_BLOCK_PADDING);
    std::vector<uint8_t> out(cbOut);
    memcpy(ivCopy, iv, AES_IV_LEN);
    ULONG cbRes = 0;
    checkNT(BCryptDecrypt(ctx.hKey, (PUCHAR)ct, (ULONG)ctLen, NULL,
                           ivCopy, (ULONG)AES_IV_LEN,
                           out.data(), cbOut, &cbRes, BCRYPT_BLOCK_PADDING),
            "BCryptDecrypt");
    out.resize(cbRes);
    ctx.close();
    return out;
}

// Write magic + salt + IV + ciphertext
static void aesEncryptFile(const char* inPath, const char* outPath, const char* password) {
    auto plaintext = readFile(inPath);

    uint8_t salt[AES_SALT_LEN], iv[AES_IV_LEN], key[AES_KEY_LEN];
    genRandom(salt, AES_SALT_LEN);
    genRandom(iv, AES_IV_LEN);

    fprintf(stderr, "Deriving AES key (PBKDF2, %llu rounds)...\n", AES_PBKDF2_IT);
    aesDerive(password, salt, key);

    auto cipher = aesEncryptBuf(key, iv, plaintext.data(), plaintext.size());
    SecureZeroMemory(key, AES_KEY_LEN);

    std::vector<uint8_t> out;
    out.reserve(4 + AES_SALT_LEN + AES_IV_LEN + cipher.size());
    // Magic
    out.push_back((AES_MAGIC)       & 0xFF);
    out.push_back((AES_MAGIC >> 8)  & 0xFF);
    out.push_back((AES_MAGIC >> 16) & 0xFF);
    out.push_back((AES_MAGIC >> 24) & 0xFF);
    out.insert(out.end(), salt,   salt   + AES_SALT_LEN);
    out.insert(out.end(), iv,     iv     + AES_IV_LEN);
    out.insert(out.end(), cipher.begin(), cipher.end());

    writeFile(outPath, out);
    fprintf(stderr, "AES enc: %zu -> %zu bytes\n", plaintext.size(), out.size());
}

static void aesDecryptFile(const char* inPath, const char* outPath, const char* password) {
    auto blob = readFile(inPath);
    const size_t HDR = 4 + AES_SALT_LEN + AES_IV_LEN;
    if (blob.size() < HDR + 16)
        throw std::runtime_error("File too small or not AES-encrypted");

    uint32_t magic = (uint32_t)blob[0] | ((uint32_t)blob[1] << 8) |
                     ((uint32_t)blob[2] << 16) | ((uint32_t)blob[3] << 24);
    if (magic != AES_MAGIC)
        throw std::runtime_error("File magic mismatch (not an AES-encrypted file)");

    const uint8_t* salt       = blob.data() + 4;
    const uint8_t* iv         = blob.data() + 4 + AES_SALT_LEN;
    const uint8_t* ciphertext = blob.data() + HDR;
    size_t         cipherLen  = blob.size() - HDR;

    uint8_t key[AES_KEY_LEN];
    fprintf(stderr, "Deriving AES key (PBKDF2, %llu rounds)...\n", AES_PBKDF2_IT);
    aesDerive(password, salt, key);

    auto plain = aesDecryptBuf(key, iv, ciphertext, cipherLen);
    SecureZeroMemory(key, AES_KEY_LEN);

    writeFile(outPath, plain);
    fprintf(stderr, "AES dec: %zu -> %zu bytes\n", blob.size(), plain.size());
}

// ===========================================================
// ChaCha20 — pure C++, RFC 7539
// File format: [counter_u32 LE 4B][ciphertext]
// (Key and nonce are provided on command line as hex)
// ===========================================================

static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

static inline uint32_t cc20_load32(const uint8_t* p) {
    return (uint32_t)p[0]         | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void cc20_store32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static const uint32_t CC20_C[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};

static inline void cc20_qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

static void cc20_block(const uint8_t key[32], uint32_t counter,
                        const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t s[16];
    s[0] = CC20_C[0]; s[1] = CC20_C[1]; s[2] = CC20_C[2]; s[3] = CC20_C[3];
    for (int i = 0; i < 8; ++i) s[4 + i] = cc20_load32(key + i * 4);
    s[12] = counter;
    for (int i = 0; i < 3; ++i) s[13 + i] = cc20_load32(nonce + i * 4);

    uint32_t init[16];
    memcpy(init, s, sizeof(s));

    for (int r = 0; r < 10; ++r) {
        cc20_qr(s[0], s[4], s[8],  s[12]);
        cc20_qr(s[1], s[5], s[9],  s[13]);
        cc20_qr(s[2], s[6], s[10], s[14]);
        cc20_qr(s[3], s[7], s[11], s[15]);
        cc20_qr(s[0], s[5], s[10], s[15]);
        cc20_qr(s[1], s[6], s[11], s[12]);
        cc20_qr(s[2], s[7], s[8],  s[13]);
        cc20_qr(s[3], s[4], s[9],  s[14]);
    }
    for (int i = 0; i < 16; ++i) s[i] += init[i];
    for (int i = 0; i < 16; ++i) cc20_store32(out + i * 4, s[i]);
}

// XOR input with ChaCha20 keystream (encrypt == decrypt)
static std::vector<uint8_t> cc20_crypt(const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        uint32_t counter,
                                        const uint8_t* data, size_t dataLen)
{
    std::vector<uint8_t> out(dataLen);
    uint8_t block[64];
    size_t pos = 0;
    while (pos < dataLen) {
        cc20_block(key, counter++, nonce, block);
        size_t take = dataLen - pos;
        if (take > 64) take = 64;
        for (size_t i = 0; i < take; ++i) out[pos + i] = data[pos + i] ^ block[i];
        pos += take;
    }
    return out;
}

static void chacha20EncFile(const char* inPath, const char* outPath,
                             const std::vector<uint8_t>& key,
                             const std::vector<uint8_t>& nonce)
{
    if (key.size() != 32)   throw std::runtime_error("ChaCha20 key must be 32 bytes (64 hex chars)");
    if (nonce.size() != 12) throw std::runtime_error("ChaCha20 nonce must be 12 bytes (24 hex chars)");

    auto plaintext = readFile(inPath);
    uint32_t counter = 0;

    auto cipher = cc20_crypt(key.data(), nonce.data(), counter, plaintext.data(), plaintext.size());

    // Prepend counter (LE 4 bytes) so decryption knows where to start
    std::vector<uint8_t> out;
    out.reserve(4 + cipher.size());
    out.push_back((counter)       & 0xFF);
    out.push_back((counter >> 8)  & 0xFF);
    out.push_back((counter >> 16) & 0xFF);
    out.push_back((counter >> 24) & 0xFF);
    out.insert(out.end(), cipher.begin(), cipher.end());
    writeFile(outPath, out);
    fprintf(stderr, "ChaCha20 enc: %zu -> %zu bytes\n", plaintext.size(), out.size());
}

// Decrypt = same operation (XOR again with same stream)
static void chacha20DecFile(const char* inPath, const char* outPath,
                             const std::vector<uint8_t>& key,
                             const std::vector<uint8_t>& nonce)
{
    if (key.size() != 32)   throw std::runtime_error("ChaCha20 key must be 32 bytes (64 hex chars)");
    if (nonce.size() != 12) throw std::runtime_error("ChaCha20 nonce must be 12 bytes (24 hex chars)");

    auto blob = readFile(inPath);
    if (blob.size() < 4) throw std::runtime_error("File too small");

    uint32_t counter = (uint32_t)blob[0] | ((uint32_t)blob[1] << 8) |
                       ((uint32_t)blob[2] << 16) | ((uint32_t)blob[3] << 24);
    const uint8_t* ct    = blob.data() + 4;
    size_t         ctLen = blob.size() - 4;

    auto plain = cc20_crypt(key.data(), nonce.data(), counter, ct, ctLen);
    writeFile(outPath, plain);
    fprintf(stderr, "ChaCha20 dec: %zu -> %zu bytes\n", blob.size(), plain.size());
}

// ===========================================================
// RSA-2048 via Windows CNG
// Key files: raw BCRYPT_RSAPUBLIC_BLOB / BCRYPT_RSAFULLPRIVATE_BLOB
// ===========================================================

static void rsaGenKey(const char* privPath, const char* pubPath) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    checkNT(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0),
            "BCryptOpenAlgorithmProvider(RSA)");
    checkNT(BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0),
            "BCryptGenerateKeyPair");
    checkNT(BCryptFinalizeKeyPair(hKey, 0),
            "BCryptFinalizeKeyPair");
    fprintf(stderr, "RSA-2048 key pair generated.\n");

    // Export public key
    ULONG cbPub = 0;
    checkNT(BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cbPub, 0),
            "BCryptExportKey(pub, size)");
    std::vector<uint8_t> pubBlob(cbPub);
    checkNT(BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, pubBlob.data(), cbPub, &cbPub, 0),
            "BCryptExportKey(pub)");

    // Export private key
    ULONG cbPriv = 0;
    checkNT(BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &cbPriv, 0),
            "BCryptExportKey(priv, size)");
    std::vector<uint8_t> privBlob(cbPriv);
    checkNT(BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB,
                             privBlob.data(), cbPriv, &cbPriv, 0),
            "BCryptExportKey(priv)");

    writeFile(pubPath,  pubBlob);
    writeFile(privPath, privBlob);

    fprintf(stderr, "Public key:  %s (%u bytes)\n", pubPath,  cbPub);
    fprintf(stderr, "Private key: %s (%u bytes)\n", privPath, cbPriv);

    SecureZeroMemory(privBlob.data(), privBlob.size());
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

static void rsaEncFile(const char* pubKeyPath, const char* inPath, const char* outPath) {
    auto pubBlob  = readFile(pubKeyPath);
    auto plaintext = readFile(inPath);

    // RSA-2048 PKCS1 max payload = 256 - 11 = 245 bytes
    if (plaintext.size() > 245)
        throw std::runtime_error("RSA plaintext too large (max 245 bytes for RSA-2048 PKCS#1 v1.5)");

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    checkNT(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0),
            "BCryptOpenAlgorithmProvider(RSA)");
    checkNT(BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey,
                                 pubBlob.data(), (ULONG)pubBlob.size(), 0),
            "BCryptImportKeyPair(pub)");

    BCRYPT_PKCS1_PADDING_INFO pi = {};
    pi.pszAlgId = NULL;

    ULONG cbOut = 0;
    BCryptEncrypt(hKey, plaintext.data(), (ULONG)plaintext.size(),
                  &pi, NULL, 0, NULL, 0, &cbOut, BCRYPT_PAD_PKCS1);

    std::vector<uint8_t> cipher(cbOut);
    ULONG cbRes = 0;
    checkNT(BCryptEncrypt(hKey, plaintext.data(), (ULONG)plaintext.size(),
                           &pi, NULL, 0, cipher.data(), cbOut, &cbRes, BCRYPT_PAD_PKCS1),
            "BCryptEncrypt(RSA)");
    cipher.resize(cbRes);

    writeFile(outPath, cipher);
    fprintf(stderr, "RSA enc: %zu -> %zu bytes\n", plaintext.size(), cipher.size());

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

static void rsaDecFile(const char* privKeyPath, const char* inPath, const char* outPath) {
    auto privBlob   = readFile(privKeyPath);
    auto ciphertext = readFile(inPath);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    checkNT(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0),
            "BCryptOpenAlgorithmProvider(RSA)");
    checkNT(BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, &hKey,
                                 privBlob.data(), (ULONG)privBlob.size(), 0),
            "BCryptImportKeyPair(priv)");

    BCRYPT_PKCS1_PADDING_INFO pi = {};
    pi.pszAlgId = NULL;

    ULONG cbOut = 0;
    BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(),
                  &pi, NULL, 0, NULL, 0, &cbOut, BCRYPT_PAD_PKCS1);

    std::vector<uint8_t> plain(cbOut);
    ULONG cbRes = 0;
    checkNT(BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(),
                           &pi, NULL, 0, plain.data(), cbOut, &cbRes, BCRYPT_PAD_PKCS1),
            "BCryptDecrypt(RSA)");
    plain.resize(cbRes);

    writeFile(outPath, plain);
    SecureZeroMemory(privBlob.data(), privBlob.size());
    fprintf(stderr, "RSA dec: %zu -> %zu bytes\n", ciphertext.size(), plain.size());

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

// ===========================================================
// CLI entry point
// ===========================================================

static void usage(const char* prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s aes enc    <infile> <outfile> <password>\n"
        "  %s aes dec    <infile> <outfile> <password>\n"
        "  %s chacha20 enc <infile> <outfile> <key_hex_64chars> <nonce_hex_24chars>\n"
        "  %s chacha20 dec <infile> <outfile> <key_hex_64chars> <nonce_hex_24chars>\n"
        "  %s rsa genkey  <privkey_file> <pubkey_file>\n"
        "  %s rsa enc     <pubkey_file> <infile> <outfile>\n"
        "  %s rsa dec     <privkey_file> <infile> <outfile>\n",
        prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char* argv[]) {
    if (argc < 3) { usage(argv[0]); return 1; }

    const std::string cipher = argv[1];
    const std::string op     = argv[2];

    try {
        // ---- AES ----
        if (cipher == "aes") {
            if (argc != 6) { usage(argv[0]); return 1; }
            const char* in   = argv[3];
            const char* out  = argv[4];
            const char* pass = argv[5];
            if (op == "enc")      aesEncryptFile(in, out, pass);
            else if (op == "dec") aesDecryptFile(in, out, pass);
            else { fprintf(stderr, "Unknown aes op '%s'\n", op.c_str()); return 1; }
        }

        // ---- ChaCha20 ----
        else if (cipher == "chacha20") {
            if (argc != 7) { usage(argv[0]); return 1; }
            const char* in    = argv[3];
            const char* out   = argv[4];
            auto key   = fromHex(argv[5]);
            auto nonce = fromHex(argv[6]);
            // Encrypt and decrypt are the same XOR operation
            if (op == "enc")      chacha20EncFile(in, out, key, nonce);
            else if (op == "dec") chacha20DecFile(in, out, key, nonce);
            else { fprintf(stderr, "Unknown chacha20 op '%s'\n", op.c_str()); return 1; }
        }

        // ---- RSA ----
        else if (cipher == "rsa") {
            if (op == "genkey") {
                if (argc != 5) { usage(argv[0]); return 1; }
                rsaGenKey(argv[3], argv[4]);
            } else if (op == "enc") {
                if (argc != 6) { usage(argv[0]); return 1; }
                rsaEncFile(argv[3], argv[4], argv[5]);
            } else if (op == "dec") {
                if (argc != 6) { usage(argv[0]); return 1; }
                rsaDecFile(argv[3], argv[4], argv[5]);
            } else {
                fprintf(stderr, "Unknown rsa op '%s'\n", op.c_str());
                return 1;
            }
        }

        else {
            fprintf(stderr, "Unknown cipher '%s'\n", cipher.c_str());
            usage(argv[0]);
            return 1;
        }

    } catch (const std::exception& ex) {
        fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
    return 0;
}
