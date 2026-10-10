// solutions/sol02_chacha20.cpp
// Module 31 — Crypto Implementation
// Solution: ChaCha20 stream cipher — pure C++ from RFC 7539
//
// Compile: g++ -std=c++17 -Wall -o sol02.exe sol02_chacha20.cpp
// No external dependencies.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

// ---- helpers ----
static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    printf("\n");
}

static inline uint32_t le32load(const uint8_t* p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16)| ((uint32_t)p[3] << 24);
}

static inline void le32store(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);  p[3] = (uint8_t)(v >> 24);
}

// ---- ChaCha20 constants (ASCII "expand 32-byte k") ----
static const uint32_t CC[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};

// ---- Quarter round (RFC 7539 §2.1) ----
static inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

// ---- ChaCha20 block function (RFC 7539 §2.3) ----
// Produces 64 bytes of keystream.
static void chachaBlock(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12], uint8_t out[64])
{
    // Initialize state
    uint32_t s[16];
    s[0] = CC[0]; s[1] = CC[1]; s[2] = CC[2]; s[3] = CC[3];
    for (int i = 0; i < 8; ++i) s[4 + i] = le32load(key + i * 4);
    s[12] = counter;
    for (int i = 0; i < 3; ++i) s[13 + i] = le32load(nonce + i * 4);

    // Save initial state for final addition
    uint32_t init[16];
    memcpy(init, s, sizeof(s));

    // 20 rounds = 10 double-rounds
    for (int i = 0; i < 10; ++i) {
        // Column rounds
        quarterRound(s[0], s[4], s[8],  s[12]);
        quarterRound(s[1], s[5], s[9],  s[13]);
        quarterRound(s[2], s[6], s[10], s[14]);
        quarterRound(s[3], s[7], s[11], s[15]);
        // Diagonal rounds
        quarterRound(s[0], s[5], s[10], s[15]);
        quarterRound(s[1], s[6], s[11], s[12]);
        quarterRound(s[2], s[7], s[8],  s[13]);
        quarterRound(s[3], s[4], s[9],  s[14]);
    }

    // Add initial state
    for (int i = 0; i < 16; ++i) s[i] += init[i];

    // Serialize to bytes (little-endian)
    for (int i = 0; i < 16; ++i) le32store(out + i * 4, s[i]);
}

// ---- Generate N bytes of keystream ----
static std::vector<uint8_t> generateKeystream(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               uint32_t counter,
                                               size_t length)
{
    std::vector<uint8_t> ks;
    ks.reserve(length);

    uint8_t block[64];
    while (ks.size() < length) {
        chachaBlock(key, counter++, nonce, block);
        size_t remaining = length - ks.size();
        size_t take = remaining < 64 ? remaining : 64;
        ks.insert(ks.end(), block, block + take);
    }
    return ks;
}

// ---- ChaCha20 encrypt/decrypt (same operation — XOR) ----
static std::vector<uint8_t> chacha20(const uint8_t key[32],
                                      const uint8_t nonce[12],
                                      uint32_t counter,
                                      const uint8_t* input,
                                      size_t inputLen)
{
    auto ks = generateKeystream(key, nonce, counter, inputLen);
    std::vector<uint8_t> output(inputLen);
    for (size_t i = 0; i < inputLen; ++i) output[i] = input[i] ^ ks[i];
    return output;
}

// ---- main: RFC 7539 test vectors + round-trip ----
int main() {
    printf("=== ChaCha20 (RFC 7539) ===\n\n");

    // ---- Test 1: Quarter round (RFC 7539 §2.1.1) ----
    {
        uint32_t a = 0x11111111u, b = 0x01020304u;
        uint32_t c = 0x9b8d6f43u, d = 0x01234567u;
        quarterRound(a, b, c, d);
        bool pass = (a == 0xea2a92f4u && b == 0xcb1cf8ceu &&
                     c == 0x4581472eu && d == 0x5881c4bbu);
        printf("[quarterRound §2.1.1] %s\n", pass ? "PASS" : "FAIL");
        printf("  result: %08x %08x %08x %08x\n", a, b, c, d);
        printf("  expect: ea2a92f4 cb1cf8ce 4581472e 5881c4bb\n\n");
    }

    // ---- Test 2: Block function (RFC 7539 §2.3.2) ----
    {
        uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        memset(nonce, 0, 12);
        nonce[3] = 0x09; nonce[7] = 0x4a;  // 00000009 0000004a 00000000

        uint8_t block[64];
        chachaBlock(key, 1, nonce, block);

        // Expected first 16 bytes from RFC 7539 §2.3.2:
        static const uint8_t expected[16] = {
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4
        };
        bool pass = (memcmp(block, expected, 16) == 0);
        printf("[chachaBlock §2.3.2] %s\n", pass ? "PASS" : "FAIL");
        printHex("  first 16B got ", block, 16);
        printHex("  first 16B exp ", expected, 16);
        printf("\n");
    }

    // ---- Test 3: Encryption (RFC 7539 §2.4.2) ----
    {
        // Key and nonce from §2.4.2
        uint8_t key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        uint8_t nonce[12] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        };

        // Plaintext from §2.4.2
        const char* pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        size_t ptLen = strlen(pt);

        // Expected ciphertext first 16 bytes from §2.4.2:
        static const uint8_t expFirst16[16] = {
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81
        };

        auto cipher = chacha20(key, nonce, 1, (const uint8_t*)pt, ptLen);
        bool pass = (memcmp(cipher.data(), expFirst16, 16) == 0);
        printf("[encrypt §2.4.2    ] %s\n", pass ? "PASS" : "FAIL");
        printHex("  cipher[0..15] got", cipher.data(), 16);
        printHex("  cipher[0..15] exp", expFirst16, 16);
        printf("\n");

        // Round-trip
        auto recovered = chacha20(key, nonce, 1, cipher.data(), cipher.size());
        recovered.push_back(0);
        bool rt = (strcmp((char*)recovered.data(), pt) == 0);
        printf("[roundtrip         ] %s\n\n", rt ? "PASS" : "FAIL");
    }

    // ---- Test 4: Custom round-trip ----
    {
        uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 17 + 5);
        for (int i = 0; i < 12; ++i) nonce[i] = (uint8_t)(i * 31 + 7);

        const char* msg = "Module 31: ChaCha20 encrypt/decrypt test.";
        auto ct = chacha20(key, nonce, 0, (const uint8_t*)msg, strlen(msg));
        auto pt = chacha20(key, nonce, 0, ct.data(), ct.size());
        pt.push_back(0);
        bool pass = (strcmp((char*)pt.data(), msg) == 0);
        printf("[custom roundtrip  ] %s\n", pass ? "PASS" : "FAIL");
        printHex("  ciphertext", ct.data(), ct.size());
    }

    return 0;
}
