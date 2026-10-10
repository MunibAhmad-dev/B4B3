// exercise_02_chacha20.cpp
// Module 31 — Crypto Implementation
// Exercise: ChaCha20 stream cipher — pure C++ from RFC 7539
//
// Compile: g++ -std=c++17 -Wall -o ex02.exe exercise_02_chacha20.cpp
// No external dependencies.
//
// Your task: implement the four TODO functions that build up ChaCha20:
//   1. quarterRound()   — the core 4-word mixing operation
//   2. chachaBlock()    — 20-round block function producing 64 keystream bytes
//   3. keystream()      — generate N bytes of keystream for a given key/nonce/counter
//   4. chacha20()       — XOR plaintext/ciphertext with the keystream

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

// ---------------------------------------------------------------
// Helpers (do not modify)
// ---------------------------------------------------------------
static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    printf("\n");
}

static void printWords(const char* label, const uint32_t* words, int n) {
    printf("%s:\n", label);
    for (int i = 0; i < n; ++i) {
        printf("  [%02d] 0x%08x\n", i, words[i]);
    }
}

// Little-endian 32-bit load/store
static inline uint32_t le32load(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void le32store(uint8_t* p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}

// ---------------------------------------------------------------
// ChaCha20 constants — ASCII "expand 32-byte k"
// ---------------------------------------------------------------
static const uint32_t CHACHA_CONSTANTS[4] = {
    0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
};

// ---------------------------------------------------------------
// TODO 1: Implement the ChaCha20 quarter round
//
// The quarter round takes four 32-bit words a, b, c, d (by reference)
// and mixes them with four iterations of: add, XOR, rotate.
//
// From RFC 7539 Section 2.1:
//   a += b; d ^= a; d <<<= 16;
//   c += d; b ^= c; b <<<= 12;
//   a += b; d ^= a; d <<<= 8;
//   c += d; b ^= c; b <<<= 7;
//
// Use rotl32(x, n) defined above for rotations.
// ---------------------------------------------------------------
static void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    // TODO: implement quarter round
    (void)a; (void)b; (void)c; (void)d;
}

// ---------------------------------------------------------------
// TODO 2: Implement the ChaCha20 block function
//
// Inputs:
//   key      — 32-byte (256-bit) key
//   counter  — 32-bit block counter (starts at 0 or 1 per RFC)
//   nonce    — 12-byte (96-bit) nonce
//
// Output:
//   out[64]  — 64 bytes of keystream
//
// Steps:
//   1. Initialize 16-word state:
//        state[0..3]  = CHACHA_CONSTANTS
//        state[4..11] = key (8 little-endian words)
//        state[12]    = counter
//        state[13..15] = nonce (3 little-endian words)
//   2. Copy state to working (initial_state and working both needed for final add)
//   3. Run 20 rounds = 10 * (column round + diagonal round):
//        Column round:   QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
//        Diagonal round: QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
//   4. Add initial_state to working, word by word (mod 2^32)
//   5. Serialize working to out[] in little-endian order
// ---------------------------------------------------------------
static void chachaBlock(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12], uint8_t out[64])
{
    // TODO: implement block function
    (void)key; (void)counter; (void)nonce;
    memset(out, 0, 64);  // remove when implemented
}

// ---------------------------------------------------------------
// TODO 3: Generate 'length' bytes of keystream
//
// Inputs:
//   key     — 32-byte key
//   nonce   — 12-byte nonce
//   counter — starting block counter
//   length  — total bytes of keystream needed
//
// Output: returned vector of 'length' bytes
//
// Hint: call chachaBlock() in a loop, incrementing counter each call.
//       Each call produces 64 bytes; copy only what is needed for the
//       final partial block.
// ---------------------------------------------------------------
static std::vector<uint8_t> generateKeystream(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               uint32_t counter,
                                               size_t length)
{
    std::vector<uint8_t> ks(length, 0);
    // TODO: generate keystream bytes
    (void)key; (void)nonce; (void)counter;
    return ks;
}

// ---------------------------------------------------------------
// TODO 4: Encrypt (or decrypt — same operation) a message
//
// XOR each byte of input with the corresponding keystream byte.
// Return the result as a vector.
// ---------------------------------------------------------------
static std::vector<uint8_t> chacha20(const uint8_t key[32],
                                      const uint8_t nonce[12],
                                      uint32_t counter,
                                      const uint8_t* input,
                                      size_t inputLen)
{
    // TODO: generate keystream of inputLen bytes, XOR with input
    (void)key; (void)nonce; (void)counter;
    std::vector<uint8_t> output(input, input + inputLen);
    return output;  // currently returns plaintext unchanged — fix this
}

// ---------------------------------------------------------------
// Main — tests against RFC 7539 Section 2.4.2 test vector
//        and a round-trip encrypt/decrypt check.
// ---------------------------------------------------------------
int main() {
    // ----- RFC 7539 Section 2.1.1: Quarter round test -----
    {
        uint32_t a = 0x11111111u, b = 0x01020304u;
        uint32_t c = 0x9b8d6f43u, d = 0x01234567u;
        quarterRound(a, b, c, d);
        // Expected (RFC 7539 §2.1.1):
        const uint32_t ea = 0xea2a92f4u, eb = 0xcb1cf8ceu;
        const uint32_t ec = 0x4581472eu, ed = 0x5881c4bbu;
        bool pass = (a == ea && b == eb && c == ec && d == ed);
        printf("[quarterRound] %s\n", pass ? "PASS" : "FAIL - implement TODO 1");
        if (!pass) printf("  got: %08x %08x %08x %08x\n  exp: %08x %08x %08x %08x\n",
                          a, b, c, d, ea, eb, ec, ed);
    }

    // ----- RFC 7539 Section 2.3.2: block function test (first 4 output words) -----
    {
        uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        memset(nonce, 0, 12);
        nonce[3] = 0x09; nonce[7] = 0x4a;  // 00000009 0000004a 00000000

        uint8_t block[64];
        chachaBlock(key, 1, nonce, block);

        // Expected first 4 words (RFC 7539 §2.3.2):
        uint32_t w0 = le32load(block + 0);
        uint32_t w1 = le32load(block + 4);
        uint32_t w2 = le32load(block + 8);
        uint32_t w3 = le32load(block + 12);
        bool pass = (w0 == 0xe4e7f110u && w1 == 0x15593bd1u &&
                     w2 == 0x1fdd0f50u && w3 == 0xc47120a3u);
        printf("[chachaBlock ] %s\n", pass ? "PASS" : "FAIL - implement TODO 2");
        if (!pass) printf("  got: %08x %08x %08x %08x\n  exp: e4e7f110 15593bd1 1fdd0f50 c47120a3\n",
                          w0, w1, w2, w3);
    }

    // ----- Round-trip encrypt/decrypt test -----
    {
        uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 7 + 3);
        for (int i = 0; i < 12; ++i) nonce[i] = (uint8_t)(i * 13 + 1);

        const char* plaintext = "The quick brown fox jumps over the lazy dog. Module 31 ChaCha20!";
        size_t ptLen = strlen(plaintext);

        auto ciphertext = chacha20(key, nonce, 0, (const uint8_t*)plaintext, ptLen);
        auto decrypted  = chacha20(key, nonce, 0, ciphertext.data(), ciphertext.size());

        decrypted.push_back(0);
        bool pass = (strcmp((char*)decrypted.data(), plaintext) == 0);
        printf("[roundtrip   ] %s\n", pass ? "PASS" : "FAIL - implement TODO 3 & 4");
        if (pass) {
            printHex("Ciphertext (first 16B)", ciphertext.data(),
                     ciphertext.size() < 16 ? ciphertext.size() : 16);
        }
    }

    return 0;
}
