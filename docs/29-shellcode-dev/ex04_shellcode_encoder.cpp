/*
  Exercise 04 — Shellcode XOR Encoder + Decoder Stub
  ---------------------------------------------------
  Encoding shellcode defeats basic signature-based AV:
    - XOR each byte with a key
    - Prepend a small decoder stub that XOR-decodes at runtime
    - The encoded bytes don't match any known signature

  This exercise builds a self-contained encoder + decoder stub.

  The output is a C array containing:
    [decoder_stub][encoded_shellcode]
  which can be copied into ex02_shellcode_runner's TEST_SC.

  Tasks:
  1. Implement xorEncode(sc, size, key) → returns encoded bytes.
  2. Write a decoder_stub in assembly (x64 NASM or inline asm):
       - Load RCX = address of encoded shellcode (after the stub)
       - Load RDX = length of shellcode
       - XOR each byte with the key
       - JMP to start of decoded bytes
  3. Implement buildPayload(sc, size, key) → decoder_stub + encoded_sc.
  4. Print the result as a C byte array: "unsigned char payload[] = {...};"
  5. Test: encode TEST_SC2 (xor eax,eax; ret), decode at runtime, execute.

  The decoder stub (x64, key in immediate):
    lea  rcx, [rip + encoded_offset]    ; point to encoded bytes
    mov  rdx, <shellcode_length>
  .loop:
    xor  byte [rcx + rdx - 1], <key>
    dec  rdx
    jnz  .loop
    jmp  rcx                            ; execute decoded shellcode

  BONUS:
  - Use a rotating key: key[i] = base_key XOR (i * multiplier).
  - Implement shikata-ga-nai style: the decoder itself is also encoded and
    uses a GetPC trick to find its own data (no hardcoded RIP-relative).
  - Output as PowerShell base64 for easy clipboard pasting.

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_shellcode_encoder.cpp
  Usage:
    ex04.exe [key]          → encode TEST_SC2 with given hex key (default: 0xAA)
    ex04.exe AA test.bin    → encode test.bin with key 0xAA
*/

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <cstdio>
#include <cstdlib>

// Test shellcode: xor eax,eax; ret
static unsigned char TEST_SC2[] = { 0x31, 0xC0, 0xC3 };

// ---------- TODO 1: xorEncode ----------
std::vector<unsigned char> xorEncode(const unsigned char* sc, size_t size, unsigned char key) {
    // YOUR CODE HERE:
    // std::vector<unsigned char> encoded(sc, sc + size);
    // for (auto& b : encoded) b ^= key;
    // return encoded;
    (void)sc; (void)size; (void)key;
    return {};
}

// ---------- TODO 2+3: buildPayload ----------
// Returns decoder_stub + encoded_shellcode as a single byte array.
// The stub length must be known at compile time so we can set the RIP-relative offset.
//
// Stub (bytes, key=0xAA, payload_len must be patched in):
//   48 8D 0D [rel32]        ; lea rcx, [rip + encoded_offset]
//   BA [len_le32]           ; mov edx, <len>
//   80 34 11 [key]          ; .loop: xor [rcx+rdx], key
//   48 FF CA                ; dec rdx
//   75 F5                   ; jnz .loop
//   FF E1                   ; jmp rcx
static const size_t STUB_LEN = 18;

std::vector<unsigned char> buildPayload(const unsigned char* sc, size_t size, unsigned char key) {
    auto encoded = xorEncode(sc, size, key);
    if (encoded.empty()) return {};

    std::vector<unsigned char> payload(STUB_LEN + size, 0);

    // Stub bytes (x64, key and length will be patched below):
    unsigned char stub[STUB_LEN] = {
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,  // lea rcx, [rip+0] — patch offset
        0xBA, 0x00, 0x00, 0x00, 0x00,               // mov edx, N       — patch length
        0x80, 0x34, 0x11, 0x00,                      // xor [rcx+rdx], K — patch key
        0x48, 0xFF,                                  // dec rdx          (rex.W + FF /1)
        // ... missing bytes — extend as needed
    };

    // YOUR CODE HERE:
    // Patch stub[3..6] with (signed int32) offset from next instr to encoded start
    // = STUB_LEN - 7  (RIP after lea = stub + 7, target = stub + STUB_LEN)
    // Patch stub[8..11] with (uint32) size
    // Patch stub[15]   with key
    // memcpy(payload.data(), stub, STUB_LEN)
    // memcpy(payload.data() + STUB_LEN, encoded.data(), size)

    (void)stub;
    return payload;
}

// ---------- print as C array ----------
void printCArray(const std::vector<unsigned char>& v, const char* name) {
    printf("unsigned char %s[] = {\n  ", name);
    for (size_t i = 0; i < v.size(); i++) {
        printf("0x%02X", v[i]);
        if (i + 1 < v.size()) printf(", ");
        if ((i + 1) % 16 == 0 && i + 1 < v.size()) printf("\n  ");
    }
    printf("\n}; // %zu bytes\n", v.size());
}

int main(int argc, char* argv[]) {
    unsigned char key = 0xAA;
    if (argc > 1) key = (unsigned char)strtol(argv[1], nullptr, 16);

    const unsigned char* sc = TEST_SC2;
    size_t scSize = sizeof(TEST_SC2);

    // Optionally read from file
    std::vector<unsigned char> fromFile;
    if (argc > 2) {
        std::ifstream f(argv[2], std::ios::binary);
        if (f) {
            fromFile = std::vector<unsigned char>(std::istreambuf_iterator<char>(f), {});
            sc = fromFile.data(); scSize = fromFile.size();
            printf("[*] Read %zu bytes from %s\n", scSize, argv[2]);
        }
    }

    printf("[*] Encoding %zu bytes with key 0x%02X\n", scSize, key);

    auto encoded = xorEncode(sc, scSize, key);
    if (encoded.empty()) {
        printf("[-] xorEncode not implemented\n"); return 1;
    }
    printCArray(encoded, "encoded_sc");

    printf("\n[*] Building payload (stub + encoded)...\n");
    auto payload = buildPayload(sc, scSize, key);
    if (payload.empty()) {
        printf("[-] buildPayload not implemented\n"); return 1;
    }
    printCArray(payload, "payload");

    // Test: run the payload
    printf("\n[*] Testing payload execution...\n");
    PVOID mem = VirtualAlloc(nullptr, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem) {
        memcpy(mem, payload.data(), payload.size());
        ((void(*)())mem)();
        VirtualFree(mem, 0, MEM_RELEASE);
        printf("[+] Payload executed (no crash = success)\n");
    }
    return 0;
}
