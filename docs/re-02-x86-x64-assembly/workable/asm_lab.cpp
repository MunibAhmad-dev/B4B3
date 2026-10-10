// RE-02 Full Demo: Assembly Lab — Disassembler, Emitter, and Pattern Recognizer
//
// This tool:
//  1. Takes a hex string of bytes and decodes them as instructions (simple decoder)
//  2. Demonstrates all key assembly patterns from theory.md with live output
//  3. Shows PEB access (Windows) and measures RDTSC timing
//
// COMPILE: cl /W4 /std:c++17 asm_lab.cpp /Fe:re02_asm_lab.exe
//          g++ -Wall -std=c++17 asm_lab.cpp -o re02_asm_lab
// RUN: re02_asm_lab.exe

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cassert>

#ifdef _WIN32
  #include <windows.h>
  #include <intrin.h>
  #define NOINLINE __declspec(noinline)
#else
  #define NOINLINE __attribute__((noinline))
#endif

// ============================================================
// PART 1: Simple 1-byte opcode decoder (educational only)
// Maps common single-byte opcodes to mnemonic strings
// ============================================================

struct OpcodeEntry { uint8_t op; const char* mnemonic; };

static const OpcodeEntry one_byte_opcodes[] = {
    {0x50,"push rax"}, {0x51,"push rcx"}, {0x52,"push rdx"}, {0x53,"push rbx"},
    {0x54,"push rsp"}, {0x55,"push rbp"}, {0x56,"push rsi"}, {0x57,"push rdi"},
    {0x58,"pop rax"},  {0x59,"pop rcx"},  {0x5A,"pop rdx"},  {0x5B,"pop rbx"},
    {0x5C,"pop rsp"},  {0x5D,"pop rbp"},  {0x5E,"pop rsi"},  {0x5F,"pop rdi"},
    {0x90,"nop"},
    {0xC3,"ret"},
    {0xCC,"int3 (breakpoint)"},
    {0xEB,"jmp short"},
    {0xE8,"call rel32"},
    {0xFF,"call/jmp/push [rm]"},
};

const char* decode_simple(uint8_t byte) {
    for (auto& e : one_byte_opcodes)
        if (e.op == byte) return e.mnemonic;
    return "unknown/multi-byte";
}

void part1_decoder(const uint8_t* bytes, size_t len) {
    printf("\n========== PART 1: Simple Opcode Decoder ==========\n");
    for (size_t i = 0; i < len; i++)
        printf("  [%02zX] 0x%02X  →  %s\n", i, bytes[i], decode_simple(bytes[i]));
}

// ============================================================
// PART 2: Assembly Pattern Demonstrations
// Compile with /FA to get the .asm file and compare!
// ============================================================

// Pattern: FNV-1a hash (found in malware resolving API names)
NOINLINE uint32_t fnv1a(const char* s) {
    uint32_t h = 0x811C9DC5u;
    while (*s) { h ^= (uint8_t)*s++; h *= 0x01000193u; }
    return h;
}

// Pattern: strlen (recognizable loop)
NOINLINE size_t my_strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

// Pattern: XOR cipher loop (very common in malware)
NOINLINE void xor_encrypt(uint8_t* buf, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= key;
}

// Pattern: function pointer dispatch (indirect call = call rax)
NOINLINE int dispatch(int (*fn)(int, int), int a, int b) { return fn(a, b); }
NOINLINE int add_ints(int a, int b) { return a + b; }
NOINLINE int mul_ints(int a, int b) { return a * b; }

// Pattern: ROL32 (rotate left — in crypto, in hash functions)
NOINLINE uint32_t rotl32(uint32_t v, int n) {
    n &= 31;
    return (v << n) | (v >> (32 - n));
}

// Pattern: byte swap (network byte order)
NOINLINE uint32_t bswap32(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x000000FFu) << 24);
}

void part2_patterns() {
    printf("\n========== PART 2: Assembly Pattern Demonstrations ==========\n");

    // FNV hash
    const char* apis[] = {"VirtualAlloc","LoadLibraryA","GetProcAddress"};
    printf("[FNV-1a hashes]\n");
    for (auto* api : apis)
        printf("  %-20s = 0x%08X\n", api, fnv1a(api));

    // strlen
    printf("\n[strlen]\n");
    const char* strs[] = {"hello", "", "malware analysis"};
    for (auto* s : strs)
        printf("  \"%s\" → %zu\n", s, my_strlen(s));

    // XOR encrypt/decrypt
    printf("\n[XOR cipher]\n");
    char msg[] = "Hello, Reverse Engineer!";
    size_t msglen = strlen(msg);
    printf("  Original: %s\n", msg);
    xor_encrypt((uint8_t*)msg, msglen, 0x42);
    printf("  Encrypted (hex): ");
    for (size_t i = 0; i < msglen; i++) printf("%02X ", (uint8_t)msg[i]);
    printf("\n");
    xor_encrypt((uint8_t*)msg, msglen, 0x42); // XOR twice = decrypt
    printf("  Decrypted: %s\n", msg);

    // Indirect call
    printf("\n[Function pointer dispatch]\n");
    printf("  dispatch(add_ints,10,5) = %d\n", dispatch(add_ints, 10, 5));
    printf("  dispatch(mul_ints,10,5) = %d\n", dispatch(mul_ints, 10, 5));

    // ROL32
    printf("\n[ROL32 (used in MurmurHash, ChaCha20, etc.)]\n");
    printf("  rotl32(0x12345678, 8) = 0x%08X\n", rotl32(0x12345678, 8));
    printf("  rotl32(0x80000001, 1) = 0x%08X\n", rotl32(0x80000001u, 1));

    // byte swap
    printf("\n[bswap32 (network byte order)]\n");
    uint32_t ip_be = 0xC0A80101; // 192.168.1.1 in big-endian
    printf("  BE: 0x%08X  LE: 0x%08X  →  %u.%u.%u.%u\n",
           ip_be, bswap32(ip_be),
           (bswap32(ip_be)>>24)&0xFF, (bswap32(ip_be)>>16)&0xFF,
           (bswap32(ip_be)>>8)&0xFF, bswap32(ip_be)&0xFF);
}

// ============================================================
// PART 3: Windows-specific ASM patterns
// ============================================================

#ifdef _WIN32
void part3_windows_asm() {
    printf("\n========== PART 3: Windows ASM Patterns ==========\n");

    // GS:[0x30] = TEB, GS:[0x60] via PEB pointer in TEB
    PTEB  teb = NtCurrentTeb();
    PPEB  peb = teb->ProcessEnvironmentBlock;
    printf("[PEB] address: 0x%016llX\n", (unsigned long long)(uintptr_t)peb);
    printf("[PEB] ImageBaseAddress: 0x%016llX\n", (unsigned long long)(uintptr_t)peb->Reserved3[1]);
    printf("[TEB] address: 0x%016llX\n", (unsigned long long)(uintptr_t)teb);

    // RDTSC timing
    uint64_t t1 = __rdtsc();
    volatile uint64_t dummy = 0;
    for (int i = 0; i < 100000; i++) dummy += i;
    uint64_t t2 = __rdtsc();
    printf("\n[RDTSC] 100K additions: ~%llu cycles\n", (unsigned long long)(t2 - t1));

    // Anti-debug hint: if t2-t1 > threshold, debugger likely attached
    uint64_t delta = t2 - t1;
    printf("[Anti-debug] delta=%llu, %s\n", (unsigned long long)delta,
           delta > 1000000 ? "DEBUGGER SUSPECTED" : "clean");

    // CPUID brand string
    int info[4];
    char brand[49] = {};
    __cpuid(info, 0x80000002); memcpy(brand,    info, 16);
    __cpuid(info, 0x80000003); memcpy(brand+16, info, 16);
    __cpuid(info, 0x80000004); memcpy(brand+32, info, 16);
    printf("[CPUID] Brand: %s\n", brand);
}
#endif

// ============================================================
// PART 4: Decode a sample shellcode stub
// ============================================================

void part4_decode_stub() {
    printf("\n========== PART 4: Stub Shellcode Decoder ==========\n");

    // This stub: sub rsp, 28h; call fn; add rsp, 28h; ret
    // (typical call wrapper with shadow space)
    static const uint8_t stub[] = {
        0x48, 0x83, 0xEC, 0x28,   // sub rsp, 0x28  (REX.W + 83 /5 ib)
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0 (placeholder)
        0x48, 0x83, 0xC4, 0x28,   // add rsp, 0x28
        0xC3,                      // ret
    };

    printf("Raw bytes:\n  ");
    for (size_t i = 0; i < sizeof(stub); i++) {
        printf("%02X ", stub[i]);
        if ((i+1) % 8 == 0) printf("\n  ");
    }
    printf("\n\nAnnotated:\n");
    printf("  48 83 EC 28     →  sub rsp, 28h    (allocate shadow space)\n");
    printf("  E8 00 00 00 00  →  call +0x00      (relative call, needs patching)\n");
    printf("  48 83 C4 28     →  add rsp, 28h    (deallocate shadow space)\n");
    printf("  C3              →  ret\n");
    printf("\nNote: 0x48 prefix = REX.W (64-bit operand size)\n");
    printf("      0x83 = immediate arithmetic with 8-bit sign-extended imm\n");
    printf("      /5 = sub opcode  /0 = add opcode\n");
}

// ============================================================
// MAIN
// ============================================================

int main() {
    printf("RE-02 Assembly Lab\n");
    printf("==================\n");

    // Part 1: decode the stub bytes
    static const uint8_t sample[] = {0x55,0x48,0x89,0xE5,0xC3,0x90,0xCC};
    part1_decoder(sample, sizeof(sample));

    part2_patterns();

#ifdef _WIN32
    part3_windows_asm();
#endif

    part4_decode_stub();

    printf("\n[Done]\n");
    return 0;
}
