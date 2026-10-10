// Exercise 3: Shellcode Runner & Analysis
// Write, analyze, and execute a minimal Windows shellcode.
//
// TASKS:
//  1. Study the annotated shellcode below — label every instruction.
//  2. Implement run_shellcode() to allocate RWX memory, copy and execute it.
//  3. Replace the MessageBox shellcode with a calc-spawning shellcode of your own.
//     (Hint: you need to find WinExec via PEB walk, not import table)
//  4. Add a disassembler dump that prints each byte as hex + the likely mnemonic.
//
// COMPILE: cl /W4 /std:c++17 ex03_shellcode_runner.cpp /Fe:ex03.exe
// WARNING: This is a lab exercise. Only run in a VM.
// PLATFORM: Windows x64 only

#ifdef _WIN32
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------
// Shellcode: Calls MessageBoxA(NULL, "Hello RE", "Shellcode", 0)
// This is NOT position-independent yet — it uses hardcoded addresses.
// Real shellcode uses PEB walk; that's the next step.
//
// For educational purposes only. The byte sequence below is a stub
// you will analyze and eventually replace.
// ---------------------------------------------------------------

// x64 MessageBoxA shellcode (conceptual, not fully position-independent)
// In a real exercise you'd generate this with msfvenom or write it manually.
// Here we demonstrate the runner infrastructure.

// A simple PIC (position-independent) stub that just returns 0:
static const uint8_t stub_shellcode[] = {
    // This is a minimal "return 42" shellcode for testing the runner
    // mov eax, 42 (0x2A)
    0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 0x2A
    0xC3                            // ret
};

// TODO TASK 1: Annotate each byte above with the instruction it represents.

// ---------------------------------------------------------------
// Runner infrastructure
// ---------------------------------------------------------------

typedef int (*ShellcodeFunc)();

// Task 2: implement this function
bool run_shellcode(const uint8_t* sc, size_t len, int* out_retval) {
    // Step 1: VirtualAlloc RWX memory
    // Step 2: memcpy shellcode into it
    // Step 3: cast to function pointer and call
    // Step 4: VirtualFree
    // Step 5: store return value in *out_retval

    // TODO: implement
    (void)sc; (void)len; (void)out_retval;
    printf("[TODO] run_shellcode not implemented yet\n");
    return false;
}

// ---------------------------------------------------------------
// Hex dump helper (Task 4 starting point)
// ---------------------------------------------------------------
void hex_dump(const uint8_t* data, size_t len, const char* label) {
    printf("\n[%s] %zu bytes:\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04zX: ", i);
        printf("%02X ", data[i]);
        if ((i+1) % 16 == 0 || i+1 == len) printf("\n");
    }
}

// ---------------------------------------------------------------
// Shellcode generation helpers
// ---------------------------------------------------------------

// Build a minimal shellcode that XOR-decodes itself then executes.
// This demonstrates a simple single-byte XOR packer.
// Caller owns returned buffer.
uint8_t* build_xor_packed(const uint8_t* original, size_t len,
                           uint8_t key, size_t* out_len) {
    // Layout: [decoder stub] [xor-encoded payload]
    // The decoder stub is position-independent x64 code that:
    //   1. Finds its own address (via call/pop trick or RIP-relative)
    //   2. XOR-decodes the payload bytes after itself
    //   3. Jumps to decoded payload

    // For the exercise, we just XOR-encode the bytes (no stub yet)
    uint8_t* packed = (uint8_t*)malloc(len);
    if (!packed) return nullptr;
    for (size_t i = 0; i < len; i++) packed[i] = original[i] ^ key;
    *out_len = len;
    return packed;
}

int main() {
    printf("=== Shellcode Runner Lab ===\n");

    hex_dump(stub_shellcode, sizeof(stub_shellcode), "stub_shellcode");

    // Task 1: annotate the bytes in the comment above, then verify here:
    printf("\nByte analysis:\n");
    printf("  Bytes 0-4: %02X %02X %02X %02X %02X  →  mov eax, 0x%02X\n",
           stub_shellcode[0], stub_shellcode[1], stub_shellcode[2],
           stub_shellcode[3], stub_shellcode[4], stub_shellcode[1]);
    printf("  Byte  5:   %02X                    →  ret\n", stub_shellcode[5]);

    // Task 2: run the shellcode
    int retval = 0;
    bool ok = run_shellcode(stub_shellcode, sizeof(stub_shellcode), &retval);
    if (ok) printf("Shellcode returned: %d (expected 42)\n", retval);

    // XOR packing demo
    uint8_t key = 0x55;
    size_t packed_len = 0;
    uint8_t* packed = build_xor_packed(stub_shellcode, sizeof(stub_shellcode),
                                        key, &packed_len);
    if (packed) {
        hex_dump(packed, packed_len, "xor-encoded (key=0x55)");
        free(packed);
    }

    return 0;
}

#else
int main() {
    puts("This exercise is Windows-only.");
    return 0;
}
#endif
