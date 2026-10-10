// Solution 3: Shellcode Runner (complete implementation)
// Windows x64 only — run in a VM.

#ifdef _WIN32
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

// Minimal "return 42" shellcode
static const uint8_t stub_shellcode[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,   // mov eax, 0x2A (42)
    0xC3                              // ret
};

typedef int (*ShellcodeFunc)();

bool run_shellcode(const uint8_t* sc, size_t len, int* out_retval) {
    // Allocate RWX memory
    LPVOID mem = VirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return false;
    }

    // Copy shellcode
    memcpy(mem, sc, len);

    // Flush instruction cache (important on some CPUs)
    FlushInstructionCache(GetCurrentProcess(), mem, len);

    // Execute
    ShellcodeFunc fn = reinterpret_cast<ShellcodeFunc>(mem);
    *out_retval = fn();

    // Clean up
    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

void hex_dump(const uint8_t* data, size_t len, const char* label) {
    printf("\n[%s] %zu bytes:\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04zX: ", i);
        printf("%02X ", data[i]);
        if ((i+1) % 16 == 0 || i+1 == len) printf("\n");
    }
}

uint8_t* build_xor_packed(const uint8_t* original, size_t len,
                           uint8_t key, size_t* out_len) {
    uint8_t* packed = (uint8_t*)malloc(len);
    if (!packed) return nullptr;
    for (size_t i = 0; i < len; i++) packed[i] = original[i] ^ key;
    *out_len = len;
    return packed;
}

// Decode and run XOR-packed shellcode
bool run_xor_shellcode(const uint8_t* packed, size_t len, uint8_t key, int* out) {
    uint8_t* decoded = (uint8_t*)malloc(len);
    if (!decoded) return false;
    for (size_t i = 0; i < len; i++) decoded[i] = packed[i] ^ key;
    bool result = run_shellcode(decoded, len, out);
    free(decoded);
    return result;
}

int main() {
    printf("=== Shellcode Runner Lab (SOLUTION) ===\n");

    hex_dump(stub_shellcode, sizeof(stub_shellcode), "stub_shellcode");
    printf("\nAnnotation:\n");
    printf("  B8 2A 00 00 00  →  mov eax, 0x0000002A  (eax = 42)\n");
    printf("  C3              →  ret                   (return eax)\n");

    printf("\n--- Running shellcode ---\n");
    int retval = 0;
    if (run_shellcode(stub_shellcode, sizeof(stub_shellcode), &retval)) {
        printf("Result: %d (expected: 42) %s\n", retval,
               retval == 42 ? "PASS" : "FAIL");
    }

    printf("\n--- XOR packing / unpacking demo ---\n");
    uint8_t key = 0x55;
    size_t packed_len = 0;
    uint8_t* packed = build_xor_packed(stub_shellcode, sizeof(stub_shellcode),
                                        key, &packed_len);
    if (packed) {
        hex_dump(packed, packed_len, "xor-encoded (key=0x55)");

        int retval2 = 0;
        if (run_xor_shellcode(packed, packed_len, key, &retval2)) {
            printf("XOR-decoded run result: %d %s\n", retval2,
                   retval2 == 42 ? "PASS" : "FAIL");
        }
        free(packed);
    }

    printf("\n[Done]\n");
    return 0;
}
#else
int main() { puts("Windows only."); return 0; }
#endif
