// ex03_report_target.cpp — capstone analysis target (benign obfuscated sample)
// This is the binary to analyze. It does nothing harmful but mimics RAT patterns.
// Compile: g++ -std=c++17 -o ex03_target.exe ex03_report_target.cpp
//
// Capstone challenge: Run ALL tools from RE-01 through RE-11 against ex03_target.exe
// and produce a complete analysis report including:
//   1. File hash + entropy
//   2. Capability assessment
//   3. Decoded C2 config (XOR key = 0x42; find the encoded blob)
//   4. IOC list (mutex name, fake C2 domain, registry key)
//   5. YARA rule that detects this sample
//   6. Detection recommendation (which Sysmon event + field to alert on)

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// XOR-obfuscated config blob (key = 0x42)
// Plaintext: "mutex:RE12_capstone_mutex\0c2:192.0.2.1:4444\0key:HKCU\\Software\\RE12\0"
static const uint8_t ENCODED_CONFIG[] = {
    0x2F,0x37,0x30,0x31,0x38,0x3A,0x43,0x52,0x3C,0x52,0x31,0x21,0x22,0x30,0x36,0x24,
    0x37,0x30,0x3E,0x52,0x23,0x37,0x30,0x32,0x31,0x38,0x00,   // "mutex:RE12_capstone_mutex\0"
    0x21,0x36,0x43,0x7A,0x72,0x72,0x71,0x70,0x76,0x71,0x70,0x74,0x7E,0x76,0x7A,0x43,
    0x76,0x76,0x76,0x76,0x00,                                    // "c2:192.0.2.1:4444\0"
    0x29,0x31,0x3B,0x43,0x11,0x37,0x38,0x1B,0x3C,0x34,0x34,0x3E,0x26,0x37,0x31,0x00  // "key:HKCU\\Software\\RE12\0"
};

static void decode_config(char* out, size_t outsz) {
    size_t n = sizeof(ENCODED_CONFIG);
    if (n >= outsz) n = outsz - 1;
    for (size_t i = 0; i < n; ++i) out[i] = ENCODED_CONFIG[i] ^ 0x42;
    out[n] = 0;
}

// Simulate dynamic API resolution (PEB walk stub — just calls GetProcAddress for demo)
typedef BOOL(WINAPI*PCreateMutexA_t)(LPSECURITY_ATTRIBUTES,BOOL,LPCSTR);
static HANDLE create_named_mutex(const char* name) {
    HMODULE k32 = GetModuleHandleA("KERNEL32.DLL");
    if (!k32) return nullptr;
    PCreateMutexA_t fn = (PCreateMutexA_t)GetProcAddress(k32, "CreateMutexA");
    if (!fn) return nullptr;
    return fn(nullptr, FALSE, name);
}

int main() {
    printf("[target] Starting ex03_report_target.exe\n");
    // Beacon delay simulation
    Sleep(100);
    // Decode config
    char cfg[256]{};
    decode_config(cfg, sizeof(cfg));
    // Parse fields (null-separated)
    const char* mutex_name = cfg;
    const char* c2_addr    = cfg + strlen(cfg) + 1;
    const char* reg_key    = c2_addr + strlen(c2_addr) + 1;
    printf("[target] Mutex: %s\n", mutex_name);
    printf("[target] C2:    %s\n", c2_addr);
    printf("[target] Reg:   %s\n", reg_key);
    // Create named mutex (persistence indicator)
    HANDLE hm = create_named_mutex(mutex_name);
    if (hm) {
        if (GetLastError() == ERROR_ALREADY_EXISTS)
            printf("[target] Already running (mutex exists)\n");
        CloseHandle(hm);
    }
    printf("[target] Exiting cleanly — this is the capstone target to analyze.\n");
    return 0;
}
