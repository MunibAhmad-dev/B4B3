/*
  Exercise 02 — Shellcode Runner
  --------------------------------
  A shellcode runner allocates memory, writes shellcode bytes, and executes them.
  This is the loader side — used when you have pre-compiled shellcode bytes
  (from msfvenom, Donut, your own PEB-walker shellcode, etc.)

  This exercise provides a simple x64 shellcode that calls MessageBoxA.
  (Generated with: msfvenom -p windows/x64/messagebox TEXT="Hello" -f c)
  For the lab, we provide inert test shellcode that just returns 0 — no network.

  Tasks:
  1. Implement runShellcode(sc, size) — allocate RWX memory, copy shellcode,
     cast to function pointer and call it.
  2. Implement runShellcodeFromFile(path) — read a binary file and run it.
  3. Try two variants of memory protection:
     a) Allocate PAGE_EXECUTE_READWRITE (simple, flagged by AV)
     b) Allocate PAGE_READWRITE, copy, then VirtualProtect to PAGE_EXECUTE_READ
        (slightly better — write-then-execute, not both at once)
  4. Test with the provided test_sc (just a RET instruction — safe to run).
  5. Measure and print how long execution took (using QueryPerformanceCounter).

  BONUS:
  - Implement a fiber-based runner: CreateFiber → run shellcode in the fiber
    context (different execution context, helps evade some hooks).
  - Implement a CreateThread runner: VirtualAlloc + copy + CreateThread.
  - Read shellcode from stdin (pipe shellcode in for easy testing).

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_shellcode_runner.cpp
  Usage:
    ex02.exe              → run built-in test shellcode
    ex02.exe payload.bin  → run shellcode from file
*/

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>

// Test shellcode: just returns (RET = 0xC3). Safe to execute.
static unsigned char TEST_SC[] = { 0xC3 };

// Slightly more interesting test: xor eax,eax; ret (return 0)
static unsigned char TEST_SC2[] = { 0x31, 0xC0, 0xC3 };

// ---------- TODO 1: runShellcode (variant a — PAGE_EXECUTE_READWRITE) ----------
bool runShellcode(const unsigned char* sc, size_t size) {
    // YOUR CODE HERE:
    // PVOID mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE,
    //                           PAGE_EXECUTE_READWRITE);
    // if (!mem) return false;
    // memcpy(mem, sc, size);
    // auto fn = (void(*)())mem;
    // fn();
    // VirtualFree(mem, 0, MEM_RELEASE);
    // return true;
    (void)sc; (void)size;
    return false;
}

// ---------- TODO 1b: runShellcodeRW_RX (variant b — RW then RX) ----------
bool runShellcodeRW_RX(const unsigned char* sc, size_t size) {
    // YOUR CODE HERE:
    // 1. VirtualAlloc PAGE_READWRITE
    // 2. memcpy
    // 3. VirtualProtect PAGE_EXECUTE_READ
    // 4. cast and call
    // 5. VirtualFree
    (void)sc; (void)size;
    return false;
}

// ---------- TODO 2: runShellcodeFromFile ----------
bool runShellcodeFromFile(const std::string& path) {
    // YOUR CODE HERE:
    // std::ifstream f(path, std::ios::binary);
    // if (!f) { printf("[-] Cannot open %s\n", path.c_str()); return false; }
    // std::vector<unsigned char> sc(std::istreambuf_iterator<char>(f), {});
    // return runShellcode(sc.data(), sc.size());
    (void)path;
    return false;
}

// ---------- timing helper ----------
double measureMs(bool(*fn)(const unsigned char*, size_t), const unsigned char* sc, size_t sz) {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    bool ok = fn(sc, sz);
    QueryPerformanceCounter(&end);
    double ms = 1000.0 * (end.QuadPart - start.QuadPart) / freq.QuadPart;
    if (!ok) ms = -1;
    return ms;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        printf("[*] Running shellcode from file: %s\n", argv[1]);
        runShellcodeFromFile(argv[1]);
        return 0;
    }

    printf("[*] Test shellcode: RET (0xC3)\n");

    double msA = measureMs(runShellcode, TEST_SC, sizeof(TEST_SC));
    if (msA < 0) printf("[-] runShellcode (RWX) not implemented\n");
    else printf("[+] RWX variant: %.3f ms\n", msA);

    double msB = measureMs(runShellcodeRW_RX, TEST_SC, sizeof(TEST_SC));
    if (msB < 0) printf("[-] runShellcodeRW_RX not implemented\n");
    else printf("[+] RW→RX variant: %.3f ms\n", msB);

    printf("\n[*] Test shellcode 2: xor eax,eax; ret\n");
    measureMs(runShellcode, TEST_SC2, sizeof(TEST_SC2));

    printf("\n[*] Done\n");
    return 0;
}
