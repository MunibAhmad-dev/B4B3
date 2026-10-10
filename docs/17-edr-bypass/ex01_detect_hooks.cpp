/*
  Exercise 01 — Detect Inline Hooks in ntdll
  --------------------------------------------
  Before bypassing hooks, learn to DETECT them.
  This is also a blue team skill: scanning for unexpected patches in ntdll
  is how you detect process injection that used hooking as a side effect.

  Tasks:
  1. Implement isHooked() — check the first 5 bytes of a function for a JMP.
     A 32-bit relative JMP is: E9 xx xx xx xx
     A 64-bit absolute JMP is: FF 25 xx xx xx xx

  2. Implement checkNtdllFunction() — call GetProcAddress on ntdll.dll, print
     the first 8 bytes as hex, and report HOOKED / CLEAN.

  3. In main(): check these functions:
     NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx,
     NtOpenProcess, NtReadVirtualMemory, NtQueueApcThread

  4. BONUS: Load a clean copy of ntdll from disk and compare byte-by-byte
     to the in-memory version. Print any differences.

  Expected output (no EDR running):
    NtAllocateVirtualMemory  4C 8B D1 B8 18 00 00 00  CLEAN
    NtOpenProcess            4C 8B D1 B8 26 00 00 00  CLEAN

  Expected output (with an EDR hooking):
    NtAllocateVirtualMemory  E9 xx xx xx xx 00 00 00  HOOKED → JMP to 0x7ff...

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_detect_hooks.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

// TODO: Return true if the first bytes of funcPtr indicate a JMP hook.
// Check for: E9 (relative JMP), FF 25 (absolute indirect JMP), or E8 (CALL).
bool isHooked(PVOID funcPtr) {
    // YOUR CODE HERE
    return false;
}

// TODO: Get the JMP target address for display.
// For E9 relative JMP: target = funcPtr + 5 + *(int32_t*)(funcPtr+1)
// For FF 25: target = *(PVOID*)(funcPtr + 6)
PVOID getHookTarget(PVOID funcPtr) {
    // YOUR CODE HERE
    return nullptr;
}

// TODO: Implement checkNtdllFunction().
// 1. GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName)
// 2. Print the first 8 bytes as hex
// 3. Call isHooked() — print HOOKED or CLEAN
// 4. If HOOKED: print "→ JMP to 0x<getHookTarget()>"
void checkNtdllFunction(const char* funcName) {
    // YOUR CODE HERE
}

// BONUS TODO: Load clean ntdll from disk and compare to in-memory version.
// Print any bytes that differ (offset, in-memory byte, disk byte).
void compareWithDisk() {
    // YOUR CODE HERE
}

int main() {
    printf("=== NTDLL Hook Detector ===\n\n");

    const char* funcs[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtReadVirtualMemory",
        "NtQueueApcThread",
        "NtProtectVirtualMemory",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        nullptr
    };

    printf("%-35s %-25s %s\n", "Function", "First 8 bytes", "Status");
    printf("%s\n", std::string(75, '-').c_str());

    for (int i = 0; funcs[i]; i++)
        checkNtdllFunction(funcs[i]);

    printf("\n--- Disk Comparison ---\n");
    compareWithDisk();

    return 0;
}
