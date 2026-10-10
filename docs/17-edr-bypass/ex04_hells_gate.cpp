/*
  Exercise 04 — Hell's Gate + Halo's Gate
  -----------------------------------------
  Dynamic syscall number resolution that works even when ntdll is hooked.

  Hell's Gate:  read syscall number from ntdll stub (works when unhooked)
  Halo's Gate:  if hooked, find a neighbouring function that is NOT hooked,
                read its syscall number, and infer ours by offset

  Tasks:
  1. Implement isNtdllStubClean() — check if the first bytes match
     the expected unhooked pattern (4C 8B D1 B8 xx xx 00 00).

  2. Implement hellsGate() — read syscall number from a clean stub.

  3. Implement halosGate() — scan forward and backward from a hooked stub
     to find a clean sibling, then infer the syscall number by ±1 per step.

  4. Implement getSyscallNumber() — combines both: try Hell's Gate first,
     fall back to Halo's Gate.

  5. In main(): resolve and print syscall numbers for:
     NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx,
     NtOpenProcess, NtReadVirtualMemory, NtProtectVirtualMemory

  6. Compare your output to a reference table for your Windows version:
     https://j00ru.vexillium.org/syscalls/nt/64/

  BONUS:
  - Simulate a hook: patch NtOpenProcess in memory with E9 xx xx xx xx,
    then call getSyscallNumber("NtOpenProcess") — Halo's Gate should still
    resolve it correctly.

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_hells_gate.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>
#include <string>
#include <iomanip>

// Spacing between adjacent syscall stubs in ntdll's export table.
// On Windows 10/11 x64, stubs are typically 32 bytes apart.
// This is approximate — a more robust implementation would parse the export
// table to get precise offsets.
static const int STUB_STEP = 32;
static const int MAX_SCAN  = 20;  // how many neighbours to check

// TODO: Return true if the bytes at stubPtr match the clean syscall pattern:
//   4C 8B D1 B8 xx xx 00 00
// (mov r10,rcx / mov eax,<ssn> where high bytes are 00 00 = ssn < 0xFFFF)
bool isNtdllStubClean(PBYTE stubPtr) {
    // YOUR CODE HERE
    return false;
}

// TODO: Read the 4-byte syscall number from a clean (unhooked) stub.
// The syscall number sits at bytes [4..7]: mov eax, <here>
DWORD hellsGate(PBYTE stubPtr) {
    // YOUR CODE HERE
    return (DWORD)-1;
}

// TODO: Scan neighbouring stubs to find a clean one.
// For each step i from 1 to MAX_SCAN:
//   Check stubPtr + i*STUB_STEP (forward)
//   If clean: return hellsGate(neighbour) - i  (our SSN is i less)
//   Check stubPtr - i*STUB_STEP (backward)
//   If clean: return hellsGate(neighbour) + i  (our SSN is i more)
// Return (DWORD)-1 if nothing found.
DWORD halosGate(PBYTE stubPtr) {
    // YOUR CODE HERE
    return (DWORD)-1;
}

// TODO: Main resolver — tries Hell's Gate first, falls back to Halo's Gate.
DWORD getSyscallNumber(const char* funcName) {
    PBYTE stubPtr = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName);
    if (!stubPtr) return (DWORD)-1;

    if (isNtdllStubClean(stubPtr))
        return hellsGate(stubPtr);
    else
        return halosGate(stubPtr);
}

int main() {
    printf("=== Hell's Gate / Halo's Gate Syscall Resolver ===\n\n");

    const char* funcs[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtReadVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtUnmapViewOfSection",
        "NtMapViewOfSection",
        nullptr
    };

    printf("%-35s %s\n", "Function", "Syscall Number");
    printf("%s\n", std::string(55, '-').c_str());

    for (int i = 0; funcs[i]; i++) {
        DWORD ssn = getSyscallNumber(funcs[i]);
        if (ssn == (DWORD)-1)
            printf("%-35s FAILED\n", funcs[i]);
        else
            printf("%-35s 0x%02X (%u)\n", funcs[i], ssn, ssn);
    }

    printf("\n[*] Compare against: https://j00ru.vexillium.org/syscalls/nt/64/\n");

    // BONUS: Simulate a hook and test Halo's Gate fallback
    printf("\n--- Simulating hook on NtOpenProcess ---\n");
    PBYTE stubPtr = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    if (stubPtr) {
        DWORD old;
        VirtualProtect(stubPtr, 8, PAGE_EXECUTE_READWRITE, &old);
        BYTE saved[8];
        memcpy(saved, stubPtr, 8);

        // Patch with E9 JMP to simulate hook
        stubPtr[0] = 0xE9;
        stubPtr[1] = 0x00; stubPtr[2] = 0x00; stubPtr[3] = 0x00; stubPtr[4] = 0x00;

        printf("[*] NtOpenProcess first bytes now: E9 00 00 00 00 (simulated hook)\n");
        DWORD ssn = getSyscallNumber("NtOpenProcess");
        if (ssn != (DWORD)-1)
            printf("[+] Halo's Gate resolved: 0x%02X (%u)\n", ssn, ssn);
        else
            printf("[-] Halo's Gate failed\n");

        // Restore
        memcpy(stubPtr, saved, 8);
        VirtualProtect(stubPtr, 8, old, &old);
        printf("[*] Hook removed\n");
    }

    return 0;
}
