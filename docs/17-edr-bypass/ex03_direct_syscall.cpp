/*
  Exercise 03 — Direct Syscall (bypass ntdll hooks entirely)
  -----------------------------------------------------------
  Execute NtAllocateVirtualMemory using a manually constructed syscall stub
  in executable memory. The stub never enters ntdll — the EDR hook is skipped.

  Tasks:
  1. Implement buildSyscallStub() — write the 4-instruction syscall stub into
     a provided buffer. The syscall number is passed as a parameter.

  2. Implement getSyscallNumberFromNtdll() — read the syscall number from the
     ntdll function's original bytes (assumes function is NOT yet hooked;
     run this before any EDR gets the chance, or use Hell's Gate from ex04).

  3. In main():
     a. Get syscall number for "NtAllocateVirtualMemory" from ntdll
     b. Allocate a small RWX buffer for the stub
     c. Build the stub into it
     d. Cast the buffer to a function pointer matching NtAllocateVirtualMemory
     e. Call it to allocate a page of memory in the current process
     f. Verify the allocation succeeded
     g. VirtualFree it

  The goal: VirtualAlloc without ever calling VirtualAlloc — your stub IS
  the syscall, running directly from your own memory.

  Syscall stub (x64):
    4C 8B D1             mov r10, rcx
    B8 xx 00 00 00       mov eax, <syscall_number>
    0F 05                syscall
    C3                   ret

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_direct_syscall.cpp -lkernel32
*/

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <iomanip>
#include <cstring>

// NtAllocateVirtualMemory signature
// Parameters match the NT native API exactly
typedef NTSTATUS (NTAPI *pfnNtAllocVirt)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect
);

// TODO: Build the 11-byte syscall stub into buf[].
// Layout:
//   [0]     = 0x4C          mov r10, rcx  (3 bytes: 4C 8B D1)
//   [1]     = 0x8B
//   [2]     = 0xD1
//   [3]     = 0xB8          mov eax, imm32 (5 bytes: B8 xx xx xx xx)
//   [4..7]  = syscallNumber (little-endian DWORD)
//   [8]     = 0x0F          syscall (2 bytes: 0F 05)
//   [9]     = 0x05
//   [10]    = 0xC3          ret
// buf must be at least 11 bytes.
void buildSyscallStub(BYTE* buf, DWORD syscallNumber) {
    // YOUR CODE HERE
}

// TODO: Read the syscall number from ntdll's function stub.
// The ntdll stub looks like (when unhooked):
//   4C 8B D1  (mov r10, rcx)
//   B8 xx xx 00 00  (mov eax, syscall_number)
// Return the DWORD at offset 4 from the function start.
// Return (DWORD)-1 if bytes don't match expected pattern.
DWORD getSyscallNumberFromNtdll(const char* funcName) {
    // YOUR CODE HERE
    return (DWORD)-1;
}

int main() {
    printf("=== Direct Syscall Demo ===\n\n");

    // Step 1: get the syscall number
    DWORD ssn = getSyscallNumberFromNtdll("NtAllocateVirtualMemory");
    if (ssn == (DWORD)-1) {
        printf("[-] Could not read syscall number (function may be hooked)\n");
        printf("    Use ex04_hells_gate.cpp to handle hooked case\n");
        return 1;
    }
    printf("[+] NtAllocateVirtualMemory syscall number: 0x%02X (%u)\n", ssn, ssn);

    // Step 2: allocate RWX memory for the stub
    BYTE* stubMem = (BYTE*)VirtualAlloc(nullptr, 16,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stubMem) { printf("[-] VirtualAlloc stub failed\n"); return 1; }

    // Step 3: build the stub
    buildSyscallStub(stubMem, ssn);

    printf("[+] Stub bytes: ");
    for (int i = 0; i < 11; i++) printf("%02X ", stubMem[i]);
    printf("\n");

    // Step 4: cast to function pointer
    auto directAlloc = (pfnNtAllocVirt)stubMem;

    // Step 5: call it — allocate 4096 bytes in current process
    PVOID  base = nullptr;
    SIZE_T size = 4096;
    NTSTATUS status = directAlloc(
        GetCurrentProcess(),   // ProcessHandle
        &base,                 // BaseAddress
        0,                     // ZeroBits
        &size,                 // RegionSize
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status == 0 && base != nullptr) {
        printf("[+] Direct syscall succeeded! Allocated %zu bytes at %p\n", size, base);
        // Write a test value to confirm it's writable
        *(DWORD*)base = 0xDEADBEEF;
        printf("[+] Wrote 0xDEADBEEF to allocated memory — readable: 0x%08X\n", *(DWORD*)base);
        VirtualFree(base, 0, MEM_RELEASE);
        printf("[+] Memory freed\n");
    } else {
        printf("[-] Direct syscall failed. NTSTATUS: 0x%08X\n", status);
    }

    VirtualFree(stubMem, 0, MEM_RELEASE);
    return 0;
}
