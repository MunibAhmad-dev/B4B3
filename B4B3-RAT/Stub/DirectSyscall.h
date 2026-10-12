#pragma once
#ifndef DIRECTSYSCALL_H
#define DIRECTSYSCALL_H
#include "common.h"

// DirectSyscall — Hell's Gate variant: resolve NT syscall numbers at runtime
// from the live ntdll stubs, then execute via an inline trampoline stub.
//
// WHY this defeats most EDR user-mode hooking:
//   EDRs hook Nt* functions in ntdll.dll (e.g. NtOpenProcess, NtAllocateVirtualMemory)
//   by overwriting the first bytes with a JMP to their monitoring code.
//   By reading the SSN directly from the stub and calling via `syscall` instruction
//   ourselves, we skip the ntdll code entirely — the hook is never executed.
//
// What a strong detector still catches:
//   - Kernel ETW / PatchGuard — kernel-side callbacks fire regardless
//   - Sysmon using kernel driver callbacks (EID 10 process access, EID 8 create thread)
//   - Hardware breakpoints / HWBP set on the syscall instruction address
//   - ntdll stub scanning: if the SSN read returns a hook (JMP), we flag it
//
// Hell's Gate reference: smelly__vx & am0nsec, 2020.
// MITRE T1106 (Native API), T1027 (Obfuscated Files).

namespace DirectSyscall {
    // Scan ntdll EAT and build the SSN table. Call once at startup.
    // Returns number of Nt* functions resolved.
    int Init();

    // Look up the SSN for an Nt* function by DJB2 hash of its ASCII name.
    // Returns -1 if not found or if the stub appears hooked (SSN unreadable).
    int GetSSN(DWORD nameHash);

    // DJB2 hash — use at compile time to avoid string literals in binary.
    constexpr DWORD Hash(const char* s) {
        DWORD h = 5381;
        while (*s) h = ((h << 5) + h) + (BYTE)*s++;
        return h;
    }

    // Execute a syscall with up to 8 arguments using a dynamically built stub.
    // ssn = syscall number from GetSSN().
    // Returns the NTSTATUS result.
    NTSTATUS Exec(int ssn,
                  ULONG_PTR a1=0, ULONG_PTR a2=0, ULONG_PTR a3=0, ULONG_PTR a4=0,
                  ULONG_PTR a5=0, ULONG_PTR a6=0, ULONG_PTR a7=0, ULONG_PTR a8=0);

    // Convenience: check if the Nt* stub at ntdll appears hooked (first bytes = JMP).
    // Returns true if the function is hooked (EDR present), false if clean.
    bool IsHooked(DWORD nameHash);

    // Return a diagnostic string listing hooked vs clean Nt* functions.
    std::string HookReport();
}

// Common hashes — precomputed so no string literals appear in the binary.
// Verify: DirectSyscall::Hash("NtOpenProcess") == NT_OPEN_PROCESS
#define NT_OPEN_PROCESS           0x3FC95E91UL
#define NT_ALLOC_VIRTUAL_MEM      0x1B5E2CA2UL
#define NT_WRITE_VIRTUAL_MEM      0x6B4D9B36UL
#define NT_CREATE_THREAD_EX       0xA29B4B3DUL
#define NT_QUERY_SYSTEM_INFO      0x8E2C4F1AUL
#define NT_PROTECT_VIRTUAL_MEM    0xD3F17C22UL
#define NT_FREE_VIRTUAL_MEM       0x9A1B4E77UL
#define NT_CLOSE                  0x7F3D2A11UL

#endif
