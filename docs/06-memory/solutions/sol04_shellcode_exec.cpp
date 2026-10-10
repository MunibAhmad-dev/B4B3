// sol04_shellcode_exec.cpp
// Demonstrates the safe RW→fill→RX shellcode execution pattern.
// The test shellcode is the shortest safe no-op: xor eax,eax / ret.
// It simply returns 0 — nothing destructive.
//
// Compile:
//   g++ -std=c++17 -Wall -o sol04.exe solutions/sol04_shellcode_exec.cpp
//
// NOTE: This is x86 shellcode. The binary will be 32-bit on 32-bit toolchains
// and the shellcode is x86/x86-64 compatible (xor eax,eax; ret works on both).

#include <windows.h>
#include <stdio.h>
#include <string.h>

// -------------------------------------------------------------------------
// Test shellcode: xor eax, eax ; ret
//   31 C0  →  XOR EAX, EAX   (zero out eax / rax — sets return value to 0)
//   C3     →  RET             (return to caller)
//
// On x86_64 Windows the calling convention returns values in rax; zeroing
// the low 32 bits also zeros the full 64-bit register.
// -------------------------------------------------------------------------
static const BYTE g_shellcode[] = { 0x31, 0xC0, 0xC3 };

// -------------------------------------------------------------------------
// Helper: print the current protection of an address
// -------------------------------------------------------------------------
static void PrintProtection(const char* label, LPVOID addr)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    VirtualQuery(addr, &mbi, sizeof(mbi));
    DWORD p = mbi.Protect & 0xFF;
    const char* name =
        (p == PAGE_READWRITE)         ? "PAGE_READWRITE" :
        (p == PAGE_EXECUTE_READ)      ? "PAGE_EXECUTE_READ" :
        (p == PAGE_EXECUTE_READWRITE) ? "PAGE_EXECUTE_READWRITE (RWX — flagged)" :
                                        "OTHER";
    printf("  [%s] 0x%p  protect=%s\n", label, addr, name);
}

// -------------------------------------------------------------------------
// Safe pattern: alloc RW → fill → VirtualProtect RX → call
// -------------------------------------------------------------------------
static void SafePattern()
{
    printf("\n=== Safe Pattern: RW → fill → RX ===\n");

    // 1. Allocate with PAGE_READWRITE — writable but NOT executable.
    LPVOID mem = VirtualAlloc(NULL, sizeof(g_shellcode),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) {
        printf("[!] VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }
    printf("[+] Allocated %zu bytes at 0x%p\n", sizeof(g_shellcode), mem);
    PrintProtection("after alloc (RW)", mem);

    // 2. Copy shellcode bytes — only possible because the page is writable.
    memcpy(mem, g_shellcode, sizeof(g_shellcode));
    printf("[+] Copied %zu shellcode bytes to 0x%p\n", sizeof(g_shellcode), mem);
    printf("    Bytes: ");
    for (size_t i = 0; i < sizeof(g_shellcode); i++)
        printf("%02X ", ((BYTE*)mem)[i]);
    printf("\n");

    // 3. Change protection to RX (no longer writable).
    DWORD oldProtect = 0;
    if (!VirtualProtect(mem, sizeof(g_shellcode), PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[!] VirtualProtect RX failed: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    printf("[+] VirtualProtect → PAGE_EXECUTE_READ\n");
    PrintProtection("after VirtualProtect (RX)", mem);

    // 4. Cast to a function pointer and call.
    //    WINAPI = __stdcall on x86; on x64 there is one calling convention.
    typedef DWORD (WINAPI *ShellcodeFunc)();
    ShellcodeFunc func = (ShellcodeFunc)mem;

    printf("[+] Calling shellcode at 0x%p ...\n", mem);
    DWORD result = func();
    printf("[+] Shellcode returned: %lu  (expected 0 from xor eax,eax; ret)\n", result);

    // 5. Free the memory.
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] VirtualFree OK\n");
}

// -------------------------------------------------------------------------
// Anti-pattern: PAGE_EXECUTE_READWRITE (RWX)
// -------------------------------------------------------------------------
static void AntiPattern()
{
    printf("\n=== Anti-Pattern: PAGE_EXECUTE_READWRITE (RWX) ===\n");
    printf("[!] Allocating with PAGE_EXECUTE_READWRITE — this is the EDR-flagged pattern.\n");

    // Allocate RWX — writable AND executable simultaneously.
    LPVOID mem = VirtualAlloc(NULL, sizeof(g_shellcode),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[!] VirtualAlloc(RWX) failed: %lu\n", GetLastError());
        return;
    }
    PrintProtection("RWX allocation", mem);

    // This page can be written and immediately executed without VirtualProtect.
    memcpy(mem, g_shellcode, sizeof(g_shellcode));

    typedef DWORD (WINAPI *ShellcodeFunc)();
    DWORD result = ((ShellcodeFunc)mem)();
    printf("[+] RWX shellcode returned: %lu\n", result);

    VirtualFree(mem, 0, MEM_RELEASE);

    printf("\n[WHY EDRs FLAG THIS]\n");
    printf("  PAGE_EXECUTE_READWRITE allocations are a strong indicator of:\n");
    printf("    - Classic shellcode loaders (no need for VirtualProtect call)\n");
    printf("    - Process injection stagers\n");
    printf("    - In-memory patching of code\n");
    printf("  EDRs hook NtAllocateVirtualMemory and scan for MEM_PRIVATE + RWX\n");
    printf("  before the allocation is even committed.\n");
    printf("\n[EVASION CONTEXT — detection and defense]\n");
    printf("  Defenders look for:\n");
    printf("    1. NtAllocateVirtualMemory with Protect = PAGE_EXECUTE_READWRITE\n");
    printf("    2. NtProtectVirtualMemory transition from RW → RX on PRIVATE memory\n");
    printf("       (still suspicious but harder to catch without behaviour context)\n");
    printf("    3. CreateRemoteThread with start address in a PRIVATE region\n");
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------
int main()
{
    printf("=== Shellcode Execution Demo ===\n");
    printf("Test shellcode: 31 C0 C3  (xor eax,eax; ret) — returns 0, no side-effects.\n");

    SafePattern();
    AntiPattern();

    printf("\n=== Summary ===\n");
    printf("  SAFE:    VirtualAlloc(RW) → fill → VirtualProtect(RX) → call\n");
    printf("  FLAGGED: VirtualAlloc(RWX) → fill → call (no protect change needed)\n");
    printf("\n=== Done ===\n");
    return 0;
}
