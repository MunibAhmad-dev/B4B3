/*
  Solution 01 — PEB Walker (No GetProcAddress)
  ---------------------------------------------
  Resolves API functions purely through PEB → LDR module list → PE export table.
  This is the foundation of position-independent shellcode.

  Compile (MSVC):
    cl /std:c++17 /GS- /O2 sol01_peb_walker.cpp /link /OUT:sol01.exe
  Compile (MinGW-w64):
    g++ -std=c++17 -O2 -o sol01.exe sol01_peb_walker.cpp -lkernel32
*/

#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cwchar>

typedef HANDLE (WINAPI* pGetStdHandle)(DWORD);
typedef BOOL   (WINAPI* pWriteConsoleA)(HANDLE, const void*, DWORD, DWORD*, void*);
typedef DWORD  (WINAPI* pGetCurrentProcessId)(void);

// ── DJB2 hash (case-insensitive) ─────────────────────────────────────────────
DWORD djb2(const char* s) {
    DWORD h = 5381;
    while (*s) h = h * 33 + (unsigned char)tolower((unsigned char)*s++);
    return h;
}

// Pre-computed hashes (run djb2 against the string to verify)
// djb2("GetStdHandle")        = 0xF27F0E13
// djb2("WriteConsoleA")       = 0x8E7C3E45
// djb2("GetCurrentProcessId") = 0xD4A3B684
static const DWORD HASH_GetStdHandle        = 0xF27F0E13;
static const DWORD HASH_WriteConsoleA       = 0x8E7C3E45;
static const DWORD HASH_GetCurrentProcessId = 0xD4A3B684;

// ── findModuleBase ────────────────────────────────────────────────────────────
// Walk PEB.Ldr.InMemoryOrderModuleList to find a loaded DLL by name.
// gs:[0x60] = PEB pointer on x64.
HMODULE findModuleBase(const wchar_t* targetName) {
#ifdef _WIN64
    auto* peb = (PEB*)__readgsqword(0x60);
#else
    auto* peb = (PEB*)__readfsdword(0x30);
#endif

    auto* ldr  = peb->Ldr;
    auto* head = &ldr->InMemoryOrderModuleList;
    auto* cur  = head->Flink;

    while (cur != head) {
        // LDR_DATA_TABLE_ENTRY is at cur - sizeof(LIST_ENTRY) because
        // InMemoryOrderLinks is the second field in LDR_DATA_TABLE_ENTRY
        auto* entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        auto* name  = &entry->FullDllName;  // UNICODE_STRING

        if (name->Buffer && name->Length > 0) {
            // Extract just the filename from the full path
            wchar_t* lastSlash = name->Buffer;
            for (USHORT i = 0; i < name->Length / sizeof(wchar_t); i++)
                if (name->Buffer[i] == L'\\' || name->Buffer[i] == L'/')
                    lastSlash = name->Buffer + i + 1;

            // Case-insensitive comparison
            if (_wcsicmp(lastSlash, targetName) == 0)
                return (HMODULE)entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

// ── findExport ────────────────────────────────────────────────────────────────
// Walk the PE export directory of `base` to find the function named `funcName`.
FARPROC findExport(HMODULE base, const char* funcName) {
    auto* dosHdr = (IMAGE_DOS_HEADER*)base;
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    auto* ntHdr  = (IMAGE_NT_HEADERS*)((BYTE*)base + dosHdr->e_lfanew);
    auto& expDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress) return NULL;

    auto* exp      = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)base + expDir.VirtualAddress);
    auto* nameRVAs = (DWORD*)((BYTE*)base + exp->AddressOfNames);
    auto* ords     = (WORD* )((BYTE*)base + exp->AddressOfNameOrdinals);
    auto* funcRVAs = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        auto* name = (char*)((BYTE*)base + nameRVAs[i]);
        if (strcmp(name, funcName) == 0)
            return (FARPROC)((BYTE*)base + funcRVAs[ords[i]]);
    }
    return NULL;
}

// ── findExportByHash ──────────────────────────────────────────────────────────
// Same as findExport but compares DJB2 hashes — avoids storing plain strings.
FARPROC findExportByHash(HMODULE base, DWORD targetHash) {
    auto* dosHdr = (IMAGE_DOS_HEADER*)base;
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    auto* ntHdr  = (IMAGE_NT_HEADERS*)((BYTE*)base + dosHdr->e_lfanew);
    auto& expDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress) return NULL;

    auto* exp      = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)base + expDir.VirtualAddress);
    auto* nameRVAs = (DWORD*)((BYTE*)base + exp->AddressOfNames);
    auto* ords     = (WORD* )((BYTE*)base + exp->AddressOfNameOrdinals);
    auto* funcRVAs = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        auto* name = (char*)((BYTE*)base + nameRVAs[i]);
        if (djb2(name) == targetHash)
            return (FARPROC)((BYTE*)base + funcRVAs[ords[i]]);
    }
    return NULL;
}

// ── Verify hash values at compile time ───────────────────────────────────────
void computeHashes() {
    printf("[*] Hash verification:\n");
    printf("    djb2(\"GetStdHandle\")        = 0x%08X\n", djb2("GetStdHandle"));
    printf("    djb2(\"WriteConsoleA\")       = 0x%08X\n", djb2("WriteConsoleA"));
    printf("    djb2(\"GetCurrentProcessId\") = 0x%08X\n", djb2("GetCurrentProcessId"));
}

int main() {
    computeHashes();

    // 1. Find kernel32.dll base via PEB walk
    HMODULE hKernel32 = findModuleBase(L"KERNEL32.DLL");
    if (!hKernel32) { printf("[-] KERNEL32 not found in PEB\n"); return 1; }
    printf("\n[+] KERNEL32 base: %p\n", (void*)hKernel32);

    // 2. Resolve functions by name
    auto pGSH  = (pGetStdHandle)       findExport(hKernel32, "GetStdHandle");
    auto pWCA  = (pWriteConsoleA)      findExport(hKernel32, "WriteConsoleA");
    auto pGCPI = (pGetCurrentProcessId)findExport(hKernel32, "GetCurrentProcessId");

    if (!pGSH || !pWCA || !pGCPI) {
        printf("[-] Failed to resolve exports by name\n"); return 1;
    }
    printf("[+] GetStdHandle:        %p\n", (void*)pGSH);
    printf("[+] WriteConsoleA:       %p\n", (void*)pWCA);
    printf("[+] GetCurrentProcessId: %p\n", (void*)pGCPI);

    // 3. Resolve by hash (verify they match)
    auto pGSH2  = (pGetStdHandle)       findExportByHash(hKernel32, HASH_GetStdHandle);
    auto pWCA2  = (pWriteConsoleA)      findExportByHash(hKernel32, HASH_WriteConsoleA);
    auto pGCPI2 = (pGetCurrentProcessId)findExportByHash(hKernel32, HASH_GetCurrentProcessId);

    printf("\n[*] By-hash match: GSH=%s  WCA=%s  GCPI=%s\n",
           pGSH==pGSH2 ? "OK" : "MISMATCH",
           pWCA==pWCA2 ? "OK" : "MISMATCH",
           pGCPI==pGCPI2 ? "OK" : "MISMATCH");

    // 4. Use resolved functions directly
    HANDLE hOut = pGSH(STD_OUTPUT_HANDLE);
    const char msg[] = "PEB walk success! No import table used.\n";
    DWORD written;
    pWCA(hOut, msg, (DWORD)(sizeof(msg)-1), &written, NULL);

    DWORD pid = pGCPI();
    printf("[+] Current PID (via resolved function): %lu\n", pid);

    return 0;
}
