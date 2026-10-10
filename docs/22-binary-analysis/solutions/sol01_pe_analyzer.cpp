/*
  Solution 01 — Full PE Analyzer
  --------------------------------
  Complete: loadFile, printSections (with entropy), printImports, printExports,
  extractStrings, and computeVerdict.

  Compile:
    g++ -std=c++17 -Wall -o sol01.exe sol01_pe_analyzer.cpp
  Usage:
    sol01.exe notepad.exe
    sol01.exe C:\Windows\System32\ntdll.dll
*/

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <ctime>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

// ── loadFile: map PE into memory ──────────────────────────────────────────────
struct PeFile {
    HANDLE hFile   = INVALID_HANDLE_VALUE;
    HANDLE hMap    = NULL;
    BYTE*  base    = nullptr;
    size_t size    = 0;

    ~PeFile() {
        if (base)                      UnmapViewOfFile(base);
        if (hMap && hMap != NULL)      CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }
};

bool loadFile(const char* path, PeFile& pe) {
    pe.hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (pe.hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open: %s (%lu)\n", path, GetLastError()); return false;
    }
    pe.size = GetFileSize(pe.hFile, NULL);
    pe.hMap = CreateFileMappingA(pe.hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!pe.hMap) { printf("[-] CreateFileMapping: %lu\n", GetLastError()); return false; }
    pe.base = (BYTE*)MapViewOfFile(pe.hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pe.base) { printf("[-] MapViewOfFile: %lu\n", GetLastError()); return false; }
    return true;
}

// ── Helper: RVA → file offset ─────────────────────────────────────────────────
static DWORD rvaToOffset(const BYTE* base, DWORD rva) {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    WORD  numSec  = nt->FileHeader.NumberOfSections;
    WORD  optSize = nt->FileHeader.SizeOfOptionalHeader;
    auto* sec     = (IMAGE_SECTION_HEADER*)(
        base + dos->e_lfanew + sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) + optSize);

    for (WORD i = 0; i < numSec; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva <  sec[i].VirtualAddress + sec[i].SizeOfRawData) {
            return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
        }
    }
    return 0;
}

// ── Shannon entropy ───────────────────────────────────────────────────────────
static double entropy(const BYTE* data, size_t len) {
    if (!len) return 0;
    size_t freq[256] = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double e = 0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / len;
        e -= p * log2(p);
    }
    return e;
}

// ── printSections ─────────────────────────────────────────────────────────────
static bool printSections(const BYTE* base) {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { printf("[-] Not a PE\n"); return false; }
    auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    WORD numSec = nt->FileHeader.NumberOfSections;

    // Timestamp
    time_t ts = nt->FileHeader.TimeDateStamp;
    char tsBuf[32]; strftime(tsBuf, sizeof(tsBuf), "%Y-%m-%d %H:%M:%S", gmtime(&ts));

    const char* machine = nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "AMD64" :
                          nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386  ? "I386"  : "Unknown";
    printf("Machine:   %s\n", machine);
    printf("Timestamp: %s\n", tsBuf);
    printf("Sections:  %d\n", numSec);

    WORD optSize = nt->FileHeader.SizeOfOptionalHeader;
    auto* sec = (IMAGE_SECTION_HEADER*)(base + dos->e_lfanew +
                sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + optSize);

    printf("  %-10s  %-10s  %-10s  %7s  %s\n",
           "Name", "RVA", "RawSize", "Entropy", "Protect");
    printf("  %s\n", std::string(55, '-').c_str());

    for (WORD i = 0; i < numSec; i++) {
        char name[9] = {}; memcpy(name, sec[i].Name, 8);
        DWORD flags = sec[i].Characteristics;
        char rwx[4] = { flags & IMAGE_SCN_MEM_READ    ? 'r' : '-',
                        flags & IMAGE_SCN_MEM_WRITE   ? 'w' : '-',
                        flags & IMAGE_SCN_MEM_EXECUTE ? 'x' : '-', 0 };

        double ent = entropy(base + sec[i].PointerToRawData, sec[i].SizeOfRawData);
        printf("  %-10s  0x%08X  0x%08X  %7.2f  %s%s\n",
               name, sec[i].VirtualAddress, sec[i].SizeOfRawData, ent, rwx,
               ent > 7.2 ? "  ← HIGH ENTROPY" : "");
    }
    return true;
}

// ── printImports ──────────────────────────────────────────────────────────────
static void printImports(const BYTE* base) {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    bool is64 = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!impDir.VirtualAddress) { printf("  (no imports)\n"); return; }

    DWORD impOff = rvaToOffset(base, impDir.VirtualAddress);
    if (!impOff) { printf("  (cannot resolve import directory)\n"); return; }

    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impOff);
    int dllCount = 0;

    for (; desc->Name; desc++, dllCount++) {
        DWORD nameOff = rvaToOffset(base, desc->Name);
        if (!nameOff) continue;
        const char* dllName = (char*)(base + nameOff);

        printf("  %s:\n", dllName);

        DWORD thunk = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        DWORD thunkOff = rvaToOffset(base, thunk);
        if (!thunkOff) continue;

        if (is64) {
            auto* entry = (IMAGE_THUNK_DATA64*)(base + thunkOff);
            for (; entry->u1.AddressOfData; entry++) {
                if (IMAGE_SNAP_BY_ORDINAL64(entry->u1.Ordinal)) {
                    printf("    [ord %llu]\n", IMAGE_ORDINAL64(entry->u1.Ordinal));
                } else {
                    DWORD off = rvaToOffset(base, (DWORD)entry->u1.AddressOfData);
                    if (off) printf("    %s\n", (char*)(base + off + 2));
                }
            }
        } else {
            auto* entry = (IMAGE_THUNK_DATA32*)(base + thunkOff);
            for (; entry->u1.AddressOfData; entry++) {
                if (IMAGE_SNAP_BY_ORDINAL32(entry->u1.Ordinal)) {
                    printf("    [ord %lu]\n", IMAGE_ORDINAL32(entry->u1.Ordinal));
                } else {
                    DWORD off = rvaToOffset(base, (DWORD)entry->u1.AddressOfData);
                    if (off) printf("    %s\n", (char*)(base + off + 2));
                }
            }
        }
    }
    if (!dllCount) printf("  (no import table entries)\n");
}

// ── printExports ──────────────────────────────────────────────────────────────
static void printExports(const BYTE* base) {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress) { printf("  (no exports)\n"); return; }

    DWORD expOff = rvaToOffset(base, expDir.VirtualAddress);
    if (!expOff) { printf("  (cannot resolve export directory)\n"); return; }

    auto* exp  = (IMAGE_EXPORT_DIRECTORY*)(base + expOff);
    auto* nameRVAs = (DWORD*)(base + rvaToOffset(base, exp->AddressOfNames));
    auto* ords     = (WORD* )(base + rvaToOffset(base, exp->AddressOfNameOrdinals));
    auto* funcRVAs = (DWORD*)(base + rvaToOffset(base, exp->AddressOfFunctions));

    printf("  Total: %lu named exports\n", exp->NumberOfNames);
    DWORD show = min(exp->NumberOfNames, (DWORD)20);
    for (DWORD i = 0; i < show; i++) {
        DWORD nameOff = rvaToOffset(base, nameRVAs[i]);
        if (!nameOff) continue;
        printf("  +0x%08X  %s\n", funcRVAs[ords[i]], (char*)(base + nameOff));
    }
    if (exp->NumberOfNames > 20)
        printf("  ... (showing 20 of %lu)\n", exp->NumberOfNames);
}

// ── extractStrings ────────────────────────────────────────────────────────────
static void extractStrings(const BYTE* base, size_t fileSize, int minLen = 6) {
    printf("  (first 20 strings ≥ %d chars)\n", minLen);
    int count = 0;
    for (size_t i = 0; i < fileSize && count < 20; ) {
        if (base[i] >= 0x20 && base[i] < 0x7F) {
            size_t j = i;
            while (j < fileSize && base[j] >= 0x20 && base[j] < 0x7F) j++;
            if ((int)(j - i) >= minLen) {
                printf("  +0x%08zX  %.*s\n", i, (int)(j-i), (char*)(base+i));
                count++;
            }
            i = j;
        } else {
            i++;
        }
    }
}

// ── computeVerdict ────────────────────────────────────────────────────────────
// SUSPICIOUS if: any section entropy > 7.2, or import of known bad API
static const char* BAD_APIS[] = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "URLDownloadToFile", "CryptEncrypt",
    nullptr
};

static std::string computeVerdict(const BYTE* base, size_t fileSize) {
    (void)fileSize;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    WORD numSec  = nt->FileHeader.NumberOfSections;
    WORD optSize = nt->FileHeader.SizeOfOptionalHeader;
    auto* sec    = (IMAGE_SECTION_HEADER*)(base + dos->e_lfanew +
                   sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + optSize);

    bool highEntropy = false;
    for (WORD i = 0; i < numSec; i++) {
        double e = entropy(base + sec[i].PointerToRawData, sec[i].SizeOfRawData);
        if (e > 7.2) { highEntropy = true; break; }
    }

    // Check imports for bad APIs
    bool badImport = false;
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress) {
        DWORD impOff = rvaToOffset(base, impDir.VirtualAddress);
        if (impOff) {
            auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impOff);
            for (; desc->Name && !badImport; desc++) {
                DWORD thunk    = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
                DWORD thunkOff = rvaToOffset(base, thunk);
                if (!thunkOff) continue;
                bool is64 = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
                if (is64) {
                    auto* e64 = (IMAGE_THUNK_DATA64*)(base + thunkOff);
                    for (; e64->u1.AddressOfData && !badImport; e64++) {
                        if (IMAGE_SNAP_BY_ORDINAL64(e64->u1.Ordinal)) continue;
                        DWORD off = rvaToOffset(base, (DWORD)e64->u1.AddressOfData);
                        if (!off) continue;
                        const char* fn = (char*)(base + off + 2);
                        for (int k = 0; BAD_APIS[k]; k++)
                            if (!strcmp(fn, BAD_APIS[k])) { badImport = true; break; }
                    }
                }
            }
        }
    }

    if (highEntropy && badImport) return "HIGHLY SUSPICIOUS (high entropy + bad imports)";
    if (highEntropy)               return "SUSPICIOUS (high entropy — possible packing)";
    if (badImport)                 return "SUSPICIOUS (bad API imports)";
    return "CLEAN";
}

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: %s <target.exe>\n", argv[0]); return 1; }

    PeFile pe;
    if (!loadFile(argv[1], pe)) return 1;

    auto* dos = (IMAGE_DOS_HEADER*)pe.base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a PE file\n"); return 1;
    }

    printf("\n=== PE Analysis: %s ===\n\n", argv[1]);
    printSections(pe.base);

    printf("\nImports:\n");
    printImports(pe.base);

    printf("\nExports:\n");
    printExports(pe.base);

    printf("\nStrings:\n");
    extractStrings(pe.base, pe.size);

    printf("\nVerdict: %s\n", computeVerdict(pe.base, pe.size).c_str());
    return 0;
}
