/*
  Exercise 01 — Full PE Analyzer
  --------------------------------
  Build a self-contained PE analysis tool. Given any .exe or .dll:
  - Print basic metadata
  - List all sections with entropy
  - Print all imports (DLL → function)
  - Print all exports
  - Extract ASCII strings ≥ 6 chars
  - Overall verdict: SUSPICIOUS if any section entropy > 7.2

  Usage:
    ex01.exe target.exe
    ex01.exe C:\Windows\System32\ntdll.dll

  Expected output:
    === PE Analysis: ntdll.dll ===
    Machine:    AMD64
    Timestamp:  2024-01-15 08:22:11 (may be fake in packed files)
    Entry RVA:  0x00000000 (DLLs often have no real entry)
    Sections: 6
      .text     RVA=0x1000  Size=0x12A000  Entropy=6.21  RWX=r-x
      .rdata    RVA=0x12B000 Size=0x4A000  Entropy=4.89  RWX=r--
      ...
    Imports: 3 DLLs
      ntdll.dll: (none — this IS ntdll)
    Exports: 2847 functions
    Suspicious APIs found: none
    Verdict: CLEAN

  Tasks:
  1. Implement loadFile() — map a file into memory using CreateFileMapping.
  2. Implement printSections() — iterate sections, compute entropy for each.
  3. Implement printImports() — full RVA → file offset conversion.
  4. Implement printExports() — name + RVA for each export.
  5. Implement extractStrings() — print offset + value for each string >= minLen.
  6. Implement computeVerdict() — SUSPICIOUS if entropy > 7.2 or known bad imports.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_pe_analyzer.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <ctime>
#include <iomanip>

// List of API names that indicate suspicious behavior
static const char* SUSPICIOUS_APIS[] = {
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "QueueUserAPC", "SetWindowsHookEx", "NtCreateThreadEx",
    "OpenProcess", "ReadProcessMemory", "MiniDumpWriteDump",
    "CryptProtectData", "CryptUnprotectData",
    nullptr
};

struct PEFile {
    HANDLE      hFile    = INVALID_HANDLE_VALUE;
    HANDLE      hMap     = nullptr;
    const BYTE* base     = nullptr;
    size_t      fileSize = 0;

    bool valid() const { return base != nullptr; }

    // TODO: Convert an RVA to a file offset using section headers
    DWORD rvaToOffset(DWORD rva) const {
        // YOUR CODE HERE
        return rva;  // placeholder
    }

    IMAGE_NT_HEADERS* ntHeaders() const {
        if (!base) return nullptr;
        auto dos = (IMAGE_DOS_HEADER*)base;
        return (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    }
};

// TODO: Load a PE file into memory using CreateFile + CreateFileMapping + MapViewOfFile.
// Populate pefile.base and pefile.fileSize.
// Return true on success.
bool loadFile(const char* path, PEFile& pefile) {
    // YOUR CODE HERE
    return false;
}

void unloadFile(PEFile& pefile) {
    if (pefile.base) UnmapViewOfFile(pefile.base);
    if (pefile.hMap)  CloseHandle(pefile.hMap);
    if (pefile.hFile != INVALID_HANDLE_VALUE) CloseHandle(pefile.hFile);
    pefile = {};
}

double entropy(const BYTE* data, size_t size) {
    if (!size) return 0.0;
    int freq[256] = {};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / size;
        e -= p * log2(p);
    }
    return e;
}

// TODO: Print section table with entropy and permissions.
void printSections(const PEFile& pe) {
    // YOUR CODE HERE
}

// TODO: Print imports: for each DLL, list every imported function.
// Flag any function in SUSPICIOUS_APIS[].
bool printImports(const PEFile& pe) {
    // returns true if any suspicious API was found
    // YOUR CODE HERE
    return false;
}

// TODO: Print exports: ordinal, RVA, name.
void printExports(const PEFile& pe) {
    // YOUR CODE HERE
}

// TODO: Extract and print ASCII strings of length >= minLen.
void extractStrings(const PEFile& pe, int minLen) {
    // YOUR CODE HERE
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }

    PEFile pe;
    if (!loadFile(argv[1], pe)) {
        printf("[-] Failed to load: %s\n", argv[1]);
        return 1;
    }

    IMAGE_NT_HEADERS* nt = pe.ntHeaders();
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Not a valid PE file\n");
        unloadFile(pe); return 1;
    }

    printf("=== PE Analysis: %s ===\n\n", argv[1]);

    // Machine
    const char* machine = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
                          ? "AMD64" : "x86";
    printf("Machine:   %s\n", machine);

    // Compile timestamp
    time_t ts = nt->FileHeader.TimeDateStamp;
    printf("Timestamp: %s", ctime(&ts));
    printf("Entry RVA: 0x%08X\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("\n");

    printf("[SECTIONS]\n");
    printSections(pe);
    printf("\n");

    printf("[IMPORTS]\n");
    bool suspicious = printImports(pe);
    printf("\n");

    printf("[EXPORTS]\n");
    printExports(pe);
    printf("\n");

    printf("[STRINGS (length >= 8)]\n");
    extractStrings(pe, 8);
    printf("\n");

    printf("[VERDICT]\n");
    printf("%s\n", suspicious ? "SUSPICIOUS — potentially malicious APIs imported"
                              : "CLEAN — no obviously suspicious imports");

    unloadFile(pe);
    return 0;
}
