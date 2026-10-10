// binary_analyst.cpp — PE binary analysis tool
// Compile: g++ -std=c++17 -o binary_analyst.exe binary_analyst.cpp
// Usage: binary_analyst.exe <file> | strings <file> | imports <file> | entropy <file> | compare <a> <b>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <set>
#include <cmath>
#include <algorithm>

// Suspicious API names to flag
static const char* SUSPICIOUS[] = {
    "VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "URLDownloadToFile","WinExec","ShellExecute","ShellExecuteA","ShellExecuteW",
    "CreateProcess","OpenProcess","NtUnmapViewOfSection","NtWriteVirtualMemory",
    "SetWindowsHookEx","GetAsyncKeyState","HttpSendRequest","InternetOpenUrl",
    "RegSetValueEx","RegCreateKeyEx","CopyFile","MoveFile","DeleteFile",
    "TerminateProcess","AdjustTokenPrivileges","LookupPrivilegeValue",
    nullptr
};

// ─── File mapping helper ──────────────────────────────────────────────────────

struct FileMap {
    const uint8_t* base = nullptr;
    size_t size = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap  = nullptr;

    bool open(const char* path) {
        hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        GetFileSizeEx(hFile, &sz);
        size = (size_t)sz.QuadPart;
        hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) return false;
        base = (const uint8_t*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        return base != nullptr;
    }
    ~FileMap() {
        if (base) UnmapViewOfFile(base);
        if (hMap)  CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }
    bool is_pe() const { return size > 0x40 && *(uint16_t*)base == 0x5A4D; }
};

// ─── Shannon entropy ──────────────────────────────────────────────────────────

static double shannon(const uint8_t* d, size_t n) {
    if (!n) return 0.0;
    uint64_t freq[256]{};
    for (size_t i = 0; i < n; ++i) ++freq[d[i]];
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / n;
        h -= p * log2(p);
    }
    return h;
}

// ─── strings <file> ───────────────────────────────────────────────────────────

static void cmd_strings(const char* path) {
    FileMap fm;
    if (!fm.open(path)) { fprintf(stderr, "Cannot open %s\n", path); return; }
    printf("=== Strings: %s ===\n", path);
    int count = 0;
    std::string cur;
    for (size_t i = 0; i < fm.size; ++i) {
        uint8_t c = fm.base[i];
        if (c >= 0x20 && c < 0x7F) {
            cur += (char)c;
        } else {
            if (cur.size() >= 4) { printf("  %s\n", cur.c_str()); ++count; }
            cur.clear();
        }
    }
    if (cur.size() >= 4) { printf("  %s\n", cur.c_str()); ++count; }
    printf("\nTotal: %d strings\n", count);
}

// ─── imports <file> ───────────────────────────────────────────────────────────

static void cmd_imports(const char* path) {
    FileMap fm;
    if (!fm.open(path)) { fprintf(stderr, "Cannot open %s\n", path); return; }
    if (!fm.is_pe()) { fprintf(stderr, "Not a PE file\n"); return; }

    auto* dos = (IMAGE_DOS_HEADER*)fm.base;
    auto* nth = (IMAGE_NT_HEADERS*)(fm.base + dos->e_lfanew);
    auto& imp_dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp_dir.VirtualAddress) { printf("No import table\n"); return; }

    // RVA -> file offset via section table
    auto* sec = IMAGE_FIRST_SECTION(nth);
    WORD  nsec = nth->FileHeader.NumberOfSections;
    auto rva2off = [&](DWORD rva) -> const uint8_t* {
        for (WORD i = 0; i < nsec; ++i) {
            if (rva >= sec[i].VirtualAddress &&
                rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
                return fm.base + sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
        }
        return nullptr;
    };

    printf("=== Imports: %s ===\n\n", path);
    int flagged = 0;
    auto* idt = (IMAGE_IMPORT_DESCRIPTOR*)rva2off(imp_dir.VirtualAddress);
    if (!idt) { printf("Cannot resolve import table RVA\n"); return; }

    for (; idt->Name; ++idt) {
        const char* dll = (const char*)rva2off(idt->Name);
        printf("  %s\n", dll ? dll : "?");
        DWORD* thunk_rva = idt->OriginalFirstThunk
            ? (DWORD*)rva2off(idt->OriginalFirstThunk)
            : (DWORD*)rva2off(idt->FirstThunk);
        if (!thunk_rva) continue;
        bool is64 = nth->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
        while (*thunk_rva) {
            DWORD snap_flag = is64 ? 0 : IMAGE_ORDINAL_FLAG32;
            if (!(*thunk_rva & snap_flag)) {
                auto* ibn = (IMAGE_IMPORT_BY_NAME*)rva2off(*thunk_rva & 0x7FFFFFFF);
                if (ibn) {
                    const char* fn = (const char*)ibn->Name;
                    bool susp = false;
                    for (int i = 0; SUSPICIOUS[i]; ++i)
                        if (!strcmp(fn, SUSPICIOUS[i])) { susp = true; break; }
                    printf("    %s%s\n", fn, susp ? "  <-- [SUSPICIOUS]" : "");
                    if (susp) ++flagged;
                }
            }
            ++thunk_rva;
        }
    }
    printf("\nFlagged suspicious APIs: %d\n", flagged);
}

// ─── entropy <file> ───────────────────────────────────────────────────────────

static void cmd_entropy(const char* path) {
    FileMap fm;
    if (!fm.open(path)) { fprintf(stderr, "Cannot open %s\n", path); return; }
    printf("=== Entropy: %s ===\n", path);
    double total = shannon(fm.base, fm.size);
    printf("  File total: %.4f %s\n", total, total > 7.0 ? "<-- HIGH (packed?)" : "");

    if (!fm.is_pe()) { printf("  (not a PE)\n"); return; }
    auto* dos = (IMAGE_DOS_HEADER*)fm.base;
    auto* nth = (IMAGE_NT_HEADERS*)(fm.base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nth);
    WORD nsec = nth->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nsec; ++i) {
        if (!sec[i].SizeOfRawData) continue;
        double e = shannon(fm.base + sec[i].PointerToRawData, sec[i].SizeOfRawData);
        printf("  %-8.8s  sz=%7u  e=%.4f%s\n",
               (char*)sec[i].Name, sec[i].SizeOfRawData, e,
               e > 7.0 ? "  <-- HIGH" : "");
    }
}

// ─── Full analysis ────────────────────────────────────────────────────────────

static void cmd_full(const char* path) {
    FileMap fm;
    if (!fm.open(path)) { fprintf(stderr, "Cannot open %s\n", path); return; }
    printf("=== Binary Analysis: %s ===\n\n", path);
    printf("Size: %zu bytes\n", fm.size);

    if (!fm.is_pe()) { printf("Not a PE file.\n"); return; }

    auto* dos = (IMAGE_DOS_HEADER*)fm.base;
    auto* nth = (IMAGE_NT_HEADERS*)(fm.base + dos->e_lfanew);
    bool is64 = nth->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    printf("Architecture:  %s\n", is64 ? "x64 (PE32+)" : "x86 (PE32)");
    printf("Subsystem:     %u\n", nth->OptionalHeader.Subsystem);
    printf("Entry point:   0x%08X\n", nth->OptionalHeader.AddressOfEntryPoint);
    printf("ImageBase:     0x%llX\n", (unsigned long long)nth->OptionalHeader.ImageBase);
    printf("Sections:      %u\n\n", nth->FileHeader.NumberOfSections);

    printf("--- Entropy per section ---\n");
    auto* sec = IMAGE_FIRST_SECTION(nth);
    WORD nsec = nth->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nsec; ++i) {
        if (!sec[i].SizeOfRawData) continue;
        double e = shannon(fm.base + sec[i].PointerToRawData, sec[i].SizeOfRawData);
        printf("  %-8.8s  raw=%7u  va=0x%08X  e=%.4f%s\n",
               (char*)sec[i].Name, sec[i].SizeOfRawData, sec[i].VirtualAddress, e,
               e > 7.0 ? "  <-- HIGH" : "");
    }
    printf("\n--- Imports (suspicious flagged) ---\n");
    cmd_imports(path);
}

// ─── compare <a> <b> ──────────────────────────────────────────────────────────

static void cmd_compare(const char* pa, const char* pb) {
    FileMap fa, fb;
    if (!fa.open(pa)) { fprintf(stderr, "Cannot open %s\n", pa); return; }
    if (!fb.open(pb)) { fprintf(stderr, "Cannot open %s\n", pb); return; }

    printf("=== Compare ===\n");
    printf("  A: %s (%zu bytes)\n", pa, fa.size);
    printf("  B: %s (%zu bytes)\n", pb, fb.size);

    size_t minlen = std::min(fa.size, fb.size);
    int diffs = 0;
    for (size_t i = 0; i < minlen && diffs < 32; ++i) {
        if (fa.base[i] != fb.base[i]) {
            printf("  Offset 0x%06zX:  A=%02X  B=%02X\n", i, fa.base[i], fb.base[i]);
            ++diffs;
        }
    }
    if (diffs == 32) printf("  ... (truncated at 32 differences)\n");
    printf("\nTotal differing bytes (first %zu): counted up to 32\n", minlen);
    if (fa.size != fb.size) printf("  Sizes differ by %zd bytes\n", (ssize_t)fa.size - (ssize_t)fb.size);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  binary_analyst.exe <file>             -- full analysis\n"
               "  binary_analyst.exe strings  <file>\n"
               "  binary_analyst.exe imports  <file>\n"
               "  binary_analyst.exe entropy  <file>\n"
               "  binary_analyst.exe compare  <a> <b>\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (argc >= 3 && cmd == "strings")            cmd_strings(argv[2]);
    else if (argc >= 3 && cmd == "imports")            cmd_imports(argv[2]);
    else if (argc >= 3 && cmd == "entropy")            cmd_entropy(argv[2]);
    else if (argc >= 4 && cmd == "compare")            cmd_compare(argv[2], argv[3]);
    else if (argc >= 2 && argv[1][0] != '-')           cmd_full(argv[1]);
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
