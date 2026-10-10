// patch_differ.cpp — binary patch diffing tool
// Compile: g++ -std=c++17 -o patch_differ.exe patch_differ.cpp
// Usage: patch_differ.exe bytes <old> <new> | sections <old> <new> | functions <old> <new>
//                         analyze <old> <new> [offset] | summary <old> <new>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cmath>

// ─── File mapping ─────────────────────────────────────────────────────────────

struct FileMap {
    const uint8_t* base = nullptr;
    size_t size = 0;
    HANDLE hf = INVALID_HANDLE_VALUE, hm = nullptr;
    bool open(const char* path) {
        hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{}; GetFileSizeEx(hf, &sz); size = (size_t)sz.QuadPart;
        hm = CreateFileMappingA(hf, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hm) return false;
        base = (const uint8_t*)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
        return base != nullptr;
    }
    ~FileMap() {
        if (base) UnmapViewOfFile(base);
        if (hm)   CloseHandle(hm);
        if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
    }
    bool is_pe() const { return size > 0x40 && *(uint16_t*)base == 0x5A4D; }
};

// ─── DJB2 hash for function fingerprinting ───────────────────────────────────

static uint32_t djb2_buf(const uint8_t* d, size_t n) {
    uint32_t h = 5381;
    for (size_t i = 0; i < n; ++i) h = ((h << 5) + h) ^ d[i];
    return h;
}

// ─── PE helpers ───────────────────────────────────────────────────────────────

static const uint8_t* rva_to_ptr(const uint8_t* base, DWORD rva) {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nth = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nth);
    WORD nsec = nth->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nsec; ++i) {
        if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
            return base + sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
    }
    return nullptr;
}

// ─── bytes <old> <new> ────────────────────────────────────────────────────────

static void cmd_bytes(const char* pa, const char* pb) {
    FileMap fa, fb;
    if (!fa.open(pa)) { fprintf(stderr, "Cannot open %s\n", pa); return; }
    if (!fb.open(pb)) { fprintf(stderr, "Cannot open %s\n", pb); return; }
    printf("=== Raw Byte Diff ===\n  A: %s (%zu bytes)\n  B: %s (%zu bytes)\n\n",
           pa, fa.size, pb, fb.size);

    size_t minlen = std::min(fa.size, fb.size);
    int diffs = 0;
    for (size_t i = 0; i < minlen; ++i) {
        if (fa.base[i] != fb.base[i]) {
            printf("  0x%06zX:  %02X -> %02X\n", i, fa.base[i], fb.base[i]);
            if (++diffs >= 50) { printf("  ... (truncated)\n"); break; }
        }
    }
    if (fa.size != fb.size)
        printf("\n  Size delta: %+zd bytes\n", (ssize_t)fb.size - (ssize_t)fa.size);
    printf("\nTotal: %d differing bytes shown\n", diffs);
}

// ─── sections <old> <new> ────────────────────────────────────────────────────

static void cmd_sections(const char* pa, const char* pb) {
    FileMap fa, fb;
    if (!fa.open(pa)) { fprintf(stderr, "Cannot open %s\n", pa); return; }
    if (!fb.open(pb)) { fprintf(stderr, "Cannot open %s\n", pb); return; }
    if (!fa.is_pe() || !fb.is_pe()) { fprintf(stderr, "Both files must be PE\n"); return; }

    printf("=== PE Section Diff ===\n");
    auto* dos_a = (IMAGE_DOS_HEADER*)fa.base;
    auto* nth_a = (IMAGE_NT_HEADERS*)(fa.base + dos_a->e_lfanew);
    auto* sec_a = IMAGE_FIRST_SECTION(nth_a);
    WORD nsec_a = nth_a->FileHeader.NumberOfSections;

    auto* dos_b = (IMAGE_DOS_HEADER*)fb.base;
    auto* nth_b = (IMAGE_NT_HEADERS*)(fb.base + dos_b->e_lfanew);
    auto* sec_b = IMAGE_FIRST_SECTION(nth_b);
    WORD nsec_b = nth_b->FileHeader.NumberOfSections;

    printf("  %-10s  %-10s  %-10s  %s\n", "Section", "Old hash", "New hash", "Changed");
    printf("  %s\n", std::string(55, '-').c_str());

    WORD n = std::max(nsec_a, nsec_b);
    for (WORD i = 0; i < n; ++i) {
        uint32_t ha = 0, hb = 0;
        char name[9]{};
        if (i < nsec_a && sec_a[i].SizeOfRawData)
            ha = djb2_buf(fa.base + sec_a[i].PointerToRawData, sec_a[i].SizeOfRawData);
        if (i < nsec_b && sec_b[i].SizeOfRawData)
            hb = djb2_buf(fb.base + sec_b[i].PointerToRawData, sec_b[i].SizeOfRawData);
        const char* sname = (i < nsec_a) ? (const char*)sec_a[i].Name :
                            (i < nsec_b) ? (const char*)sec_b[i].Name : "?";
        snprintf(name, sizeof(name), "%.8s", sname);
        printf("  %-10s  %08X    %08X    %s\n", name, ha, hb,
               ha != hb ? "YES <--" : "no");
    }
}

// ─── functions <old> <new> ───────────────────────────────────────────────────

static void cmd_functions(const char* pa, const char* pb) {
    FileMap fa, fb;
    if (!fa.open(pa)) { fprintf(stderr, "Cannot open %s\n", pa); return; }
    if (!fb.open(pb)) { fprintf(stderr, "Cannot open %s\n", pb); return; }
    if (!fa.is_pe() || !fb.is_pe()) { fprintf(stderr, "Both must be PE\n"); return; }
    printf("=== Export Function Diff ===\n");

    auto get_exports = [](const uint8_t* base) -> std::map<std::string, uint32_t> {
        std::map<std::string, uint32_t> m;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        auto* nth = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        auto& dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir.VirtualAddress) return m;
        auto* exp   = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress); // note: not rva_to_ptr here, using direct base
        auto* names = (DWORD*)(base + exp->AddressOfNames);
        auto* funcs = (DWORD*)(base + exp->AddressOfFunctions);
        auto* ords  = (WORD* )(base + exp->AddressOfNameOrdinals);
        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            const char* name = (const char*)(base + names[i]);
            DWORD fn_off = funcs[ords[i]];
            const uint8_t* fn_ptr = base + fn_off;
            // hash first 64 bytes of function
            uint32_t h = djb2_buf(fn_ptr, std::min((size_t)64, (size_t)0x200));
            m[name] = h;
        }
        return m;
    };

    auto ea = get_exports(fa.base);
    auto eb = get_exports(fb.base);

    int changed = 0, added = 0, removed = 0;
    for (auto& [name, ha] : ea) {
        auto it = eb.find(name);
        if (it == eb.end()) { printf("  [-] %-40s  (removed)\n", name.c_str()); ++removed; }
        else if (it->second != ha) { printf("  [*] %-40s  CHANGED\n", name.c_str()); ++changed; }
    }
    for (auto& [name, hb] : eb) {
        if (ea.find(name) == ea.end()) { printf("  [+] %-40s  (added)\n", name.c_str()); ++added; }
    }
    printf("\nChanged: %d  Added: %d  Removed: %d\n", changed, added, removed);
}

// ─── analyze <old> <new> [offset] ────────────────────────────────────────────

static void cmd_analyze(const char* pa, const char* pb, size_t offset) {
    FileMap fa, fb;
    if (!fa.open(pa)) { fprintf(stderr, "Cannot open %s\n", pa); return; }
    if (!fb.open(pb)) { fprintf(stderr, "Cannot open %s\n", pb); return; }
    printf("=== Patch Analysis @ offset 0x%zX ===\n\n", offset);

    size_t window = 32;
    size_t start  = (offset >= 4) ? offset - 4 : 0;
    size_t end    = std::min({start + window, fa.size, fb.size});

    printf("  Offset      Old   New\n");
    printf("  %s\n", std::string(30, '-').c_str());
    for (size_t i = start; i < end; ++i) {
        bool diff = (fa.base[i] != fb.base[i]);
        printf("  0x%06zX    %02X    %02X%s\n", i, fa.base[i], fb.base[i],
               diff ? "  <--" : "");
    }

    // Pattern detection
    printf("\nPattern hints at offset 0x%zX:\n", offset);
    if (fb.size > offset + 1) {
        uint8_t b0 = fb.base[offset], b1 = fb.base[offset+1];
        if (b0 == 0xE9) printf("  -> JMP rel32 (hook/patch)\n");
        if (b0 == 0xFF && b1 == 0x25) printf("  -> JMP [mem] (indirect hook)\n");
        if (b0 == 0x90) printf("  -> NOP sled\n");
        if (b0 == 0xCC) printf("  -> INT3 breakpoint\n");
        if (b0 == 0x48 && b1 == 0xB8) printf("  -> MOV RAX, imm64 (likely shellcode stub)\n");
    }
}

// ─── summary <old> <new> ─────────────────────────────────────────────────────

static void cmd_summary(const char* pa, const char* pb) {
    FileMap fa, fb;
    if (!fa.open(pa)) { fprintf(stderr, "Cannot open %s\n", pa); return; }
    if (!fb.open(pb)) { fprintf(stderr, "Cannot open %s\n", pb); return; }

    size_t diff_count = 0;
    size_t minlen = std::min(fa.size, fb.size);
    for (size_t i = 0; i < minlen; ++i)
        if (fa.base[i] != fb.base[i]) ++diff_count;

    printf("=== Diff Summary ===\n");
    printf("  Old: %s  (%zu bytes)\n", pa, fa.size);
    printf("  New: %s  (%zu bytes)\n", pb, fb.size);
    printf("  Size delta:     %+zd\n",  (ssize_t)fb.size - (ssize_t)fa.size);
    printf("  Differing bytes (first %zu): %zu\n", minlen, diff_count);
    printf("  Change ratio:   %.2f%%\n",
           minlen ? (double)diff_count * 100.0 / minlen : 0.0);
    if (fa.is_pe() && fb.is_pe()) {
        printf("\n  Run 'sections' and 'functions' for PE-level breakdown.\n");
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  patch_differ.exe bytes    <old> <new>\n"
               "  patch_differ.exe sections <old> <new>\n"
               "  patch_differ.exe functions <old> <new>\n"
               "  patch_differ.exe analyze  <old> <new> [offset_hex]\n"
               "  patch_differ.exe summary  <old> <new>\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "bytes"     && argc >= 4) cmd_bytes(argv[2], argv[3]);
    else if (cmd == "sections"  && argc >= 4) cmd_sections(argv[2], argv[3]);
    else if (cmd == "functions" && argc >= 4) cmd_functions(argv[2], argv[3]);
    else if (cmd == "analyze"   && argc >= 4) {
        size_t off = (argc >= 5) ? (size_t)strtoul(argv[4], nullptr, 16) : 0;
        cmd_analyze(argv[2], argv[3], off);
    }
    else if (cmd == "summary"   && argc >= 4) cmd_summary(argv[2], argv[3]);
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
