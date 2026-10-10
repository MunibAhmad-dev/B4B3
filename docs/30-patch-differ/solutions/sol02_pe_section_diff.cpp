/*
  Solution 02 — PE Section-Level Diff (complete)

  Compares two PE files section-by-section, focusing on .text for code changes.

  Compile:
    g++ -std=c++17 -Wall -o sol02.exe sol02_pe_section_diff.cpp
  Usage:
    sol02.exe old.exe new.exe
*/

#include <windows.h>
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cstdio>
#include <cstring>

// ---------- Reuse byteDiff from ex01 (minimal version) ----------
struct DiffHunk { size_t offset; std::vector<BYTE> old_, new_; };

std::vector<DiffHunk> byteDiff(const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    std::vector<DiffHunk> hunks;
    size_t n = std::min(a.size(), b.size());
    DiffHunk cur; bool inHunk = false;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            if (!inHunk) { cur = {i,{},{}}; inHunk = true; }
            cur.old_.push_back(a[i]); cur.new_.push_back(b[i]);
        } else {
            if (inHunk) { hunks.push_back(cur); inHunk = false; }
        }
    }
    if (inHunk) hunks.push_back(cur);
    if (a.size() != b.size()) {
        DiffHunk h; h.offset = n;
        for (size_t i = n; i < a.size(); i++) h.old_.push_back(a[i]);
        for (size_t i = n; i < b.size(); i++) h.new_.push_back(b[i]);
        if (!h.old_.empty() || !h.new_.empty()) hunks.push_back(h);
    }
    return hunks;
}

// ---------- parseSections ----------
// Returns a map of { section_name -> raw_bytes }.
// Supports both PE32 and PE32+ (64-bit) images.
std::map<std::string, std::vector<BYTE>> parseSections(const std::string& path) {
    std::map<std::string, std::vector<BYTE>> result;

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        printf("[-] Cannot open: %s\n", path.c_str());
        return result;
    }
    std::vector<BYTE> buf(std::istreambuf_iterator<char>(f),
                          std::istreambuf_iterator<char>());
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return result;

    // DOS header
    auto* dos = (IMAGE_DOS_HEADER*)buf.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a valid PE: %s\n", path.c_str());
        return result;
    }

    // NT headers (use the 32-bit struct first to read the magic field)
    LONG ntOff = dos->e_lfanew;
    if ((size_t)ntOff + sizeof(IMAGE_NT_HEADERS64) > buf.size()) return result;

    auto* ntBase = (IMAGE_NT_HEADERS*)( buf.data() + ntOff );
    if (ntBase->Signature != IMAGE_NT_SIGNATURE) return result;

    WORD  numSections = 0;
    DWORD sectionTableOffset = 0;

    if (ntBase->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* nt64 = (IMAGE_NT_HEADERS64*)(buf.data() + ntOff);
        numSections       = nt64->FileHeader.NumberOfSections;
        sectionTableOffset = ntOff
            + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
            + nt64->FileHeader.SizeOfOptionalHeader;
    } else {
        auto* nt32 = (IMAGE_NT_HEADERS32*)(buf.data() + ntOff);
        numSections       = nt32->FileHeader.NumberOfSections;
        sectionTableOffset = ntOff
            + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)
            + nt32->FileHeader.SizeOfOptionalHeader;
    }

    if (sectionTableOffset + numSections * sizeof(IMAGE_SECTION_HEADER) > buf.size())
        return result;

    auto* sections = (IMAGE_SECTION_HEADER*)(buf.data() + sectionTableOffset);

    for (WORD i = 0; i < numSections; i++) {
        // Section name is up to 8 bytes, not necessarily null-terminated
        std::string name(reinterpret_cast<const char*>(sections[i].Name), 8);
        // Trim trailing nulls
        name.erase(std::find(name.begin(), name.end(), '\0'), name.end());

        DWORD rawOff  = sections[i].PointerToRawData;
        DWORD rawSize = sections[i].SizeOfRawData;

        if (rawOff == 0 || rawSize == 0) {
            result[name] = {};
            continue;
        }
        if ((size_t)rawOff + rawSize > buf.size()) {
            rawSize = (DWORD)(buf.size() - rawOff);
        }

        result[name] = std::vector<BYTE>(buf.begin() + rawOff,
                                          buf.begin() + rawOff + rawSize);
    }

    return result;
}

// ---------- sectionDiff ----------
void sectionDiff(const std::string& pathA, const std::string& pathB) {
    auto secsA = parseSections(pathA);
    auto secsB = parseSections(pathB);

    if (secsA.empty()) {
        printf("[-] parseSections returned no sections for: %s\n", pathA.c_str());
        return;
    }

    printf("%-12s  %8s  %8s  %7s  %s\n",
           "Section", "OldSize", "NewSize", "Changed", "Status");
    printf("%s\n", std::string(55, '-').c_str());

    // Sections present in old file
    for (auto& [name, bytesA] : secsA) {
        if (!secsB.count(name)) {
            printf("%-12s  %8zu  %8s  %7s  REMOVED\n",
                   name.c_str(), bytesA.size(), "-", "-");
            continue;
        }
        auto& bytesB = secsB[name];
        auto  hunks  = byteDiff(bytesA, bytesB);

        size_t changed = 0;
        for (auto& h : hunks) changed += h.old_.size();
        double pct = bytesA.size() ? 100.0 * changed / bytesA.size() : 0.0;

        printf("%-12s  %8zu  %8zu  %6.2f%%  %s\n",
               name.c_str(), bytesA.size(), bytesB.size(), pct,
               changed == 0 ? "SAME" : "CHANGED");

        // For .text section, print first 3 hunks in detail
        if (name == ".text" && !hunks.empty()) {
            size_t show = std::min(hunks.size(), (size_t)3);
            printf("  [.text detail — first %zu of %zu hunks]\n",
                   show, hunks.size());
            for (size_t i = 0; i < show; i++) {
                auto& h = hunks[i];
                printf("  @@ 0x%08zX  -%zu +%zu\n",
                       h.offset, h.old_.size(), h.new_.size());
                printf("  old: ");
                for (auto by : h.old_) printf("%02X ", by);
                printf("\n  new: ");
                for (auto by : h.new_) printf("%02X ", by);
                printf("\n");
            }
        }
    }

    // Sections only in new file (added)
    for (auto& [name, bytes] : secsB) {
        if (!secsA.count(name))
            printf("%-12s  %8s  %8zu  %7s  ADDED\n",
                   name.c_str(), "-", bytes.size(), "-");
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <old.exe> <new.exe>\n", argv[0]);
        return 1;
    }
    printf("[*] PE section diff: %s -> %s\n\n", argv[1], argv[2]);
    sectionDiff(argv[1], argv[2]);
    return 0;
}
