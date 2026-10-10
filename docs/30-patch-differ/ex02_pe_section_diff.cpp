/*
  Exercise 02 — PE Section-Level Diff
  ---------------------------------------
  A smarter diff works at the PE section level rather than raw bytes.
  This avoids false positives from:
    - PE header timestamp changes (the timestamp field changes every rebuild)
    - Relocation table changes (ASLR base changes)
    - Debug info section changes

  By comparing only .text (code) sections, you focus on actual code changes.

  Tasks:
  1. Implement parseSections(filename) — return a map of {name → raw_bytes}.
  2. Implement sectionDiff(old, newPE) — compare section by section:
       - Sections in old but not new → REMOVED
       - Sections in new but not old → ADDED
       - Sections in both → compare bytes (same as ex01 byteDiff)
  3. Print per-section stats: changed bytes, unchanged bytes, % changed.
  4. For the .text section, print the first 3 hunks in detail.

  BONUS:
  - Account for relocated addresses: before comparing, zero out all
    relocation entries (using the .reloc section's base relocation table)
    so ASLR-induced byte changes don't show up as false diffs.
  - Check the PE header checksum and timestamp fields separately.

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_pe_section_diff.cpp
  Usage:
    ex02.exe old.exe new.exe
*/

#include <windows.h>
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>
#include <algorithm>

// Reuse byteDiff from ex01 (simplified version here)
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
        for (size_t i=n;i<a.size();i++) h.old_.push_back(a[i]);
        for (size_t i=n;i<b.size();i++) h.new_.push_back(b[i]);
        hunks.push_back(h);
    }
    return hunks;
}

// ---------- TODO 1: parseSections ----------
std::map<std::string, std::vector<BYTE>> parseSections(const std::string& path) {
    std::map<std::string, std::vector<BYTE>> result;
    // YOUR CODE HERE:
    // 1. Read file into buffer
    // 2. Parse IMAGE_NT_HEADERS64 via e_lfanew
    // 3. Walk IMAGE_SECTION_HEADER array
    // 4. For each section:
    //    name = std::string((char*)sec->Name, strnlen((char*)sec->Name, 8))
    //    result[name] = vector(buf + sec->PointerToRawData,
    //                          buf + sec->PointerToRawData + sec->SizeOfRawData)
    (void)path;
    return result;
}

// ---------- TODO 2+3: sectionDiff ----------
void sectionDiff(const std::string& pathA, const std::string& pathB) {
    auto secsA = parseSections(pathA);
    auto secsB = parseSections(pathB);

    if (secsA.empty()) { printf("[-] parseSections not implemented\n"); return; }

    printf("%-12s  %8s  %8s  %7s  %s\n", "Section", "OldSize", "NewSize", "Changed", "Status");
    printf("%s\n", std::string(55, '-').c_str());

    // Sections in A
    for (auto& [name, bytesA] : secsA) {
        if (!secsB.count(name)) {
            printf("%-12s  %8zu  %8s  %7s  REMOVED\n",
                   name.c_str(), bytesA.size(), "-", "-");
            continue;
        }
        auto& bytesB = secsB[name];
        auto hunks = byteDiff(bytesA, bytesB);
        size_t changed = 0;
        for (auto& h : hunks) changed += h.old_.size();
        double pct = bytesA.size() ? 100.0 * changed / bytesA.size() : 0;
        printf("%-12s  %8zu  %8zu  %6.2f%%  %s\n",
               name.c_str(), bytesA.size(), bytesB.size(), pct,
               changed == 0 ? "SAME" : "CHANGED");

        // YOUR CODE HERE: for .text section, print first 3 hunks
        if (name == ".text" && !hunks.empty()) {
            printf("  [.text detail — first %zu of %zu hunks]\n",
                   std::min(hunks.size(), (size_t)3), hunks.size());
            for (size_t i = 0; i < std::min(hunks.size(), (size_t)3); i++) {
                auto& h = hunks[i];
                printf("  @@ 0x%08zX  -%zu +%zu\n", h.offset,
                       h.old_.size(), h.new_.size());
                printf("  old: "); for (auto b : h.old_) printf("%02X ", b); printf("\n");
                printf("  new: "); for (auto b : h.new_) printf("%02X ", b); printf("\n");
            }
        }
    }

    // Sections only in B (added)
    for (auto& [name, _] : secsB)
        if (!secsA.count(name))
            printf("%-12s  %8s  %8zu  %7s  ADDED\n",
                   name.c_str(), "-", _.size(), "-");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <old.exe> <new.exe>\n", argv[0]);
        return 1;
    }
    printf("[*] Section diff: %s → %s\n\n", argv[1], argv[2]);
    sectionDiff(argv[1], argv[2]);
    return 0;
}
