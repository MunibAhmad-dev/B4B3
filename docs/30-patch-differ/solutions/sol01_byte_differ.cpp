/*
  Solution 01 — Byte-Level Binary Diff (complete)

  Compile:
    g++ -std=c++17 -Wall -o sol01.exe sol01_byte_differ.cpp
  Usage:
    sol01.exe old.exe new.exe
*/

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstdio>

static const size_t CONTEXT_DISTANCE = 4;  // merge hunks within 4 bytes of each other
static const size_t CONTEXT_PRINT    = 4;  // context bytes shown around each hunk

struct DiffHunk {
    size_t          offset;
    std::vector<BYTE> oldBytes;
    std::vector<BYTE> newBytes;
};

// ---------- readFile ----------
std::vector<BYTE> readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        printf("[-] Cannot open: %s\n", path.c_str());
        return {};
    }
    return { std::istreambuf_iterator<char>(f),
             std::istreambuf_iterator<char>() };
}

// ---------- byteDiff ----------
std::vector<DiffHunk> byteDiff(const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    std::vector<DiffHunk> raw;
    size_t n = std::min(a.size(), b.size());

    // --- Pass 1: collect raw (non-merged) hunks ---
    DiffHunk cur;
    bool inHunk = false;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            if (!inHunk) {
                cur = { i, {}, {} };
                inHunk = true;
            }
            cur.oldBytes.push_back(a[i]);
            cur.newBytes.push_back(b[i]);
        } else {
            if (inHunk) {
                raw.push_back(cur);
                inHunk = false;
            }
        }
    }
    if (inHunk) raw.push_back(cur);

    // Handle size difference at end
    if (a.size() != b.size()) {
        DiffHunk h;
        h.offset = n;
        for (size_t i = n; i < a.size(); i++) h.oldBytes.push_back(a[i]);
        for (size_t i = n; i < b.size(); i++) h.newBytes.push_back(b[i]);
        if (!h.oldBytes.empty() || !h.newBytes.empty())
            raw.push_back(h);
    }

    if (raw.empty()) return {};

    // --- Pass 2: merge adjacent hunks within CONTEXT_DISTANCE bytes ---
    std::vector<DiffHunk> merged;
    merged.push_back(raw[0]);

    for (size_t i = 1; i < raw.size(); i++) {
        DiffHunk& prev = merged.back();
        DiffHunk& next = raw[i];

        size_t prevEnd = prev.offset + prev.oldBytes.size();
        size_t gap     = next.offset - prevEnd;  // gap of identical bytes between them

        if (gap <= CONTEXT_DISTANCE) {
            // Merge: extend prev to cover the gap + next hunk
            for (size_t j = prevEnd; j < next.offset; j++) {
                prev.oldBytes.push_back(a[j]);
                prev.newBytes.push_back(b[j]);
            }
            for (size_t j = 0; j < next.oldBytes.size(); j++) {
                prev.oldBytes.push_back(next.oldBytes[j]);
                prev.newBytes.push_back(next.newBytes[j]);
            }
        } else {
            merged.push_back(next);
        }
    }

    return merged;
}

// ---------- printDiff ----------
void printDiff(const std::vector<DiffHunk>& hunks,
               const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    if (hunks.empty()) {
        printf("[=] Files are identical in the compared region\n");
        return;
    }

    for (const auto& h : hunks) {
        printf("@@ 0x%08zX  -%zu +%zu @@\n",
               h.offset, h.oldBytes.size(), h.newBytes.size());

        // Context before
        size_t ctxStart = (h.offset >= CONTEXT_PRINT) ? h.offset - CONTEXT_PRINT : 0;
        if (ctxStart < h.offset) {
            printf("   ctx: ");
            for (size_t i = ctxStart; i < h.offset && i < a.size(); i++)
                printf("%02X ", a[i]);
            printf("\n");
        }

        // Old (removed) bytes
        printf("  old: ");
        for (auto byte : h.oldBytes) printf("%02X ", byte);
        printf("\n");

        // New (added) bytes
        printf("  new: ");
        for (auto byte : h.newBytes) printf("%02X ", byte);
        printf("\n");

        // Context after
        size_t afterStart = h.offset + h.oldBytes.size();
        size_t afterEnd   = std::min(afterStart + CONTEXT_PRINT, a.size());
        if (afterStart < afterEnd) {
            printf("   ctx: ");
            for (size_t i = afterStart; i < afterEnd; i++)
                printf("%02X ", a[i]);
            printf("\n");
        }
        printf("\n");
    }
    (void)b;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <old_file> <new_file>\n", argv[0]);
        return 1;
    }

    auto a = readFile(argv[1]);
    auto b = readFile(argv[2]);

    if (a.empty() || b.empty()) {
        printf("[-] Could not read one or both files\n");
        return 1;
    }

    printf("[*] Old: %s (%zu bytes)\n", argv[1], a.size());
    printf("[*] New: %s (%zu bytes)\n", argv[2], b.size());
    if (a.size() != b.size())
        printf("[!] Size delta: %+zd bytes\n",
               (ptrdiff_t)b.size() - (ptrdiff_t)a.size());

    auto hunks = byteDiff(a, b);

    printDiff(hunks, a, b);

    size_t totalChanged = 0;
    for (const auto& h : hunks) totalChanged += h.oldBytes.size();
    printf("[*] Summary: %zu hunks, %zu changed bytes (%.2f%%)\n",
           hunks.size(), totalChanged,
           a.size() ? 100.0 * totalChanged / a.size() : 0.0);
    return 0;
}
