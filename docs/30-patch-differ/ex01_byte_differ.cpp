/*
  Exercise 01 — Byte-Level Binary Diff
  ----------------------------------------
  Diff two binary files at the raw byte level and display the changed
  regions as "hunks" — the same format used by text diff tools but
  applied to binary files.

  Output format per hunk:
    @@ 0x00041A20 +3 bytes @@
    old: E8 12 34 56
    new: E8 78 9A BC

  Tasks:
  1. Implement readFile(path) → returns file contents as vector<BYTE>.
  2. Implement byteDiff(a, b) → returns vector<DiffHunk>.
     Each DiffHunk covers a contiguous run of changed bytes.
     Merge hunks that are within CONTEXT_DISTANCE bytes of each other.
  3. Implement printDiff(hunks, context, a, b) — print each hunk with
     CONTEXT bytes of unchanged bytes before and after for readability.
  4. Print a summary: total changed bytes, number of hunks, changed %.

  CONTEXT_DISTANCE: 4 (merge hunks within 4 bytes of each other)
  CONTEXT_PRINT:    4 (show 4 bytes of context around each hunk)

  BONUS:
  - Color output: red for old bytes, green for new bytes.
  - Also show the ASCII printable interpretation of each byte.
  - Accept --offset flag to start diff at a given file offset.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_byte_differ.cpp
  Usage:
    ex01.exe old.exe new.exe
    ex01.exe notepad_win10.exe notepad_win11.exe
*/

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstdio>

static const size_t CONTEXT_DISTANCE = 4;
static const size_t CONTEXT_PRINT    = 4;

struct DiffHunk {
    size_t offset;
    std::vector<BYTE> oldBytes;
    std::vector<BYTE> newBytes;
};

// ---------- TODO 1: readFile ----------
std::vector<BYTE> readFile(const std::string& path) {
    // YOUR CODE HERE:
    // std::ifstream f(path, std::ios::binary);
    // if (!f) { printf("[-] Cannot open %s\n", path.c_str()); return {}; }
    // return { std::istreambuf_iterator<char>(f), {} };
    (void)path;
    return {};
}

// ---------- TODO 2: byteDiff ----------
std::vector<DiffHunk> byteDiff(const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    std::vector<DiffHunk> hunks;
    size_t n = std::min(a.size(), b.size());

    // YOUR CODE HERE (see theory.md section 4):
    // 1. Walk byte by byte, build raw hunks where a[i] != b[i]
    // 2. Merge adjacent hunks that are within CONTEXT_DISTANCE of each other
    //    (merge: if next_hunk.offset - (prev_hunk.offset + prev_hunk.size) <= CONTEXT_DISTANCE)
    // 3. Handle size difference at end

    (void)n;
    return hunks;
}

// ---------- TODO 3: printDiff ----------
void printDiff(const std::vector<DiffHunk>& hunks,
               const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    if (hunks.empty()) { printf("[=] Files are identical\n"); return; }

    for (auto& h : hunks) {
        // Print header
        printf("@@ 0x%08zX  -%zu +%zu @@\n",
               h.offset, h.oldBytes.size(), h.newBytes.size());

        // Print context before
        size_t ctxStart = h.offset >= CONTEXT_PRINT ? h.offset - CONTEXT_PRINT : 0;
        if (ctxStart < h.offset) {
            printf("   ctx: ");
            for (size_t i = ctxStart; i < h.offset && i < a.size(); i++)
                printf("%02X ", a[i]);
            printf("\n");
        }

        // YOUR CODE HERE: print old bytes (red) and new bytes (green)
        printf("  old: ");
        for (auto b2 : h.oldBytes) printf("%02X ", b2);
        printf("\n");
        printf("  new: ");
        for (auto b2 : h.newBytes) printf("%02X ", b2);
        printf("\n\n");
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
        printf("[-] readFile not implemented or files empty\n");
        return 1;
    }

    printf("[*] Old: %s (%zu bytes)\n", argv[1], a.size());
    printf("[*] New: %s (%zu bytes)\n", argv[2], b.size());
    if (a.size() != b.size())
        printf("[!] File sizes differ: %+zd bytes\n", (ssize_t)b.size() - (ssize_t)a.size());

    auto hunks = byteDiff(a, b);
    if (hunks.empty() && !a.empty()) {
        printf("[-] byteDiff not implemented\n"); return 1;
    }

    printDiff(hunks, a, b);

    size_t totalChanged = 0;
    for (auto& h : hunks) totalChanged += h.oldBytes.size();
    printf("[*] Summary: %zu hunks, %zu changed bytes (%.2f%%)\n",
           hunks.size(), totalChanged,
           a.size() ? 100.0 * totalChanged / a.size() : 0.0);
    return 0;
}
