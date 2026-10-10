/*
  Exercise 02 — File Enumerator by Extension
  --------------------------------------------
  Before ransomware can encrypt files, it must enumerate them.
  This exercise builds the enumeration engine.

  Tasks:
  1. Implement enumerateFiles() — recursively enumerate all files under rootPath
     whose extension matches one in targetExts. Use std::filesystem.

  2. Implement getFileSizeHuman() — return a human-readable file size string
     (e.g. "1.2 MB", "345 KB", "12 B").

  3. In main():
     - Enumerate C:\RansomwareSimTest\ (create it first with a few test files)
     - Print a table: path | size | extension
     - Print totals: file count, total bytes, breakdown by extension

  Expected output (example):
    C:\RansomwareSimTest\docs\contract.docx     45.2 KB   .docx
    C:\RansomwareSimTest\docs\budget.xlsx       12.1 KB   .xlsx
    C:\RansomwareSimTest\photos\family.jpg      2.3 MB    .jpg
    ---
    Total: 3 files, 2.4 MB
    By extension: .docx=1  .xlsx=1  .jpg=1

  BONUS:
  - Add a dry-run mode that logs what WOULD be encrypted without touching files.
  - Sort results by file size descending.
  - Skip files that are open/locked (attempt exclusive open — if it fails, skip).

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_file_enumerator.cpp
*/

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

struct FileEntry {
    fs::path    path;
    uintmax_t   size;
    std::string ext;
};

// Well-known file types ransomware typically targets
const std::vector<std::string> TARGET_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".txt", ".csv", ".jpg", ".jpeg", ".png",
    ".bmp", ".mp4", ".zip", ".7z", ".rar", ".sql",
    ".mdb", ".accdb", ".pst", ".ost"
};

// TODO: Implement this.
// Recursively enumerate all regular files under rootPath whose extension
// (case-insensitive) appears in targetExts.
// Return vector of FileEntry structs sorted by path.
std::vector<FileEntry> enumerateFiles(const std::string& rootPath,
                                       const std::vector<std::string>& targetExts) {
    // YOUR CODE HERE
    return {};
}

// TODO: Return a human-readable file size string.
// Examples: 0 → "0 B", 512 → "512 B", 2048 → "2.0 KB", 1572864 → "1.5 MB"
std::string fileSizeHuman(uintmax_t bytes) {
    // YOUR CODE HERE
    return std::to_string(bytes) + " B";
}

int main() {
    // Ensure test directory exists (create it manually with some files first)
    const std::string TEST_DIR = "C:\\RansomwareSimTest";

    // Safety: only operate on the designated test directory
    if (!fs::exists(TEST_DIR)) {
        printf("[-] Test directory not found: %s\n", TEST_DIR.c_str());
        printf("    Create it first and add some test files.\n");
        return 1;
    }

    // TODO: Call enumerateFiles() and print the results table.
    // YOUR CODE HERE

    printf("[TASK] Implement enumerateFiles() and fileSizeHuman() above.\n");
    return 0;
}
