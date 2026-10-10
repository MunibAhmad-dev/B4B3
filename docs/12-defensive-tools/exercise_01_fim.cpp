// exercise_01_fim.cpp
// Module 12 Exercise 01 — File Integrity Monitor
// Compile: g++ -std=c++17 -Wall -o ex01.exe exercise_01_fim.cpp -ladvapi32
//
// Goal: Learn to detect file-system changes by comparing CRC32 hashes over time.
// This is the most fundamental building block of host-based intrusion detection.
//
// What you will practice:
//   - Walking a directory tree with FindFirstFileEx / FindNextFile
//   - Computing a fast file hash (CRC32 using the standard 0xEDB88320 polynomial)
//   - Storing state in a std::map<path, hash> baseline
//   - Diffing two snapshots to find NEW / MODIFIED / DELETED files

#include <windows.h>
#include <cstdint>
#include <string>
#include <map>
#include <iostream>
#include <iomanip>

// ============================================================= CRC32 table ===

static uint32_t g_crc_table[256];
static bool     g_crc_ready = false;

static void build_crc_table() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
    g_crc_ready = true;
}

// Returns the CRC32 of the named file, or 0xFFFFFFFF on any error.
static uint32_t file_crc32(const std::string& path) {
    if (!g_crc_ready) build_crc_table();

    HANDLE hf = CreateFileA(
        path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return 0xFFFFFFFF;

    uint32_t crc = 0xFFFFFFFFUL;
    BYTE     buf[65536];
    DWORD    got;
    while (ReadFile(hf, buf, sizeof buf, &got, nullptr) && got)
        for (DWORD i = 0; i < got; ++i)
            crc = (crc >> 8) ^ g_crc_table[(crc ^ buf[i]) & 0xFF];

    CloseHandle(hf);
    return crc ^ 0xFFFFFFFFUL;
}

// ============================================================= File map type =

// Maps absolute file path to its CRC32 hash.
using FileMap = std::map<std::string, uint32_t>;

// ================================================== Recursive directory walk =

// Fills `out` with (path, crc32) pairs for every regular file under `dir`.
// Skips symlinks / reparse points to avoid infinite recursion.
static void scan_dir(const std::string& dir, FileMap& out) {
    std::string pattern = dir + "\\*";
    WIN32_FIND_DATA fd;
    HANDLE h = FindFirstFileExA(
        pattern.c_str(), FindExInfoBasic, &fd,
        FindExSearchNameMatch, nullptr,
        FIND_FIRST_EX_LARGE_FETCH);

    if (h == INVALID_HANDLE_VALUE) {
        // Access denied or empty directory — note and continue
        if (GetLastError() == ERROR_ACCESS_DENIED)
            std::cerr << "[WARN] Access denied: " << dir << "\n";
        return;
    }

    do {
        std::string name(fd.cFileName);
        if (name == "." || name == "..") continue;

        std::string full = dir + "\\" + name;
        DWORD attrs      = fd.dwFileAttributes;

        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) continue;   // skip symlinks

        if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
            scan_dir(full, out);                               // recurse
        } else {
            out[full] = file_crc32(full);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

// ======================================================== Diff and print ====

// Compares baseline vs current snapshot and prints changes.
// Returns the number of changes found.
static int compare_maps(const FileMap& baseline, const FileMap& current) {
    int changes = 0;

    // Look for NEW and MODIFIED files
    for (const auto& [path, hash] : current) {
        auto it = baseline.find(path);
        if (it == baseline.end()) {
            std::cout << "  [NEW]      " << path << "\n";
            ++changes;
        } else if (it->second != hash && hash != 0xFFFFFFFF) {
            std::cout << "  [MODIFIED] " << path << "\n";
            ++changes;
        }
    }

    // Look for DELETED files
    for (const auto& [path, hash] : baseline) {
        if (current.find(path) == current.end()) {
            std::cout << "  [DELETED]  " << path << "\n";
            ++changes;
        }
    }
    return changes;
}

// =========================================================== Timestamp ======

static std::string now_str() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d",
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: ex01.exe <directory> <interval_seconds>\n"
                     "  directory        -- root path to monitor\n"
                     "  interval_seconds -- seconds between re-scans\n";
        return 1;
    }

    std::string dir        = argv[1];
    int         interval_s = std::stoi(argv[2]);

    std::cout << "[FIM] Building baseline for: " << dir << "\n";

    FileMap baseline;
    scan_dir(dir, baseline);

    std::cout << "[FIM] Baseline complete: " << baseline.size() << " file(s).\n";
    std::cout << "[FIM] Scanning every " << interval_s << "s. Ctrl+C to stop.\n\n";

    for (;;) {
        Sleep(static_cast<DWORD>(interval_s) * 1000);

        FileMap current;
        scan_dir(dir, current);

        std::cout << "[" << now_str() << "] Re-scan complete ("
                  << current.size() << " files)\n";

        int changes = compare_maps(baseline, current);
        if (changes == 0)
            std::cout << "  No changes.\n";
        else
            std::cout << "  " << changes << " change(s) found.\n";

        // Roll the baseline forward so the next scan diffs against *this* state.
        baseline = current;
    }
}
