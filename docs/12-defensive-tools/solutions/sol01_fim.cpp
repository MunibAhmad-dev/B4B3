// solutions/sol01_fim.cpp
// Module 12 Solution 01 — File Integrity Monitor (complete)
// Compile: g++ -std=c++17 -Wall -o sol01.exe sol01_fim.cpp -ladvapi32 -lbcrypt
//
// Modes:
//   sol01.exe baseline <dir> <baseline_file>   -- build and save SHA-256 baseline
//   sol01.exe check    <dir> <baseline_file>   -- compare dir against saved baseline
//   sol01.exe watch    <dir> <interval_sec>    -- continuous re-scan with timestamps
//
// Features:
//   - SHA-256 via Windows CNG (BCrypt API)
//   - Recursive walk via FindFirstFileExW (Unicode-safe)
//   - Skips symlinks / reparse points
//   - Notes access-denied paths and continues
//   - Baseline stored as TSV: hash<tab>utf8_path

#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <stdexcept>

// ================================================================ CNG SHA-256

// Computes SHA-256 of the file at `path` (wide string).
// Returns hex string on success, or a tag like "<ACCESS_DENIED>" on failure.
static std::string sha256_file(const std::wstring& path) {
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return "<ALG_OPEN_FAILED>";

    // Query the hash output length (32 bytes for SHA-256)
    DWORD hashLen = 0, cbResult = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hashLen),
                      sizeof hashLen, &cbResult, 0);
    std::vector<BYTE> hashBuf(hashLen, 0);

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "<HASH_CREATE_FAILED>";
    }

    HANDLE hFile = CreateFileW(
        path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return (err == ERROR_ACCESS_DENIED) ? "<ACCESS_DENIED>" : "<OPEN_FAILED>";
    }

    BYTE buf[65536];
    DWORD got;
    bool ok = true;
    while (ok && ReadFile(hFile, buf, sizeof buf, &got, nullptr) && got)
        ok = (BCryptHashData(hHash, buf, got, 0) == 0);

    CloseHandle(hFile);

    if (ok)
        BCryptFinishHash(hHash, hashBuf.data(), hashLen, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!ok) return "<HASH_ERROR>";

    std::ostringstream oss;
    for (BYTE b : hashBuf)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

// ========================================================= Encoding helpers

static std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

static std::string to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                        s.data(), n, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

// ============================================================ Directory walk

// Maps absolute path (wide) -> SHA-256 hex string (or error tag).
using FileMap = std::map<std::wstring, std::string>;

static void scan_dir(const std::wstring& dir, FileMap& out) {
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(
        pattern.c_str(), FindExInfoBasic, &fd,
        FindExSearchNameMatch, nullptr,
        FIND_FIRST_EX_LARGE_FETCH);

    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_ACCESS_DENIED)
            std::wcerr << L"[WARN] Access denied: " << dir << L"\n";
        return;
    }

    do {
        std::wstring name(fd.cFileName);
        if (name == L"." || name == L"..") continue;

        std::wstring full  = dir + L"\\" + name;
        DWORD        attrs = fd.dwFileAttributes;

        // Skip symlinks and junction points
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        if (attrs & FILE_ATTRIBUTE_DIRECTORY)
            scan_dir(full, out);
        else
            out[full] = sha256_file(full);

    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

// =========================================================== Baseline I/O

static bool save_baseline(const FileMap& fm, const std::string& path) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    for (const auto& [wpath, hash] : fm)
        ofs << hash << "\t" << to_utf8(wpath) << "\n";
    return ofs.good();
}

static FileMap load_baseline(const std::string& path) {
    FileMap fm;
    std::ifstream ifs(path);
    if (!ifs) return fm;
    std::string line;
    while (std::getline(ifs, line)) {
        auto tab = line.find('\t');
        if (tab == std::string::npos) continue;
        std::string  hash  = line.substr(0, tab);
        std::wstring wpath = to_wide(line.substr(tab + 1));
        fm[wpath] = hash;
    }
    return fm;
}

// =========================================================== Diff and print

static int compare_and_print(const FileMap& baseline, const FileMap& current,
                              const std::string& prefix = "") {
    int changes = 0;

    for (const auto& [wpath, hash] : current) {
        if (!hash.empty() && hash[0] == '<') continue;  // skip error entries
        auto it = baseline.find(wpath);
        if (it == baseline.end()) {
            if (!prefix.empty()) std::cout << prefix << " ";
            std::cout << "[NEW]      " << to_utf8(wpath) << "\n";
            ++changes;
        } else if (it->second != hash) {
            if (!prefix.empty()) std::cout << prefix << " ";
            std::cout << "[MODIFIED] " << to_utf8(wpath) << "\n";
            ++changes;
        }
    }

    for (const auto& [wpath, hash] : baseline) {
        if (current.find(wpath) == current.end()) {
            if (!prefix.empty()) std::cout << prefix << " ";
            std::cout << "[DELETED]  " << to_utf8(wpath) << "\n";
            ++changes;
        }
    }
    return changes;
}

static std::string now_str() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[24];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ================================================================ Modes

static int mode_baseline(const std::string& dir, const std::string& outfile) {
    std::cout << "[FIM] Building baseline: " << dir << " -> " << outfile << "\n";
    FileMap fm;
    scan_dir(to_wide(dir), fm);
    std::cout << "[FIM] Scanned " << fm.size() << " file(s).\n";
    if (!save_baseline(fm, outfile)) {
        std::cerr << "[FIM] ERROR: cannot write " << outfile << "\n";
        return 1;
    }
    std::cout << "[FIM] Baseline saved to " << outfile << "\n";
    return 0;
}

static int mode_check(const std::string& dir, const std::string& basefile) {
    FileMap baseline = load_baseline(basefile);
    if (baseline.empty()) {
        std::cerr << "[FIM] ERROR: cannot load baseline from " << basefile << "\n";
        return 1;
    }
    std::cout << "[FIM] Loaded " << baseline.size()
              << " baseline entries from " << basefile << "\n";
    std::cout << "[FIM] Scanning " << dir << "...\n";

    FileMap current;
    scan_dir(to_wide(dir), current);

    int changes = compare_and_print(baseline, current);

    std::cout << "\n[FIM] " << current.size() << " file(s) checked, "
              << changes << " change(s) found.\n";
    return changes ? 2 : 0;
}

static int mode_watch(const std::string& dir, int interval_sec) {
    std::cout << "[FIM] Watch mode: " << dir
              << " (every " << interval_sec << "s). Ctrl+C to stop.\n";
    FileMap prev;
    scan_dir(to_wide(dir), prev);
    std::cout << "[FIM] Baseline: " << prev.size() << " file(s).\n\n";

    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(interval_sec));

        FileMap curr;
        scan_dir(to_wide(dir), curr);

        int changes = compare_and_print(prev, curr, now_str());

        if (changes == 0)
            std::cout << now_str() << " No changes (" << curr.size() << " files)\n";
        else
            std::cout << now_str() << " Total: " << changes << " change(s)\n";

        prev = curr;
    }
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  sol01.exe baseline <dir> <baseline_file>\n"
                  << "  sol01.exe check    <dir> <baseline_file>\n"
                  << "  sol01.exe watch    <dir> <interval_sec>\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "baseline" && argc >= 4)
        return mode_baseline(argv[2], argv[3]);

    if (cmd == "check" && argc >= 4)
        return mode_check(argv[2], argv[3]);

    if (cmd == "watch" && argc >= 4)
        return mode_watch(argv[2], std::stoi(argv[3]));

    std::cerr << "[FIM] Unknown command or missing arguments.\n"
              << "      Run with no arguments for usage.\n";
    return 1;
}
