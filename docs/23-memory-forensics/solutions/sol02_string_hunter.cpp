/*
  Solution 02 — In-Memory String Hunter (Complete)
  --------------------------------------------------
  Scans all committed memory regions of a running process and extracts
  interesting strings: URLs, IPs, paths, registry keys, passwords, etc.

  Compile:
    g++ -std=c++17 -Wall -o sol02.exe sol02_string_hunter.cpp
    cl  /std:c++17 sol02_string_hunter.cpp /Fe:sol02.exe

  Usage:
    sol02.exe <PID>
    sol02.exe 1234
    sol02.exe 1234 6
    sol02.exe 1234 6 --keyword password
*/

#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <cstdio>
#include <cstring>
#include <algorithm>

static int g_minLen = 5;


// =========================================================
// FoundString
// =========================================================
struct FoundString {
    std::string value;
    bool        isWide;
    LPVOID      regionBase;
    size_t      offsetInRegion;
};


// =========================================================
// isInteresting — URL/IP/path/keyword heuristics
// =========================================================
bool isInteresting(const std::string& s) {
    // Protocol prefixes
    if (s.find("http://")  != std::string::npos) return true;
    if (s.find("https://") != std::string::npos) return true;
    if (s.find("ftp://")   != std::string::npos) return true;

    // Registry
    if (s.find("HKEY_")    != std::string::npos) return true;
    if (s.find("HKLM\\")   != std::string::npos) return true;
    if (s.find("HKCU\\")   != std::string::npos) return true;

    // Named objects (mutexes, events)
    if (s.find("Global\\") != std::string::npos) return true;

    // Executable/library filenames
    if (s.find(".exe")     != std::string::npos) return true;
    if (s.find(".dll")     != std::string::npos) return true;
    if (s.find(".bat")     != std::string::npos) return true;
    if (s.find(".ps1")     != std::string::npos) return true;

    // Credentials
    if (s.find("password") != std::string::npos) return true;
    if (s.find("Password") != std::string::npos) return true;
    if (s.find("passwd")   != std::string::npos) return true;
    if (s.find("token")    != std::string::npos) return true;
    if (s.find("secret")   != std::string::npos) return true;
    if (s.find("apikey")   != std::string::npos) return true;

    // UNC paths
    if (s.find("\\\\")     != std::string::npos) return true;

    // cmd.exe / powershell invocations
    if (s.find("cmd.exe")  != std::string::npos) return true;
    if (s.find("powershell")!= std::string::npos) return true;

    // IP-address heuristic: at least 3 dots, all digits + dots
    {
        int  dots        = 0;
        bool allDigDots  = !s.empty();
        for (char c : s) {
            if (c == '.') dots++;
            else if (c < '0' || c > '9') { allDigDots = false; break; }
        }
        if (allDigDots && dots == 3 && s.size() >= 7) return true;
    }

    return false;
}


// =========================================================
// scanRegion — extract ASCII + UTF-16LE strings from a buffer
//   Reads from hProcess at [base, base+size).
//   Returns all interesting strings found.
// =========================================================
std::vector<FoundString> scanRegion(HANDLE  hProcess,
                                    LPVOID  base,
                                    SIZE_T  regionSize) {
    std::vector<FoundString> found;

    // Read the region in chunks to limit peak memory
    static const SIZE_T CHUNK = 1024 * 1024;  // 1 MB per read
    std::vector<BYTE>   buf;

    SIZE_T offset = 0;
    while (offset < regionSize) {
        SIZE_T toRead = std::min(CHUNK, regionSize - offset);
        buf.resize(toRead);

        SIZE_T bytesRead = 0;
        LPVOID src = (LPBYTE)base + offset;
        if (!ReadProcessMemory(hProcess, src, buf.data(), toRead, &bytesRead)
            || bytesRead == 0) {
            offset += toRead;
            continue;
        }

        const BYTE* data = buf.data();
        SIZE_T size = bytesRead;

        // ---- ASCII ----
        {
            size_t runStart = SIZE_MAX;
            for (size_t i = 0; i <= size; i++) {
                bool printable = (i < size && data[i] >= 0x20 && data[i] <= 0x7E);
                if (printable) {
                    if (runStart == SIZE_MAX) runStart = i;
                } else {
                    if (runStart != SIZE_MAX) {
                        size_t len = i - runStart;
                        if ((int)len >= g_minLen) {
                            FoundString fs;
                            fs.value          = std::string((const char*)data + runStart, len);
                            fs.isWide         = false;
                            fs.regionBase     = base;
                            fs.offsetInRegion = offset + runStart;
                            found.push_back(std::move(fs));
                        }
                        runStart = SIZE_MAX;
                    }
                }
            }
        }

        // ---- UTF-16LE ----
        {
            size_t runStart = SIZE_MAX;
            for (size_t i = 0; i + 1 < size; i += 2) {
                bool wideChar = (data[i + 1] == 0x00 &&
                                 data[i] >= 0x20 && data[i] <= 0x7E);
                if (wideChar) {
                    if (runStart == SIZE_MAX) runStart = i;
                } else {
                    if (runStart != SIZE_MAX) {
                        size_t chars = (i - runStart) / 2;
                        if ((int)chars >= g_minLen) {
                            std::string s;
                            s.reserve(chars);
                            for (size_t j = runStart; j < i; j += 2)
                                s += (char)data[j];

                            FoundString fs;
                            fs.value          = std::move(s);
                            fs.isWide         = true;
                            fs.regionBase     = base;
                            fs.offsetInRegion = offset + runStart;
                            found.push_back(std::move(fs));
                        }
                        runStart = SIZE_MAX;
                    }
                }
            }
        }

        offset += bytesRead;
    }

    return found;
}


// =========================================================
// huntStrings — enumerate all committed regions and scan each
// =========================================================
std::vector<FoundString> huntStrings(DWORD pid) {
    std::vector<FoundString> all;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return all;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = nullptr;
    SIZE_T regionsScanned = 0, bytesScanned = 0;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            mbi.Protect != 0) {

            auto regionStrings = scanRegion(hProcess,
                                            mbi.BaseAddress,
                                            mbi.RegionSize);
            all.insert(all.end(),
                       regionStrings.begin(),
                       regionStrings.end());
            regionsScanned++;
            bytesScanned += mbi.RegionSize;
        }
        addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProcess);

    printf("[*] Scanned %zu committed regions (%.1f MB)\n",
           regionsScanned, bytesScanned / 1048576.0);
    return all;
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID> [minLen] [--keyword <word>]\n", argv[0]);
        printf("  Example: %s 1234\n", argv[0]);
        printf("  Example: %s 1234 6 --keyword http\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    if (argc > 2 && atoi(argv[2]) > 0)
        g_minLen = atoi(argv[2]);

    const char* keyword = nullptr;
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], "--keyword") == 0) keyword = argv[i + 1];

    printf("[*] Hunting strings in PID %lu  (minLen=%d%s%s)\n\n",
           pid, g_minLen,
           keyword ? "  keyword=" : "",
           keyword ? keyword : "");

    auto strings = huntStrings(pid);
    if (strings.empty()) {
        printf("[-] No strings found\n");
        return 1;
    }

    // Deduplicate and filter
    std::set<std::string> seen;
    int printed = 0;

    for (auto& s : strings) {
        // Keyword filter
        if (keyword && s.value.find(keyword) == std::string::npos)
            continue;
        // Interesting filter (skip when keyword given — user knows what they want)
        if (!keyword && !isInteresting(s.value))
            continue;
        // Dedup
        if (seen.count(s.value)) continue;
        seen.insert(s.value);

        printf("[%s] %p+%06zX  %s\n",
               s.isWide ? "W" : "A",
               s.regionBase,
               s.offsetInRegion,
               s.value.c_str());
        printed++;
    }

    printf("\n[*] PID %lu: %zu total strings, %d interesting/matching printed\n",
           pid, strings.size(), printed);
    return 0;
}
