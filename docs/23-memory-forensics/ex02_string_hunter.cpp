/*
  Exercise 02 — In-Memory String Hunter
  ----------------------------------------
  Scan all committed regions of a live process and extract strings.
  More powerful than file-based string extraction because:
    - Decrypted/decoded strings appear in memory even if not on disk.
    - Packed executables unpack themselves; strings are visible after unpack.
    - C2 URLs, encryption keys, mutex names often only appear at runtime.

  Tasks:
  1. Implement scanProcessMemory(pid, minLen) — enumerate all committed
     MEM_COMMIT regions, ReadProcessMemory each one, extract ASCII + Wide strings.
  2. Filter for interesting patterns (URLs, IPs, registry keys, etc.).
  3. De-duplicate: don't print the same string twice.
  4. Print with region base address so you know WHERE in the process it lives.

  BONUS:
  - Accept a keyword argument: scan only for strings containing a specific word.
    ex02.exe 1234 --keyword "password"
  - For each interesting string, check if it appears in the process's file on
    disk (if not, it was generated or decrypted at runtime — very interesting).

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_string_hunter.cpp
  Usage:
    ex02.exe <PID> [minLen] [--keyword <word>]
    ex02.exe 1234
    ex02.exe 1234 6 --keyword http
*/

#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <cstdio>
#include <cstring>

static int g_minLen = 5;

struct FoundString {
    std::string value;
    bool        isWide;
    LPVOID      regionBase;
    size_t      offsetInRegion;
};

// Re-use classification logic from ex02 of module 22
bool isInteresting(const std::string& s) {
    if (s.find("http://")  != std::string::npos) return true;
    if (s.find("https://") != std::string::npos) return true;
    if (s.find("HKEY_")    != std::string::npos) return true;
    if (s.find("HKLM\\")   != std::string::npos) return true;
    if (s.find("Global\\") != std::string::npos) return true;
    if (s.find(".exe")     != std::string::npos) return true;
    if (s.find(".dll")     != std::string::npos) return true;
    if (s.find("password") != std::string::npos) return true;
    if (s.find("Password") != std::string::npos) return true;
    if (s.find("token")    != std::string::npos) return true;
    // IP address-ish: digit.digit.digit.digit
    int dots = 0;
    for (char c : s) if (c == '.') dots++;
    if (dots == 3 && s.size() >= 7) return true;
    return false;
}

std::vector<FoundString> extractFromBuf(const BYTE* buf, size_t size, LPVOID base) {
    std::vector<FoundString> found;

    // ASCII
    size_t start = SIZE_MAX;
    for (size_t i = 0; i <= size; i++) {
        if (i < size && buf[i] >= 0x20 && buf[i] <= 0x7E) {
            if (start == SIZE_MAX) start = i;
        } else {
            if (start != SIZE_MAX) {
                size_t len = i - start;
                if ((int)len >= g_minLen) {
                    std::string s((char*)buf + start, len);
                    found.push_back({ s, false, base, start });
                }
                start = SIZE_MAX;
            }
        }
    }

    // Wide (UTF-16LE)
    start = SIZE_MAX;
    for (size_t i = 0; i + 1 < size; i += 2) {
        if (buf[i+1] == 0x00 && buf[i] >= 0x20 && buf[i] <= 0x7E) {
            if (start == SIZE_MAX) start = i;
        } else {
            if (start != SIZE_MAX) {
                size_t chars = (i - start) / 2;
                if ((int)chars >= g_minLen) {
                    std::string s;
                    for (size_t j = start; j < i; j += 2) s += (char)buf[j];
                    found.push_back({ s, true, base, start });
                }
                start = SIZE_MAX;
            }
        }
    }

    return found;
}

// ---------- TODO: scanProcessMemory ----------
std::vector<FoundString> scanProcessMemory(DWORD pid) {
    std::vector<FoundString> all;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return all;
    }

    // YOUR CODE HERE:
    // MEMORY_BASIC_INFORMATION mbi = {};
    // LPVOID addr = nullptr;
    // while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    //     if (mbi.State == MEM_COMMIT &&
    //         !(mbi.Protect & PAGE_GUARD) &&
    //         !(mbi.Protect & PAGE_NOACCESS))
    //     {
    //         std::vector<BYTE> buf(mbi.RegionSize);
    //         SIZE_T bytesRead = 0;
    //         if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytesRead)) {
    //             auto found = extractFromBuf(buf.data(), bytesRead, mbi.BaseAddress);
    //             all.insert(all.end(), found.begin(), found.end());
    //         }
    //     }
    //     addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    // }

    CloseHandle(hProcess);
    return all;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID> [minLen] [--keyword <word>]\n", argv[0]);
        return 1;
    }
    DWORD pid = (DWORD)atoi(argv[1]);
    if (argc > 2 && atoi(argv[2]) > 0) g_minLen = atoi(argv[2]);

    const char* keyword = nullptr;
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], "--keyword") == 0) keyword = argv[i+1];

    auto strings = scanProcessMemory(pid);
    if (strings.empty()) {
        printf("[-] No strings found (scanProcessMemory not implemented?)\n");
        return 1;
    }

    std::set<std::string> seen;
    int printed = 0;

    for (auto& s : strings) {
        if (keyword && s.value.find(keyword) == std::string::npos) continue;
        if (!keyword && !isInteresting(s.value)) continue;
        if (seen.count(s.value)) continue;
        seen.insert(s.value);

        printf("[%s] %p+%06zX  %s\n",
               s.isWide ? "W" : "A",
               s.regionBase, s.offsetInRegion,
               s.value.c_str());
        printed++;
    }

    printf("\n[*] Process %lu: %zu strings scanned, %d interesting/matching printed\n",
           pid, strings.size(), printed);
    return 0;
}
