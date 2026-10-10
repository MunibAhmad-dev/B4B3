/*
  Solution 01 — Memory Region Scanner (Complete)
  ------------------------------------------------
  Enumerates all committed virtual memory regions of a target process,
  flags private+executable regions as suspicious, dumps their first 64
  bytes, and checks for MZ headers (reflectively loaded PEs).

  Compile:
    g++ -std=c++17 -Wall -o sol01.exe sol01_memory_scanner.cpp -lpsapi
    cl  /std:c++17 sol01_memory_scanner.cpp /Fe:sol01.exe /link psapi.lib

  Usage:
    sol01.exe <PID>
    sol01.exe 1234
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <string>
#include <vector>
#include <cstdio>
#include <algorithm>

struct Region {
    LPVOID base;
    SIZE_T size;
    DWORD  state;
    DWORD  protect;
    DWORD  type;
    bool   suspicious;
};

// =========================================================
// Display helpers (already in the exercise, kept for completeness)
// =========================================================
static const char* protectStr(DWORD p) {
    switch (p & 0xFF) {
        case PAGE_NOACCESS:           return "---";
        case PAGE_READONLY:           return "r--";
        case PAGE_READWRITE:          return "rw-";
        case PAGE_WRITECOPY:          return "wc-";
        case PAGE_EXECUTE:            return "--x";
        case PAGE_EXECUTE_READ:       return "r-x";
        case PAGE_EXECUTE_READWRITE:  return "rwx";
        case PAGE_EXECUTE_WRITECOPY:  return "wcx";
        default:                      return "???";
    }
}

static const char* typeStr(DWORD t) {
    if (t == MEM_IMAGE)   return "IMAGE  ";
    if (t == MEM_MAPPED)  return "MAPPED ";
    if (t == MEM_PRIVATE) return "PRIVATE";
    return "UNKNOWN";
}

static bool isExecutable(DWORD protect) {
    return (protect & (PAGE_EXECUTE |
                       PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE |
                       PAGE_EXECUTE_WRITECOPY)) != 0;
}


// =========================================================
// 1. enableSeDebugPrivilege
// =========================================================
bool enableSeDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken))
        return false;

    LUID luid = {};
    LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid);

    TOKEN_PRIVILEGES tp  = {};
    tp.PrivilegeCount    = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp),
                                    nullptr, nullptr);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}


// =========================================================
// 2. enumerateRegions — walk all committed pages
// =========================================================
std::vector<Region> enumerateRegions(DWORD pid) {
    std::vector<Region> regions;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return regions;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = nullptr;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            Region r;
            r.base  = mbi.BaseAddress;
            r.size  = mbi.RegionSize;
            r.state = mbi.State;
            // Note: mbi.Protect can be 0 for guard pages; use AllocationProtect
            // as fallback but Protect is what the current page has.
            r.protect    = mbi.Protect ? mbi.Protect : mbi.AllocationProtect;
            r.type       = mbi.Type;
            r.suspicious = (mbi.Type == MEM_PRIVATE && isExecutable(r.protect));
            regions.push_back(r);
        }
        // Advance to the next region
        addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return regions;
}


// =========================================================
// 3. checkMzHeader — read 2 bytes and test for MZ signature
// =========================================================
bool checkMzHeader(HANDLE hProcess, LPVOID addr) {
    BYTE header[2] = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, addr, header, 2, &bytesRead)
        || bytesRead < 2)
        return false;
    return header[0] == 0x4D && header[1] == 0x5A;   // "MZ"
}


// =========================================================
// 4. printSuspicious — dump each suspicious region
// =========================================================
void printSuspicious(DWORD pid, const std::vector<Region>& regions) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[-] Cannot open process for region dump: %lu\n",
               GetLastError());
        return;
    }

    int idx = 0;
    for (auto& r : regions) {
        if (!r.suspicious) continue;

        idx++;
        bool hasMz = checkMzHeader(hProcess, r.base);

        printf("\n[SUSPICIOUS #%d]\n", idx);
        printf("  Base    : %p\n",   r.base);
        printf("  Size    : %zu KB  (%zu bytes)\n",
               r.size / 1024, r.size);
        printf("  Type    : %s\n",   typeStr(r.type));
        printf("  Protect : %s (0x%02X)\n", protectStr(r.protect), r.protect);
        if (hasMz)
            printf("  [!] MZ HEADER DETECTED — possible reflective PE load!\n");

        // Dump first 64 bytes
        BYTE buf[64] = {};
        SIZE_T bytesRead = 0;
        SIZE_T toRead    = (r.size < sizeof(buf)) ? r.size : sizeof(buf);
        ReadProcessMemory(hProcess, r.base, buf, toRead, &bytesRead);

        printf("  Hex dump (%zu bytes):\n  ", bytesRead);
        for (SIZE_T i = 0; i < bytesRead; i++) {
            printf("%02X ", buf[i]);
            if ((i + 1) % 16 == 0 && i + 1 < bytesRead)
                printf("\n  ");
        }
        printf("\n");

        // ASCII representation
        printf("  ASCII:  ");
        for (SIZE_T i = 0; i < bytesRead; i++) {
            char c = (buf[i] >= 0x20 && buf[i] <= 0x7E) ? (char)buf[i] : '.';
            printf("%c", c);
        }
        printf("\n");
    }

    CloseHandle(hProcess);
}


// =========================================================
// Summary stats
// =========================================================
static void printSummary(const std::vector<Region>& regions) {
    SIZE_T totalImage   = 0, totalMapped = 0, totalPrivate = 0;
    int    suspicious   = 0;

    for (auto& r : regions) {
        if (r.type == MEM_IMAGE)        totalImage   += r.size;
        else if (r.type == MEM_MAPPED)  totalMapped  += r.size;
        else if (r.type == MEM_PRIVATE) totalPrivate += r.size;
        if (r.suspicious) suspicious++;
    }

    printf("\n[SUMMARY]\n");
    printf("  Total committed regions : %zu\n", regions.size());
    printf("  Image  memory           : %.1f MB\n", totalImage   / 1048576.0);
    printf("  Mapped memory           : %.1f MB\n", totalMapped  / 1048576.0);
    printf("  Private memory          : %.1f MB\n", totalPrivate / 1048576.0);
    printf("  Suspicious regions      : %d\n\n", suspicious);
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    DWORD pid = (DWORD)atoi(argv[1]);

    printf("[*] Enabling SeDebugPrivilege...\n");
    if (!enableSeDebugPrivilege())
        printf("[!] SeDebugPrivilege not granted — may fail on protected processes\n");

    printf("[*] Scanning memory regions of PID %lu...\n\n", pid);

    auto regions = enumerateRegions(pid);
    if (regions.empty()) {
        printf("[-] No regions found (OpenProcess may have failed)\n");
        return 1;
    }

    // Print table header
    printf("%-18s  %-14s  %-8s  %-5s  %s\n",
           "Base", "Size", "Type", "Prot", "Flags");
    printf("%s\n", std::string(70, '-').c_str());

    for (auto& r : regions) {
        printf("%p  %12zu  %s  %s",
               r.base, r.size,
               typeStr(r.type), protectStr(r.protect));
        if (r.suspicious) printf("  *** SUSPICIOUS ***");
        printf("\n");
    }

    printSummary(regions);
    printSuspicious(pid, regions);

    return 0;
}
