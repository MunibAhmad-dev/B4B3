/*
  Exercise 01 — Memory Region Scanner
  --------------------------------------
  Scan all virtual memory regions of a running process and report:
    - Region type (image, mapped, private)
    - Permissions (read, write, execute)
    - Suspicious regions: private + executable + not image-backed
      (this is where shellcode and injected code typically lives)

  Tasks:
  1. Implement enumerateRegions(pid) — use VirtualQueryEx in a loop to
     walk all committed memory regions of the target process.
  2. For each region, print: base, size, type (MEM_IMAGE/MEM_MAPPED/MEM_PRIVATE),
     state (MEM_COMMIT/MEM_RESERVE/MEM_FREE), and permissions.
  3. Flag regions as SUSPICIOUS if:
       - State == MEM_COMMIT
       - Type == MEM_PRIVATE
       - Protect has PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
         or PAGE_EXECUTE_WRITECOPY
     These are the classic indicators of shellcode or an injected PE.
  4. For each suspicious region, dump the first 64 bytes as hex.

  BONUS:
  - Check if a suspicious private executable region looks like an MZ header
    (0x4D 0x5A = "MZ") — this indicates a manually mapped / reflectively
    loaded PE hiding in memory.
  - Count total memory committed by image vs private vs mapped.
  - Compare suspicious private executable regions against the Toolhelp32
    module list to see if any are un-backed (not in any loaded module).

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_memory_scanner.cpp
  Usage:
    ex01.exe <PID>
    ex01.exe 1234
*/

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdio>

struct Region {
    LPVOID  base;
    SIZE_T  size;
    DWORD   state;
    DWORD   protect;
    DWORD   type;
    bool    suspicious;
};

const char* protectStr(DWORD p) {
    switch (p & 0xFF) {
        case PAGE_NOACCESS:          return "---";
        case PAGE_READONLY:          return "r--";
        case PAGE_READWRITE:         return "rw-";
        case PAGE_WRITECOPY:         return "wc-";
        case PAGE_EXECUTE:           return "--x";
        case PAGE_EXECUTE_READ:      return "r-x";
        case PAGE_EXECUTE_READWRITE: return "rwx";
        case PAGE_EXECUTE_WRITECOPY: return "wcx";
        default:                     return "???";
    }
}

const char* typeStr(DWORD t) {
    if (t == MEM_IMAGE)   return "IMAGE  ";
    if (t == MEM_MAPPED)  return "MAPPED ";
    if (t == MEM_PRIVATE) return "PRIVATE";
    return "UNKNOWN";
}

bool isExecutable(DWORD protect) {
    return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// ---------- TODO 1: enumerateRegions ----------
std::vector<Region> enumerateRegions(DWORD pid) {
    std::vector<Region> regions;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return regions;
    }

    // YOUR CODE HERE:
    // MEMORY_BASIC_INFORMATION mbi = {};
    // LPVOID addr = nullptr;
    // while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    //     if (mbi.State == MEM_COMMIT) {
    //         Region r;
    //         r.base = mbi.BaseAddress;
    //         r.size = mbi.RegionSize;
    //         r.state = mbi.State;
    //         r.protect = mbi.Protect;
    //         r.type = mbi.Type;
    //         r.suspicious = (mbi.Type == MEM_PRIVATE && isExecutable(mbi.Protect));
    //         regions.push_back(r);
    //     }
    //     addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    // }

    CloseHandle(hProcess);
    return regions;
}

// ---------- TODO 4: dump suspicious regions ----------
void dumpRegion(DWORD pid, const Region& r) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    BYTE buf[64] = {};
    SIZE_T bytesRead = 0;
    SIZE_T toRead = min(r.size, sizeof(buf));
    ReadProcessMemory(hProcess, r.base, buf, toRead, &bytesRead);
    CloseHandle(hProcess);

    printf("  [DUMP %p +%zu bytes]\n  ", r.base, bytesRead);
    for (SIZE_T i = 0; i < bytesRead; i++) {
        printf("%02X ", buf[i]);
        if ((i+1) % 16 == 0) printf("\n  ");
    }
    printf("\n");

    if (bytesRead >= 2 && buf[0] == 0x4D && buf[1] == 0x5A)
        printf("  [!] MZ header detected — possible reflective PE load!\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    DWORD pid = (DWORD)atoi(argv[1]);
    auto regions = enumerateRegions(pid);

    if (regions.empty()) {
        printf("[-] No regions found (enumerateRegions not implemented?)\n");
        return 1;
    }

    printf("%-18s %-14s %-8s %-7s %s\n",
           "Base", "Size", "Type", "Prot", "Flags");
    printf("%s\n", std::string(65, '-').c_str());

    int suspicious = 0;
    for (auto& r : regions) {
        printf("%018p  %12zu  %s  %s",
               r.base, r.size, typeStr(r.type), protectStr(r.protect));
        if (r.suspicious) { printf("  *** SUSPICIOUS ***"); suspicious++; }
        printf("\n");
    }

    printf("\n[*] Total regions: %zu  Suspicious: %d\n",
           regions.size(), suspicious);

    // Dump suspicious
    for (auto& r : regions)
        if (r.suspicious) dumpRegion(pid, r);

    return 0;
}
