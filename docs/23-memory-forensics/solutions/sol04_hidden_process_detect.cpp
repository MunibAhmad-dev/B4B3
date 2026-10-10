/*
  Solution 04 — Hidden Process Detector (Complete)
  --------------------------------------------------
  Detects DKOM-hidden processes by brute-forcing PID handles and
  comparing against the Toolhelp32 snapshot.

  A DKOM rootkit unlinks a process from the kernel's ActiveProcessLinks
  list, making it invisible to Task Manager, Toolhelp32, and NtQuerySystemInformation,
  but the process still exists and its handle is still openable by PID.

  Compile:
    g++ -std=c++17 -Wall -o sol04.exe sol04_hidden_process_detect.cpp -lpsapi
    cl  /std:c++17 sol04_hidden_process_detect.cpp /Fe:sol04.exe /link psapi.lib

  Usage:
    sol04.exe
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <set>
#include <map>
#include <string>
#include <cstdio>
#include <algorithm>


// =========================================================
// 1. getToolhelp32Pids — enumerate via CreateToolhelp32Snapshot
// =========================================================
std::set<DWORD> getToolhelp32Pids() {
    std::set<DWORD> pids;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return pids;
    }

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            pids.insert(pe.th32ProcessID);
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pids;
}


// =========================================================
// 2. bruteForcePids — try OpenProcess for every PID 4..65532 (step 4)
//    Windows PIDs are always multiples of 4 (kernel handle increment).
// =========================================================
std::set<DWORD> bruteForcePids(DWORD maxPid = 65532) {
    std::set<DWORD> pids;

    for (DWORD pid = 4; pid <= maxPid; pid += 4) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, pid);
        if (h) {
            pids.insert(pid);
            CloseHandle(h);
        }
    }
    return pids;
}


// =========================================================
// findHidden — set difference: brute-force found but Toolhelp32 missed
// =========================================================
std::set<DWORD> findHidden(const std::set<DWORD>& bruteForce,
                            const std::set<DWORD>& toolhelp) {
    std::set<DWORD> hidden;
    for (DWORD pid : bruteForce)
        if (!toolhelp.count(pid)) hidden.insert(pid);
    return hidden;
}


// =========================================================
// describeProcess — print what we can learn about a PID
// =========================================================
static void describeProcess(DWORD pid, bool isHidden) {
    HANDLE h = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!h) {
        printf("  PID=%-6lu  [cannot open]\n", pid);
        return;
    }

    // Image name
    char imageName[MAX_PATH] = "<unknown>";
    GetProcessImageFileNameA(h, imageName, sizeof(imageName));

    // Memory usage
    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);
    GetProcessMemoryInfo(h, &pmc, sizeof(pmc));

    // Process times
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    ULONGLONG createTime = 0;
    if (GetProcessTimes(h, &ftCreate, &ftExit, &ftKernel, &ftUser))
        createTime = ((ULONGLONG)ftCreate.dwHighDateTime << 32)
                   |  ftCreate.dwLowDateTime;

    CloseHandle(h);

    printf("  PID=%-6lu  %s\n", pid, imageName);
    printf("           WorkingSet=%.1f MB  CreateTime=%llu\n",
           pmc.WorkingSetSize / 1048576.0, createTime);
    if (isHidden)
        printf("           [!] NOT visible in Toolhelp32 snapshot!\n");
}


// =========================================================
// main
// =========================================================
int main() {
    printf("=== Hidden Process Detector ===\n\n");

    // Step 1: Toolhelp32 snapshot
    printf("[*] Collecting visible processes via Toolhelp32...\n");
    auto toolhelp = getToolhelp32Pids();
    printf("[*] Toolhelp32 reports %zu processes\n\n", toolhelp.size());

    if (toolhelp.empty()) {
        printf("[-] Toolhelp32 enumeration failed\n");
        return 1;
    }

    // Step 2: Brute-force PID scan
    printf("[*] Brute-forcing PIDs 4..65532 (step 4)...\n");
    printf("    (This may take a moment...)\n");
    auto bruteForce = bruteForcePids();
    printf("[*] Brute-force found %zu accessible PIDs\n\n", bruteForce.size());

    if (bruteForce.empty()) {
        printf("[-] Brute-force PID scan returned nothing (privilege issue?)\n");
        return 1;
    }

    // Step 3: Compute the hidden set
    auto hidden = findHidden(bruteForce, toolhelp);

    // Step 4: Print normally-visible processes (for reference)
    printf("[ALL ACCESSIBLE PROCESSES]\n");
    printf("%-8s  %s\n", "PID", "Image");
    printf("%s\n", std::string(60, '-').c_str());
    for (DWORD pid : bruteForce) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) continue;
        char name[MAX_PATH] = "<unknown>";
        GetProcessImageFileNameA(h, name, sizeof(name));
        CloseHandle(h);

        bool isHid = hidden.count(pid) > 0;
        printf("%-8lu  %s%s\n", pid, name,
               isHid ? "  *** HIDDEN ***" : "");
    }

    // Step 5: Report hidden processes
    printf("\n");
    if (hidden.empty()) {
        printf("[*] No hidden processes detected.\n");
        printf("[*] (Note: kernel DKOM hides processes from both Toolhelp32\n"
               "    AND from OpenProcess on pre-Vista kernels.  This scan\n"
               "    catches 'half-hidden' rootkits that only unlink from the\n"
               "    process list but leave handles intact.)\n");
    } else {
        printf("[!] Found %zu HIDDEN process(es):\n\n", hidden.size());
        for (DWORD pid : hidden) {
            printf("[HIDDEN] PID %lu\n", pid);
            describeProcess(pid, true);
            printf("\n");
        }
    }

    // Summary counts
    printf("\n[SUMMARY]\n");
    printf("  Toolhelp32 visible : %zu\n", toolhelp.size());
    printf("  Brute-force found  : %zu\n", bruteForce.size());
    printf("  Hidden (delta)     : %zu\n", hidden.size());

    return 0;
}
