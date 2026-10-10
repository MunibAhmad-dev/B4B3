/*
  Exercise 04 — Hidden Process Detector (DKOM Detection)
  -------------------------------------------------------
  Rootkits hide processes using DKOM (Direct Kernel Object Manipulation):
  they unlink the process from the kernel's ActiveProcessLinks list.
  This makes the process invisible to:
    - Task Manager
    - Process Explorer
    - Toolhelp32 (CreateToolhelp32Snapshot)
    - NtQuerySystemInformation (what tasklist uses)

  But the process is still running and has a valid PID.

  Detection: brute-force PID scanning
    For PID in range [4, 65535, step 4]:
        Try OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID)
        If it succeeds → the process exists
        Compare against the Toolhelp32 list
        If OpenProcess succeeds but Toolhelp32 doesn't see it → HIDDEN!

  Tasks:
  1. Implement getToolhelp32Pids() — use CreateToolhelp32Snapshot +
     Process32First/Next to collect all visible PIDs.
  2. Implement bruteForcePids() — try OpenProcess for all PIDs 4..65532 (step 4).
  3. Compare the two sets and print any PIDs that brute-force found but
     Toolhelp32 did not report.
  4. For each suspect PID, print what you can learn:
     GetProcessImageFileNameA, process times, memory usage.

  BONUS:
  - Also compare against NtQuerySystemInformation(SystemProcessInformation) —
    a second independent enumeration method.
  - Try to read the image name from the hidden process's PEB (if memory access works).
  - Check if the hidden process has open handles (NtQueryInformationProcess).

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_hidden_process_detect.cpp
    -lpsapi
  Usage:
    ex04.exe
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <set>
#include <string>
#include <cstdio>

// ---------- TODO 1: getToolhelp32Pids ----------
std::set<DWORD> getToolhelp32Pids() {
    std::set<DWORD> pids;
    // YOUR CODE HERE:
    // HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // if (hSnap == INVALID_HANDLE_VALUE) return pids;
    // PROCESSENTRY32 pe = { sizeof(pe) };
    // if (Process32First(hSnap, &pe)) {
    //     do { pids.insert(pe.th32ProcessID); }
    //     while (Process32Next(hSnap, &pe));
    // }
    // CloseHandle(hSnap);
    return pids;
}

// ---------- TODO 2: bruteForcePids ----------
std::set<DWORD> bruteForcePids() {
    std::set<DWORD> pids;
    // YOUR CODE HERE:
    // for (DWORD pid = 4; pid <= 65532; pid += 4) {
    //     HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    //     if (h) { pids.insert(pid); CloseHandle(h); }
    // }
    return pids;
}

void describeProcess(DWORD pid) {
    HANDLE h = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return;

    char name[MAX_PATH] = "?";
    GetProcessImageFileNameA(h, name, sizeof(name));

    PROCESS_MEMORY_COUNTERS pmc = { sizeof(pmc) };
    GetProcessMemoryInfo(h, &pmc, sizeof(pmc));

    FILETIME create, exit, kernel, user;
    GetProcessTimes(h, &create, &exit, &kernel, &user);
    ULONGLONG createTime = ((ULONGLONG)create.dwHighDateTime << 32) | create.dwLowDateTime;

    printf("  PID=%-6lu  Image=%s\n", pid, name);
    printf("           WorkingSet=%.1f MB  CreateTime=%llu\n",
           pmc.WorkingSetSize / 1048576.0, createTime);
    CloseHandle(h);
}

int main() {
    printf("[*] Collecting visible processes (Toolhelp32)...\n");
    auto visible = getToolhelp32Pids();
    printf("[*] Toolhelp32 reports %zu processes\n", visible.size());

    if (visible.empty()) {
        printf("[-] getToolhelp32Pids not implemented yet\n");
        return 1;
    }

    printf("[*] Brute-forcing PIDs 4..65532...\n");
    auto bruteforce = bruteForcePids();
    printf("[*] Brute-force found %zu accessible PIDs\n", bruteforce.size());

    if (bruteforce.empty()) {
        printf("[-] bruteForcePids not implemented yet\n");
        return 1;
    }

    // Find hidden: brute-force found it, Toolhelp32 didn't
    int hidden = 0;
    for (DWORD pid : bruteforce) {
        if (!visible.count(pid)) {
            printf("[HIDDEN!] PID %lu not in Toolhelp32 list\n", pid);
            describeProcess(pid);
            hidden++;
        }
    }

    if (hidden == 0)
        printf("[*] No hidden processes detected\n");
    else
        printf("\n[!] Found %d hidden process(es)!\n", hidden);

    return 0;
}
