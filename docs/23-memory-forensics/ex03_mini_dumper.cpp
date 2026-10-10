/*
  Exercise 03 — MiniDump Writer
  --------------------------------
  A minidump captures a process's memory, threads, and modules at a point
  in time for offline analysis. IR (Incident Response) analysts use this to
  analyze compromised processes without running them live.

  This tool creates a full-memory minidump of any process:
    MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, ...)

  The resulting .dmp file can be opened in:
    - WinDbg (`.open -z target.dmp`)
    - Visual Studio debugger
    - Python's volatility3 / rekall framework

  Tasks:
  1. Implement dumpProcess(pid, outputPath) — open the target process with
     PROCESS_ALL_ACCESS, create the output file, call MiniDumpWriteDump.
  2. Validate the dump: check that the output file is non-zero size.
  3. Print the dump file size and a hint on how to open it in WinDbg.

  BONUS:
  - Implement LSASS dump detection evasion:
    Instead of calling MiniDumpWriteDump directly (which EDRs hook), use
    NtReadVirtualMemory in a loop to copy all LSASS memory to your own
    process, then write a valid minidump format manually using the
    MINIDUMP_* structs from dbghelp.h.
  - Use comsvcs.dll's MiniDump() export (rundll32 comsvcs.dll,MiniDump
    <pid> dump.dmp full) as an alternative method.

  Note: dumping LSASS requires SeDebugPrivilege.
  In authorized penetration tests this is allowed; in this exercise we
  dump a process you own (e.g. notepad.exe).

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_mini_dumper.cpp -ldbghelp
  Usage:
    ex03.exe <PID> [output.dmp]
    ex03.exe 1234
    ex03.exe 1234 notepad.dmp
*/

#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include <string>
#include <cstdio>

bool enableSeDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid);

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

// ---------- TODO 1: dumpProcess ----------
bool dumpProcess(DWORD pid, const std::string& outputPath) {
    // YOUR CODE HERE:
    // 1. HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    //    if (!hProcess) { printf("[-] OpenProcess: %lu\n", GetLastError()); return false; }
    //
    // 2. HANDLE hFile = CreateFileA(outputPath.c_str(), GENERIC_WRITE, 0, nullptr,
    //                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    //    if (hFile == INVALID_HANDLE_VALUE) { ... }
    //
    // 3. MINIDUMP_TYPE flags = (MINIDUMP_TYPE)(MiniDumpWithFullMemory |
    //                                          MiniDumpWithHandleData |
    //                                          MiniDumpWithThreadInfo |
    //                                          MiniDumpWithFullMemoryInfo |
    //                                          MiniDumpWithUnloadedModules);
    //
    // 4. BOOL ok = MiniDumpWriteDump(hProcess, pid, hFile, flags,
    //                                nullptr, nullptr, nullptr);
    //
    // 5. CloseHandle(hFile); CloseHandle(hProcess);
    // 6. return ok == TRUE;

    (void)pid; (void)outputPath;
    printf("[-] dumpProcess not implemented yet\n");
    return false;
}

// ---------- TODO 2+3: validate and report ----------
void reportDump(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Dump file not found\n");
        return;
    }
    LARGE_INTEGER size = {};
    GetFileSizeEx(hFile, &size);
    CloseHandle(hFile);

    printf("[+] Dump written: %s  (%lld bytes / %.1f MB)\n",
           path.c_str(), size.QuadPart, size.QuadPart / 1048576.0);
    printf("[*] Open in WinDbg:\n");
    printf("    windbg -z \"%s\"\n", path.c_str());
    printf("[*] Or: .open -z \"%s\" in an existing WinDbg session\n", path.c_str());
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID> [output.dmp]\n", argv[0]);
        printf("  Example: %s 1234\n", argv[0]);
        printf("  Example: %s 1234 notepad.dmp\n", argv[0]);
        return 1;
    }
    DWORD pid = (DWORD)atoi(argv[1]);
    std::string outPath = argc > 2 ? argv[2] : ("dump_" + std::to_string(pid) + ".dmp");

    printf("[*] Enabling SeDebugPrivilege...\n");
    if (!enableSeDebugPrivilege())
        printf("[!] SeDebugPrivilege not granted — may fail on protected processes\n");

    printf("[*] Dumping PID %lu → %s\n", pid, outPath.c_str());
    if (dumpProcess(pid, outPath))
        reportDump(outPath);
    else
        printf("[-] Dump failed\n");

    return 0;
}
