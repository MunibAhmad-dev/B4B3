/*
  Solution 03 — MiniDump Writer (Complete)
  ------------------------------------------
  Creates a full-memory minidump of any process for offline forensic
  analysis in WinDbg, Visual Studio, or Volatility.

  Requires SeDebugPrivilege for protected processes (e.g. lsass.exe on
  an authorized engagement).  For your own processes no privilege is needed.

  Compile:
    g++ -std=c++17 -Wall -o sol03.exe sol03_mini_dumper.cpp -ldbghelp
    cl  /std:c++17 sol03_mini_dumper.cpp /Fe:sol03.exe /link dbghelp.lib

  Usage:
    sol03.exe <PID>
    sol03.exe <PID> output.dmp
    sol03.exe 1234 notepad.dmp
*/

#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include <string>
#include <cstdio>


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
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp    = {};
    tp.PrivilegeCount      = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp),
                                    nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    if (!ok) {
        printf("[-] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        return false;
    }
    if (err == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] SeDebugPrivilege not assigned to this account\n");
        return false;
    }
    printf("[+] SeDebugPrivilege enabled\n");
    return true;
}


// =========================================================
// 2. createDump — open process, create file, call MiniDumpWriteDump
// =========================================================
bool createDump(DWORD pid, const std::string& outputPath) {
    // Open the target process with full access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return false;
    }

    // Create (or overwrite) the output file
    HANDLE hFile = CreateFileA(
        outputPath.c_str(),
        GENERIC_WRITE,
        0,            // no sharing
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(\"%s\") failed: %lu\n",
               outputPath.c_str(), GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    // Dump flags: full memory + handles + thread info + memory info
    MINIDUMP_TYPE flags = (MINIDUMP_TYPE)(
        MiniDumpWithFullMemory         |   // all committed pages
        MiniDumpWithHandleData         |   // open handles
        MiniDumpWithThreadInfo         |   // thread start times, etc.
        MiniDumpWithFullMemoryInfo     |   // MEMORY_INFO_LIST
        MiniDumpWithProcessThreadData  |   // TEB/PEB data
        MiniDumpWithUnloadedModules    );  // recently unloaded DLLs

    printf("[*] Calling MiniDumpWriteDump...\n");

    BOOL ok = MiniDumpWriteDump(
        hProcess,
        pid,
        hFile,
        flags,
        nullptr,    // no exception info (not a crash dump)
        nullptr,    // no user stream
        nullptr);   // no callback

    DWORD err = GetLastError();

    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (!ok) {
        printf("[-] MiniDumpWriteDump failed: %lu\n", err);
        // Remove the partial/empty file
        DeleteFileA(outputPath.c_str());
        return false;
    }

    return true;
}


// =========================================================
// 3. reportDump — validate file size and print WinDbg instructions
// =========================================================
void reportDump(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Dump file not found at '%s'\n", path.c_str());
        return;
    }

    LARGE_INTEGER size = {};
    GetFileSizeEx(hFile, &size);
    CloseHandle(hFile);

    if (size.QuadPart == 0) {
        printf("[-] Dump file is empty — dump may have failed silently\n");
        return;
    }

    printf("\n[+] Dump complete!\n");
    printf("    Path   : %s\n", path.c_str());
    printf("    Size   : %lld bytes  (%.1f MB)\n",
           size.QuadPart, size.QuadPart / 1048576.0);
    printf("\n[*] Analysis options:\n");
    printf("    WinDbg (GUI)    : File > Open Crash Dump > \"%s\"\n",  path.c_str());
    printf("    WinDbg (CLI)    : windbg -z \"%s\"\n",                 path.c_str());
    printf("    WinDbg (inline) : .open -z \"%s\"\n",                  path.c_str());
    printf("    Visual Studio   : Debug > Other Debug Targets > Dump file\n");
    printf("    Volatility3     : vol -f \"%s\" windows.pslist\n",     path.c_str());
    printf("\n[*] Useful WinDbg commands after opening:\n");
    printf("    !analyze -v   — automatic analysis\n");
    printf("    lm            — loaded modules\n");
    printf("    !process 0 0  — process list\n");
    printf("    !address      — memory region summary\n");
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage  : %s <PID> [output.dmp]\n", argv[0]);
        printf("Example: %s 1234\n",               argv[0]);
        printf("Example: %s 1234 notepad.dmp\n",   argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    if (pid == 0) {
        printf("[-] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    std::string outPath = (argc > 2)
        ? argv[2]
        : ("dump_" + std::to_string(pid) + ".dmp");

    printf("[*] Target PID    : %lu\n",  pid);
    printf("[*] Output file   : %s\n\n", outPath.c_str());

    printf("[*] Requesting SeDebugPrivilege...\n");
    if (!enableSeDebugPrivilege())
        printf("[!] Continuing without SeDebugPrivilege — "
               "will fail on protected processes\n\n");

    printf("[*] Creating dump...\n");
    if (createDump(pid, outPath)) {
        reportDump(outPath);
        return 0;
    } else {
        printf("[-] Dump failed\n");
        return 1;
    }
}
