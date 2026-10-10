/*
  Solution 04 — Token Enumerator
  --------------------------------
  Complete implementation that walks all running processes and for each prints:
    PID | Process Name | User (DOMAIN\user) | Integrity Level | Notable Privileges

  Highlights processes carrying SeDebugPrivilege or SeImpersonatePrivilege —
  these are high-value targets for privilege escalation (token theft / potato attacks).

  Compile:
    g++ -std=c++17 -Wall -o sol04_token_enum.exe sol04_token_enum.cpp -ladvapi32
  Run as Administrator for full results (some processes need SeDebugPrivilege).
*/

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdio>

// ---- TODO 1: getTokenUser ----
std::string getTokenUser(HANDLE hToken) {
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
    if (!sz) return "?";

    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz))
        return "?";

    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    char name[256] = {}, domain[256] = {};
    DWORD nl = sizeof(name), dl = sizeof(domain);
    SID_NAME_USE use;
    if (!LookupAccountSidA(nullptr, tu->User.Sid, name, &nl, domain, &dl, &use))
        return "?";

    return std::string(domain) + "\\" + name;
}

// ---- TODO 2: getIntegrityLevel ----
std::string getIntegrityLevel(HANDLE hToken) {
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &sz);
    if (!sz) return "?";

    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), sz, &sz))
        return "?";

    auto* tml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    DWORD rid = *GetSidSubAuthority(
        tml->Label.Sid,
        *GetSidSubAuthorityCount(tml->Label.Sid) - 1);

    if (rid >= SECURITY_MANDATORY_SYSTEM_RID)   return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID)      return "High";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID)    return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID)       return "Low";
    return "Untrusted";
}

// ---- TODO 3: getPrivileges ----
// Returns only ENABLED privileges. Flags SeDebugPrivilege and SeImpersonatePrivilege.
struct PrivilegeInfo {
    std::vector<std::string> enabled;
    bool hasDebug       = false;
    bool hasImpersonate = false;
};

PrivilegeInfo getPrivileges(HANDLE hToken) {
    PrivilegeInfo info;

    DWORD sz = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &sz);
    if (!sz) return info;

    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenPrivileges, buf.data(), sz, &sz))
        return info;

    auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
    for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
        if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
            char name[64] = {};
            DWORD nl = sizeof(name);
            LookupPrivilegeNameA(nullptr, &tp->Privileges[i].Luid, name, &nl);
            info.enabled.push_back(name);

            if (strcmp(name, "SeDebugPrivilege")       == 0) info.hasDebug       = true;
            if (strcmp(name, "SeImpersonatePrivilege") == 0) info.hasImpersonate = true;
        }
    }
    return info;
}

// ---- TODO 4: enumerateProcessTokens ----
void enumerateProcessTokens() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot: %lu\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32First(hSnap, &pe)) {
        CloseHandle(hSnap);
        return;
    }

    do {
        // PROCESS_QUERY_INFORMATION preferred; fall back to LIMITED if needed
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProc)
            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProc) continue;

        HANDLE hToken = nullptr;
        if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
            CloseHandle(hProc);
            continue;
        }

        std::string user      = getTokenUser(hToken);
        std::string integrity = getIntegrityLevel(hToken);
        PrivilegeInfo privs   = getPrivileges(hToken);

        // Build notable privileges string
        std::string notable;
        if (privs.hasDebug)       notable += " [SeDebug]";
        if (privs.hasImpersonate) notable += " [SeImpersonate]";

        // Print row — flag high-value targets with a marker
        bool highValue = privs.hasDebug || privs.hasImpersonate;
        printf("%s PID=%-6lu  %-28s  %-38s  %-9s%s\n",
               highValue ? ">>>" : "   ",
               pe.th32ProcessID,
               pe.szExeFile,
               user.c_str(),
               integrity.c_str(),
               notable.c_str());

        CloseHandle(hToken);
        CloseHandle(hProc);
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);
}

int main() {
    printf("[*] Token Enumerator — run as Administrator for full results\n");
    printf("[*] >>> marks high-value targets (SeDebug / SeImpersonate)\n\n");
    printf("    %-6s  %-28s  %-38s  %-9s  Notable\n",
           "PID", "Process", "User", "Integrity");
    printf("    %s\n", std::string(100, '-').c_str());

    enumerateProcessTokens();
    return 0;
}
