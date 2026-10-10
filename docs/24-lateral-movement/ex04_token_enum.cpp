/*
  Exercise 04 — Token Enumerator
  --------------------------------
  Tokens represent user identity. Understanding what tokens exist on a
  machine and what privileges they carry is fundamental to:
    - Privilege escalation (find a SYSTEM token you can steal)
    - Lateral movement (find tokens for other users/machines)
    - Defense (audit which processes have dangerous privileges)

  This tool enumerates all running processes and for each one prints:
    - Process name + PID
    - Token user (who owns it)
    - Token type (Primary / Impersonation)
    - Integrity level (System / High / Medium / Low)
    - Privileges (especially SeDebugPrivilege, SeImpersonatePrivilege)

  Tasks:
  1. Implement getTokenUser(hToken) → returns "DOMAIN\\user".
  2. Implement getIntegrityLevel(hToken) → returns "System"/"High"/"Medium"/"Low".
  3. Implement getPrivileges(hToken) → returns vector of privilege names
     that are ENABLED (SE_PRIVILEGE_ENABLED).
  4. Implement enumerateAll() — walk all processes via Toolhelp32,
     OpenProcess + OpenProcessToken, call helpers, print report.
  5. Highlight processes that have SeImpersonatePrivilege or SeDebugPrivilege
     (these are high-value targets for privilege escalation).

  BONUS:
  - Also check for TOKEN_DUPLICATE on each token — if you can open it
    with TOKEN_DUPLICATE, you can steal that identity.
  - Identify "potato-able" tokens: services running as NETWORK SERVICE
    or LOCAL SERVICE with SeImpersonatePrivilege enabled.

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_token_enum.cpp -ladvapi32
  Run as Administrator for best results (some processes need SeDebugPrivilege).
*/

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdio>

// ---------- TODO 1: getTokenUser ----------
std::string getTokenUser(HANDLE hToken) {
    // YOUR CODE HERE:
    // DWORD sz = 0;
    // GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
    // std::vector<BYTE> buf(sz);
    // GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
    // TOKEN_USER* tu = (TOKEN_USER*)buf.data();
    // char name[256]={}, domain[256]={};
    // DWORD nl=sizeof(name), dl=sizeof(domain);
    // SID_NAME_USE use;
    // LookupAccountSidA(nullptr, tu->User.Sid, name, &nl, domain, &dl, &use);
    // return std::string(domain) + "\\" + name;
    (void)hToken;
    return "?";
}

// ---------- TODO 2: getIntegrityLevel ----------
std::string getIntegrityLevel(HANDLE hToken) {
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &sz);
    if (!sz) return "?";
    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), sz, &sz))
        return "?";

    // YOUR CODE HERE:
    // TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)buf.data();
    // DWORD rid = *GetSidSubAuthority(tml->Label.Sid,
    //                 *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
    // if (rid >= SECURITY_MANDATORY_SYSTEM_RID)   return "System";
    // if (rid >= SECURITY_MANDATORY_HIGH_RID)     return "High";
    // if (rid >= SECURITY_MANDATORY_MEDIUM_RID)   return "Medium";
    // return "Low";
    return "?";
}

// ---------- TODO 3: getPrivileges ----------
std::vector<std::string> getPrivileges(HANDLE hToken) {
    std::vector<std::string> result;
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &sz);
    if (!sz) return result;
    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenPrivileges, buf.data(), sz, &sz))
        return result;

    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)buf.data();
    for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
        // YOUR CODE HERE:
        // if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
        //     char name[64] = {}; DWORD nl = sizeof(name);
        //     LookupPrivilegeNameA(nullptr, &tp->Privileges[i].Luid, name, &nl);
        //     result.push_back(name);
        // }
    }
    return result;
}

// ---------- TODO 4: enumerateAll ----------
void enumerateAll() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (!Process32First(hSnap, &pe)) { CloseHandle(hSnap); return; }

    do {
        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProc) continue;

        HANDLE hToken = nullptr;
        if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
            CloseHandle(hProc); continue;
        }

        std::string user      = getTokenUser(hToken);
        std::string integrity = getIntegrityLevel(hToken);
        auto        privs     = getPrivileges(hToken);

        // Check for high-value privileges
        bool hasDebug       = false;
        bool hasImpersonate = false;
        for (auto& p : privs) {
            if (p == "SeDebugPrivilege")       hasDebug = true;
            if (p == "SeImpersonatePrivilege") hasImpersonate = true;
        }

        printf("PID=%-6lu  %-25s  %-30s  %-8s",
               pe.th32ProcessID, pe.szExeFile, user.c_str(), integrity.c_str());
        if (hasDebug)       printf("  [SeDebug]");
        if (hasImpersonate) printf("  [SeImpersonate]");
        printf("\n");

        CloseHandle(hToken);
        CloseHandle(hProc);
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);
}

int main() {
    printf("[*] Token Enumerator — run as Admin for full results\n\n");
    printf("%-10s  %-25s  %-30s  %-8s\n", "PID", "Process", "User", "Integrity");
    printf("%s\n", std::string(80, '-').c_str());
    enumerateAll();
    return 0;
}
