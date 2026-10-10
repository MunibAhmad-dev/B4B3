/*
  Exercise 02 — Named Pipe Client (Victim Simulator)
  ----------------------------------------------------
  This is the "victim" process that connects to the attacker's pipe.
  In a real scenario, a Windows service or SYSTEM process would be
  tricked into connecting via:
    - Print Spooler exploit (SpoolSample)
    - DCOM/COM coercion
    - UNC path in a file operation
    - A shortcut (.lnk) pointing to \\.\pipe\AttackerPipe

  In this lab: run this manually after ex01_named_pipe_server.exe is waiting.

  Tasks:
  1. Implement connectToPipe(pipeName) — WaitNamedPipeA + CreateFileA.
  2. Write a small message to the pipe ("hello from victim").
  3. Read the server's response (optional, server may not reply).
  4. Close and exit.

  Compile:
    g++ -std=c++17 -Wall -o client.exe ex02_named_pipe_client.cpp
  Usage:
    client.exe [pipeName]
    client.exe \\.\pipe\TestImpersonation
*/

#include <windows.h>
#include <string>
#include <cstdio>

// ---------- TODO 1: connectToPipe ----------
HANDLE connectToPipe(const std::string& pipeName) {
    // YOUR CODE HERE:
    // Step 1: wait until the pipe is available
    // if (!WaitNamedPipeA(pipeName.c_str(), 5000)) return INVALID_HANDLE_VALUE;
    //
    // Step 2: open a handle to the pipe
    // return CreateFileA(
    //     pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
    //     0, nullptr, OPEN_EXISTING, 0, nullptr);
    (void)pipeName;
    return INVALID_HANDLE_VALUE;
}

int main(int argc, char* argv[]) {
    const char* pipeName = argc > 1 ? argv[1] : "\\\\.\\pipe\\TestImpersonation";
    printf("[*] Connecting to pipe: %s\n", pipeName);

    HANDLE hPipe = connectToPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] connectToPipe not implemented or failed: %lu\n", GetLastError());
        printf("    Is the server running? Start ex01 first.\n");
        return 1;
    }
    printf("[+] Connected!\n");

    // Write a message so the server knows we're here
    const char* msg = "hello from victim";
    DWORD written = 0;
    WriteFile(hPipe, msg, (DWORD)strlen(msg), &written, nullptr);
    printf("[*] Sent: %s\n", msg);

    // Read server response (may not reply)
    char resp[256] = {};
    DWORD read = 0;
    if (ReadFile(hPipe, resp, sizeof(resp)-1, &read, nullptr) && read > 0)
        printf("[*] Server replied: %s\n", resp);

    CloseHandle(hPipe);
    printf("[*] Disconnected\n");
    return 0;
}
