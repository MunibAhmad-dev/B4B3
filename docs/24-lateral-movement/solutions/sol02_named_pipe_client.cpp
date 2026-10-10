/*
  Solution 02 — Named Pipe Client (Victim Simulator)
  ----------------------------------------------------
  Complete implementation of the pipe client that connects to the
  attacker-controlled pipe, writes a message, and reads the server's reply.

  In a real scenario the "victim" would be a privileged service or SYSTEM
  process tricked into connecting. In this lab we run it manually.

  Compile:
    g++ -std=c++17 -Wall -o sol02_client.exe sol02_named_pipe_client.cpp
  Usage:
    sol02_client.exe [pipeName]
    sol02_client.exe \\.\pipe\TestPipe
  Run sol01_server.exe first, then this client.
*/

#include <windows.h>
#include <string>
#include <cstdio>

// ---- TODO 1: connectToPipe ----
HANDLE connectToPipe(const std::string& pipeName) {
    // Wait up to 5 seconds for the pipe to become available
    if (!WaitNamedPipeA(pipeName.c_str(), 5000)) {
        printf("[-] WaitNamedPipeA failed: %lu\n", GetLastError());
        printf("    Is sol01_server.exe running?\n");
        return INVALID_HANDLE_VALUE;
    }

    // Open a read+write handle to the pipe
    HANDLE h = CreateFileA(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,           // no sharing
        nullptr,     // default security
        OPEN_EXISTING,
        0,           // synchronous I/O (not overlapped)
        nullptr      // no template
    );
    return h;
}

int main(int argc, char* argv[]) {
    const char* pipeName = (argc > 1) ? argv[1] : "\\\\.\\pipe\\TestPipe";

    printf("[*] Named Pipe Client\n");
    printf("[*] Connecting to: %s\n", pipeName);

    HANDLE hPipe = connectToPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to connect: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Connected to pipe!\n");

    // ---- Write a message to the server ----
    const char* msg = "HELLO from client";
    DWORD written = 0;
    if (!WriteFile(hPipe, msg, (DWORD)strlen(msg), &written, nullptr)) {
        printf("[-] WriteFile failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    printf("[*] Sent (%lu bytes): %s\n", written, msg);

    // ---- Read the server's reply ----
    char resp[512] = {};
    DWORD bytesRead = 0;
    if (ReadFile(hPipe, resp, sizeof(resp) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        resp[bytesRead] = '\0';
        printf("[*] Server replied (%lu bytes): %s\n", bytesRead, resp);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
            printf("[*] Server closed the pipe (no reply expected)\n");
        } else {
            printf("[-] ReadFile failed: %lu\n", err);
        }
    }

    CloseHandle(hPipe);
    printf("[*] Disconnected\n");
    return 0;
}
