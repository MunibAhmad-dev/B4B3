/*
  Exercise 02 — Service ↔ GUI IPC via Named Pipe
  -------------------------------------------------
  Services run in Session 0 (isolated from user desktops). To communicate
  with a user's application you need IPC. Named pipes are ideal:
    - Bidirectional
    - Low latency
    - Built into Windows (no extra dependencies)
    - Support impersonation for security

  Architecture:
    Service (server)  → creates \\.\pipe\HeartbeatCtrl
    GUI client        → connects, sends command, receives response

  Commands:
    "STATUS"   → service responds with current uptime + heartbeat count
    "STOP"     → service sets g_Running = false
    "LOG"      → service flushes and returns last 5 log lines
    "PING"     → service responds "PONG"

  Tasks:
  1. In the service's worker thread, create the named pipe and listen.
  2. For each incoming connection, read the command string, dispatch,
     write the response, disconnect.
  3. Build a client (separate main or compile with #define CLIENT):
     connect to the pipe, send a command, print the response.
  4. Integrate with the service from ex01 (call pipeWorker from ServiceMain
     in a separate thread).

  Compile service:
    g++ -std=c++17 -o service.exe ex02_service_pipe_ipc.cpp -ladvapi32
  Compile client:
    g++ -std=c++17 -DCLIENT -o client.exe ex02_service_pipe_ipc.cpp
  Usage:
    service.exe --install && sc start HeartbeatSvc
    client.exe STATUS
    client.exe STOP
*/

#include <windows.h>
#include <string>
#include <fstream>
#include <atomic>
#include <thread>
#include <cstdio>
#include <ctime>

static const char* PIPE_NAME = "\\\\.\\pipe\\HeartbeatCtrl";
static std::atomic<DWORD> g_uptimeSeconds{0};
static std::atomic<DWORD> g_heartbeatCount{0};
static std::atomic<bool>  g_Running{true};

// ---------- TODO 1+2: Pipe server worker ----------
void pipeWorker() {
    while (g_Running) {
        // YOUR CODE HERE:
        // HANDLE hPipe = CreateNamedPipeA(PIPE_NAME, PIPE_ACCESS_DUPLEX,
        //     PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
        // if (hPipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        //
        // if (!ConnectNamedPipe(hPipe, nullptr)) { CloseHandle(hPipe); continue; }
        //
        // char cmd[256] = {};
        // DWORD bytesRead = 0;
        // ReadFile(hPipe, cmd, sizeof(cmd)-1, &bytesRead, nullptr);
        // cmd[bytesRead] = '\0';
        //
        // std::string response;
        // if (strcmp(cmd, "PING") == 0)   response = "PONG";
        // else if (strcmp(cmd, "STATUS") == 0)
        //     response = "Uptime=" + std::to_string(g_uptimeSeconds.load()) +
        //                "s  Heartbeats=" + std::to_string(g_heartbeatCount.load());
        // else if (strcmp(cmd, "STOP") == 0) { g_Running = false; response = "STOPPING"; }
        // else response = "UNKNOWN COMMAND";
        //
        // DWORD written = 0;
        // WriteFile(hPipe, response.c_str(), (DWORD)response.size(), &written, nullptr);
        // DisconnectNamedPipe(hPipe);
        // CloseHandle(hPipe);

        Sleep(1000); // remove when implemented
    }
}

#ifdef CLIENT

// ---------- TODO 3: Client ----------
int main(int argc, char* argv[]) {
    const char* cmd = argc > 1 ? argv[1] : "PING";
    printf("[*] Sending command: %s\n", cmd);

    // YOUR CODE HERE:
    // if (!WaitNamedPipeA(PIPE_NAME, 5000)) { printf("[-] No pipe\n"); return 1; }
    // HANDLE h = CreateFileA(PIPE_NAME, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    // WriteFile(h, cmd, strlen(cmd), ...);
    // char resp[4096]={};
    // DWORD read=0;
    // ReadFile(h, resp, sizeof(resp)-1, &read, nullptr);
    // printf("[*] Response: %s\n", resp);
    // CloseHandle(h);

    printf("[-] Client not implemented yet\n");
    return 0;
}

#else

// Minimal service entry point for testing
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("[*] Starting pipe server on %s\n", PIPE_NAME);
    printf("[*] Use client.exe to send commands\n");
    printf("[*] Press Ctrl+C to stop\n");
    std::thread worker(pipeWorker);
    worker.join();
    return 0;
}

#endif
