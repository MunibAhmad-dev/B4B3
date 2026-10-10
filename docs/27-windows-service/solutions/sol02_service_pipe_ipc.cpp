/*
  Solution 02 — Windows Service with Named-Pipe IPC
  --------------------------------------------------
  Service side creates a named pipe and handles STATUS/STOP/LOG/PING commands.
  Client side (#define SERVICE_CLIENT) connects and sends a command.

  Compile service:
    g++ -std=c++17 -Wall -o sol02_service.exe sol02_service_pipe_ipc.cpp -ladvapi32
  Compile client:
    g++ -std=c++17 -Wall -DSERVICE_CLIENT -o sol02_client.exe sol02_service_pipe_ipc.cpp -ladvapi32
  Usage (service):
    sol02_service.exe install   # then: sc start PipeDemoService
  Usage (client):
    sol02_client.exe STATUS
    sol02_client.exe PING
    sol02_client.exe LOG "test message"
    sol02_client.exe STOP
*/

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <ctime>

#define PIPE_NAME     "\\\\.\\pipe\\ServiceCtrl"
#define SERVICE_NAME  "PipeDemoService"
#define LOG_FILE      "C:\\Windows\\Temp\\PipeDemoService.log"

// ─────────────────────────────────────────────────────────────────────────────
#ifdef SERVICE_CLIENT
// ── CLIENT SIDE ──────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: %s <STATUS|STOP|LOG|PING> [arg]\n", argv[0]); return 1; }

    // Build command string
    std::string cmd = argv[1];
    if (argc >= 3) { cmd += " "; cmd += argv[2]; }

    // Wait for pipe and connect
    if (!WaitNamedPipeA(PIPE_NAME, 5000)) {
        printf("[-] Pipe not available (is service running?): %lu\n", GetLastError());
        return 1;
    }

    HANDLE hPipe = CreateFileA(PIPE_NAME,
                                GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed: %lu\n", GetLastError()); return 1;
    }

    // Switch to message mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);

    // Send command
    DWORD written;
    WriteFile(hPipe, cmd.c_str(), (DWORD)cmd.size(), &written, NULL);

    // Read response
    char buf[2048] = {};
    DWORD read;
    if (ReadFile(hPipe, buf, sizeof(buf)-1, &read, NULL))
        printf("[*] Response: %s\n", buf);
    else
        printf("[*] No response (STOP may have closed the pipe)\n");

    CloseHandle(hPipe);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
#else
// ── SERVICE SIDE ─────────────────────────────────────────────────────────────

static SERVICE_STATUS_HANDLE g_hStatus = NULL;
static volatile BOOL g_Running = TRUE;
static SERVICE_STATUS g_Status = {};

static void setStatus(DWORD state, DWORD checkpoint = 0) {
    g_Status.dwCurrentState  = state;
    g_Status.dwCheckPoint    = checkpoint;
    SetServiceStatus(g_hStatus, &g_Status);
}

static void appendLog(const std::string& msg) {
    std::ofstream f(LOG_FILE, std::ios::app);
    if (!f) return;
    time_t t = time(NULL);
    char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    f << "[" << ts << "] " << msg << "\n";
}

// ── pipeWorker: runs in a separate thread, handles IPC commands ───────────────
static DWORD WINAPI pipeWorker(LPVOID) {
    while (g_Running) {
        HANDLE hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 1024, 1024, 0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000); continue;
        }

        // Wait for a client (with timeout so we can check g_Running)
        OVERLAPPED ov = {}; ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        ConnectNamedPipe(hPipe, &ov);
        DWORD ret = WaitForSingleObject(ov.hEvent, 2000);
        CloseHandle(ov.hEvent);

        if (ret != WAIT_OBJECT_0 && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe); continue;
        }

        // Read command
        char buf[1024] = {};
        DWORD read;
        if (!ReadFile(hPipe, buf, sizeof(buf)-1, &read, NULL)) {
            DisconnectNamedPipe(hPipe); CloseHandle(hPipe); continue;
        }

        std::string cmd(buf, read);
        std::string response;

        if (cmd == "STATUS") {
            char status[256];
            snprintf(status, sizeof(status),
                     "Service: RUNNING  State: %lu  PID: %lu",
                     g_Status.dwCurrentState, GetCurrentProcessId());
            response = status;

        } else if (cmd == "PING") {
            response = "PONG";

        } else if (cmd.substr(0, 3) == "LOG") {
            std::string msg = cmd.size() > 4 ? cmd.substr(4) : "(empty)";
            appendLog(msg);
            response = "Logged: " + msg;

        } else if (cmd == "STOP") {
            response = "Stopping service";
            DWORD w; WriteFile(hPipe, response.c_str(), (DWORD)response.size(), &w, NULL);
            DisconnectNamedPipe(hPipe); CloseHandle(hPipe);
            g_Running = FALSE;
            setStatus(SERVICE_STOP_PENDING, 1);
            return 0;

        } else {
            response = "Unknown command: " + cmd;
        }

        DWORD written;
        WriteFile(hPipe, response.c_str(), (DWORD)response.size(), &written, NULL);
        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}

// ── Service control handler ───────────────────────────────────────────────────
static VOID WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        setStatus(SERVICE_STOP_PENDING, 1);
        g_Running = FALSE;
    } else if (ctrl == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(g_hStatus, &g_Status);
    }
}

// ── ServiceMain ───────────────────────────────────────────────────────────────
static VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    (void)argc; (void)argv;

    g_hStatus = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_hStatus) return;

    g_Status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_Status.dwWaitHint                = 3000;
    setStatus(SERVICE_START_PENDING, 1);

    HANDLE hWorker = CreateThread(NULL, 0, pipeWorker, NULL, 0, NULL);

    setStatus(SERVICE_RUNNING);
    appendLog("Service started");

    while (g_Running) Sleep(1000);

    appendLog("Service stopping");
    WaitForSingleObject(hWorker, 5000);
    CloseHandle(hWorker);
    setStatus(SERVICE_STOPPED);
}

// ── install / uninstall helpers ───────────────────────────────────────────────
static void installService() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) { printf("[-] OpenSCManager: %lu\n", GetLastError()); return; }

    SC_HANDLE hSvc = CreateServiceA(hScm, SERVICE_NAME, "Pipe Demo Service",
                                    SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                    path, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) printf("[-] CreateService: %lu\n", GetLastError());
    else { printf("[+] Installed. Run: sc start %s\n", SERVICE_NAME); CloseServiceHandle(hSvc); }
    CloseServiceHandle(hScm);
}

static void uninstallService() {
    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE hSvc = OpenServiceA(hScm, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (hSvc) {
        SERVICE_STATUS ss; ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(hSvc); CloseServiceHandle(hSvc);
        printf("[+] Service removed\n");
    }
    CloseServiceHandle(hScm);
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && strcmp(argv[1], "install")   == 0) { installService();   return 0; }
    if (argc >= 2 && strcmp(argv[1], "uninstall") == 0) { uninstallService(); return 0; }

    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };
    if (!StartServiceCtrlDispatcherA(table))
        printf("[-] StartServiceCtrlDispatcher: %lu (run as service or use 'install')\n", GetLastError());
    return 0;
}
#endif
