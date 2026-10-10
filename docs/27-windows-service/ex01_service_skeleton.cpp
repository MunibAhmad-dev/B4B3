/*
  Exercise 01 — Windows Service Skeleton
  ----------------------------------------
  Build a complete Windows service that:
  1. Installs itself when run with --install flag
  2. Uninstalls itself when run with --uninstall flag
  3. When running as a service: writes a heartbeat log every 30 seconds
  4. Stops cleanly on sc stop

  Usage:
    ex01.exe --install     → registers the service
    sc start HeartbeatSvc  → starts it (or: ex01.exe --start)
    sc stop  HeartbeatSvc  → stops it
    ex01.exe --uninstall   → removes it

  Log file: C:\Windows\Temp\heartbeat.log
  Each line: "2026-10-01T12:34:56  [HEARTBEAT] alive  PID=1234  Uptime=30s"

  Tasks:
  1. Implement installService() — use OpenSCManager + CreateService.
  2. Implement uninstallService() — use OpenService + DeleteService.
  3. Complete ServiceMain() — call RegisterServiceCtrlHandlerEx,
     set SERVICE_RUNNING, then loop writing heartbeats until g_Running = false.
  4. Complete ServiceCtrlHandler() — handle SERVICE_CONTROL_STOP.

  BONUS:
  - Add SERVICE_CONTROL_INTERROGATE handling (query current status).
  - Make the service restart automatically on crash:
    SetServiceFailureActions with SC_ACTION_RESTART.
  - Write events to Windows Event Log (RegisterEventSource, ReportEvent).

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_service_skeleton.cpp -ladvapi32
*/

#include <windows.h>
#include <fstream>
#include <string>
#include <atomic>
#include <ctime>
#include <iomanip>
#include <sstream>

static const char* SERVICE_NAME = "HeartbeatSvc";
static const char* LOG_PATH     = "C:\\Windows\\Temp\\heartbeat.log";

static SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
static SERVICE_STATUS        g_Status       = {};
static std::atomic<bool>     g_Running{true};

void logLine(const std::string& msg) {
    auto t = std::time(nullptr); char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", std::localtime(&t));
    std::ofstream f(LOG_PATH, std::ios::app);
    f << ts << "  " << msg << "\n";
}

void setStatus(DWORD state, DWORD checkPoint = 0) {
    g_Status.dwCurrentState = state;
    g_Status.dwCheckPoint   = checkPoint;
    SetServiceStatus(g_StatusHandle, &g_Status);
}

// TODO: Handle SCM control codes (SERVICE_CONTROL_STOP etc.)
DWORD WINAPI ServiceCtrlHandler(DWORD ctrl, DWORD eventType,
                                 LPVOID eventData, LPVOID context) {
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(eventData);
    UNREFERENCED_PARAMETER(context);

    if (ctrl == SERVICE_CONTROL_STOP) {
        setStatus(SERVICE_STOP_PENDING);
        // TODO: set g_Running = false
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

// TODO: Complete ServiceMain
VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // Register control handler
    g_StatusHandle = RegisterServiceCtrlHandlerExA(
        SERVICE_NAME, ServiceCtrlHandler, nullptr);
    if (!g_StatusHandle) return;

    // Configure status
    g_Status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_Status.dwWin32ExitCode    = NO_ERROR;
    g_Status.dwWaitHint         = 3000;

    setStatus(SERVICE_START_PENDING, 1);
    logLine("[SERVICE] Starting...");

    setStatus(SERVICE_RUNNING);
    logLine("[SERVICE] Running");

    DWORD uptime = 0;
    while (g_Running) {
        // TODO: sleep in small increments so stop is responsive
        // Sleep(1000) in a loop, check g_Running each second, report every 30s
        Sleep(30000);
        uptime += 30;

        char pid[32];
        sprintf_s(pid, "%lu", GetCurrentProcessId());
        logLine(std::string("[HEARTBEAT] alive  PID=") + pid +
                "  Uptime=" + std::to_string(uptime) + "s");
    }

    logLine("[SERVICE] Stopping");
    setStatus(SERVICE_STOPPED);
}

// TODO: Implement installService()
bool installService() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) { printf("[-] OpenSCManager: %lu\n", GetLastError()); return false; }

    // YOUR CODE HERE: CreateServiceA(...)
    SC_HANDLE hSvc = nullptr; // replace with CreateServiceA

    if (!hSvc) {
        printf("[-] CreateService: %lu\n", GetLastError());
        CloseServiceHandle(hScm); return false;
    }
    printf("[+] Service installed: %s\n", SERVICE_NAME);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

// TODO: Implement uninstallService()
bool uninstallService() {
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;

    SC_HANDLE hSvc = OpenServiceA(hScm, SERVICE_NAME, DELETE | SERVICE_STOP);
    if (!hSvc) { CloseServiceHandle(hScm); return false; }

    // TODO: stop it first, then DeleteService
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    printf("[+] Service removed\n");
    return true;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--install")   == 0) return installService()   ? 0 : 1;
        if (strcmp(argv[1], "--uninstall") == 0) return uninstallService() ? 0 : 1;
    }

    // Run as service (called by SCM)
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)SERVICE_NAME, ServiceMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherA(table)) {
        printf("StartServiceCtrlDispatcher failed: %lu\n", GetLastError());
        printf("Run with --install to install, or start via sc.exe\n");
        return 1;
    }
    return 0;
}
