/*
  Solution 01 — Windows Service Skeleton (complete)
*/
#pragma comment(lib, "advapi32.lib")
#include <windows.h>
#include <fstream>
#include <string>
#include <atomic>
#include <ctime>

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

DWORD WINAPI ServiceCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        setStatus(SERVICE_STOP_PENDING);
        g_Running = false;
        return NO_ERROR;
    }
    if (ctrl == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(g_StatusHandle, &g_Status);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

VOID WINAPI ServiceMain(DWORD, LPSTR*) {
    g_StatusHandle = RegisterServiceCtrlHandlerExA(SERVICE_NAME, ServiceCtrlHandler, nullptr);
    if (!g_StatusHandle) return;

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
        for (int i = 0; i < 30 && g_Running; i++) Sleep(1000);
        if (!g_Running) break;
        uptime += 30;
        char pid[32]; sprintf_s(pid, "%lu", GetCurrentProcessId());
        logLine(std::string("[HEARTBEAT] alive  PID=") + pid +
                "  Uptime=" + std::to_string(uptime) + "s");
    }

    logLine("[SERVICE] Stopping");
    setStatus(SERVICE_STOPPED);
}

bool installService() {
    char path[MAX_PATH]; GetModuleFileNameA(nullptr, path, MAX_PATH);
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) return false;
    SC_HANDLE hSvc = CreateServiceA(
        hScm, SERVICE_NAME, "Heartbeat Service",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        path, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) { DWORD e=GetLastError(); CloseServiceHandle(hScm);
        printf("[-] CreateService: %lu\n",e); return false; }
    printf("[+] Service installed: %s\n", SERVICE_NAME);
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return true;
}

bool uninstallService() {
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceA(hScm, SERVICE_NAME, DELETE | SERVICE_STOP);
    if (!hSvc) { CloseServiceHandle(hScm); return false; }
    SERVICE_STATUS ss = {};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    Sleep(1000);
    DeleteService(hSvc);
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    printf("[+] Service removed\n");
    return true;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--install")   == 0) return installService()   ? 0 : 1;
        if (strcmp(argv[1], "--uninstall") == 0) return uninstallService() ? 0 : 1;
    }
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)SERVICE_NAME, ServiceMain }, { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherA(table);
    return 0;
}
