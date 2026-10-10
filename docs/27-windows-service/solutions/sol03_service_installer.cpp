/*
  Solution 03 — Service Installer / Manager
  ------------------------------------------
  Complete service management utility: install, start, stop, query, delete,
  and configure failure-action auto-restart.

  Compile:
    g++ -std=c++17 -Wall -o sol03.exe sol03_service_installer.cpp -ladvapi32
  Usage:
    sol03.exe install   <name> <display> <bin_path> [auto|demand]
    sol03.exe start     <name>
    sol03.exe stop      <name>
    sol03.exe query     <name>
    sol03.exe delete    <name>
    sol03.exe setfailure <name>
*/

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

// ── Helper: open SCM ──────────────────────────────────────────────────────────
static SC_HANDLE openScm(DWORD access) {
    SC_HANDLE h = OpenSCManagerA(NULL, NULL, access);
    if (!h) printf("[-] OpenSCManager failed: %lu\n", GetLastError());
    return h;
}

// ── installService ────────────────────────────────────────────────────────────
bool installService(const char* name, const char* display,
                    const char* binPath, bool autoStart) {
    SC_HANDLE hScm = openScm(SC_MANAGER_CREATE_SERVICE);
    if (!hScm) return false;

    DWORD startType = autoStart ? SERVICE_AUTO_START : SERVICE_DEMAND_START;
    SC_HANDLE hSvc = CreateServiceA(
        hScm, name, display,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        startType,
        SERVICE_ERROR_NORMAL,
        binPath,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        printf("[-] CreateService failed: %lu\n", GetLastError());
        CloseServiceHandle(hScm); return false;
    }
    printf("[+] Service '%s' installed (start: %s)\n", name, autoStart ? "AUTO" : "DEMAND");
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return true;
}

// ── startService ──────────────────────────────────────────────────────────────
bool startService(const char* name) {
    SC_HANDLE hScm = openScm(SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceA(hScm, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) { printf("[-] OpenService: %lu\n", GetLastError()); CloseServiceHandle(hScm); return false; }

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) printf("[*] Service already running\n");
        else printf("[-] StartService: %lu\n", err);
        CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
        return err == ERROR_SERVICE_ALREADY_RUNNING;
    }

    // Poll until RUNNING or timeout
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed;
    for (int i = 0; i < 30; i++) {
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (BYTE*)&ssp, sizeof(ssp), &needed);
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            printf("[+] Service '%s' is RUNNING (PID %lu)\n", name, ssp.dwProcessId);
            break;
        }
        Sleep(500);
    }
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ssp.dwCurrentState == SERVICE_RUNNING;
}

// ── stopService ───────────────────────────────────────────────────────────────
bool stopService(const char* name) {
    SC_HANDLE hScm = openScm(SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceA(hScm, name,
                                   SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) { printf("[-] OpenService: %lu\n", GetLastError()); CloseServiceHandle(hScm); return false; }

    SERVICE_STATUS ss;
    if (!ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) printf("[*] Service not running\n");
        else printf("[-] ControlService(STOP): %lu\n", err);
    }

    // Poll until STOPPED
    SERVICE_STATUS_PROCESS ssp = {}; DWORD needed;
    for (int i = 0; i < 30; i++) {
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (BYTE*)&ssp, sizeof(ssp), &needed);
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            printf("[+] Service '%s' is STOPPED\n", name); break;
        }
        Sleep(500);
    }
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ssp.dwCurrentState == SERVICE_STOPPED;
}

// ── queryService ──────────────────────────────────────────────────────────────
void queryService(const char* name) {
    SC_HANDLE hScm = openScm(SC_MANAGER_CONNECT);
    if (!hScm) return;
    SC_HANDLE hSvc = OpenServiceA(hScm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hSvc) { printf("[-] OpenService: %lu\n", GetLastError()); CloseServiceHandle(hScm); return; }

    SERVICE_STATUS_PROCESS ssp = {}; DWORD needed;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (BYTE*)&ssp, sizeof(ssp), &needed);

    static const char* stateNames[] = {"","STOPPED","START_PENDING","STOP_PENDING",
                                        "RUNNING","CONTINUE_PENDING","PAUSE_PENDING","PAUSED"};
    DWORD s = ssp.dwCurrentState;
    printf("[*] Service: %s\n", name);
    printf("    State:     %s (%lu)\n", s < 8 ? stateNames[s] : "?", s);
    printf("    PID:       %lu\n", ssp.dwProcessId);
    printf("    Checkpoint:%lu\n", ssp.dwCheckPoint);

    // Also print binary path
    DWORD cfgNeeded = 0;
    QueryServiceConfigA(hSvc, NULL, 0, &cfgNeeded);
    if (cfgNeeded > 0) {
        std::string buf(cfgNeeded, '\0');
        auto* cfg = (QUERY_SERVICE_CONFIGA*)buf.data();
        if (QueryServiceConfigA(hSvc, cfg, cfgNeeded, &cfgNeeded))
            printf("    BinPath:   %s\n", cfg->lpBinaryPathName);
    }

    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
}

// ── deleteService ─────────────────────────────────────────────────────────────
bool deleteService(const char* name) {
    stopService(name);  // stop first
    SC_HANDLE hScm = openScm(SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceA(hScm, name, DELETE);
    if (!hSvc) { printf("[-] OpenService: %lu\n", GetLastError()); CloseServiceHandle(hScm); return false; }

    bool ok = DeleteService(hSvc) != 0;
    if (ok) printf("[+] Service '%s' deleted\n", name);
    else printf("[-] DeleteService: %lu\n", GetLastError());
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ok;
}

// ── setFailureActions ─────────────────────────────────────────────────────────
// Configure: restart 3 times with 5s delay, reset counter after 24h.
bool setFailureActions(const char* name) {
    SC_HANDLE hScm = openScm(SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceA(hScm, name, SERVICE_CHANGE_CONFIG);
    if (!hSvc) { printf("[-] OpenService: %lu\n", GetLastError()); CloseServiceHandle(hScm); return false; }

    SC_ACTION actions[3];
    for (int i = 0; i < 3; i++) {
        actions[i].Type  = SC_ACTION_RESTART;
        actions[i].Delay = 5000;  // 5 seconds
    }

    SERVICE_FAILURE_ACTIONSA sfa = {};
    sfa.dwResetPeriod = 86400;  // reset after 24 hours
    sfa.lpRebootMsg   = NULL;
    sfa.lpCommand     = NULL;
    sfa.cActions      = 3;
    sfa.lpsaActions   = actions;

    bool ok = ChangeServiceConfig2A(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa) != 0;
    if (ok) printf("[+] Failure actions set (restart x3, 5s delay, 24h reset)\n");
    else printf("[-] ChangeServiceConfig2: %lu\n", GetLastError());

    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage:\n"
               "  %s install   <name> <display> <binpath> [auto|demand]\n"
               "  %s start     <name>\n"
               "  %s stop      <name>\n"
               "  %s query     <name>\n"
               "  %s delete    <name>\n"
               "  %s setfailure <name>\n",
               argv[0],argv[0],argv[0],argv[0],argv[0],argv[0]);
        return 1;
    }

    const char* verb = argv[1];
    const char* name = argv[2];

    if (!strcmp(verb, "install")) {
        if (argc < 5) { printf("install needs: name display binpath [auto|demand]\n"); return 1; }
        bool autoStart = (argc >= 6 && !strcmp(argv[5], "auto"));
        return installService(name, argv[3], argv[4], autoStart) ? 0 : 1;
    }
    if (!strcmp(verb, "start"))      return startService(name)  ? 0 : 1;
    if (!strcmp(verb, "stop"))       return stopService(name)   ? 0 : 1;
    if (!strcmp(verb, "query"))      { queryService(name); return 0; }
    if (!strcmp(verb, "delete"))     return deleteService(name) ? 0 : 1;
    if (!strcmp(verb, "setfailure")) return setFailureActions(name) ? 0 : 1;

    printf("[-] Unknown verb: %s\n", verb);
    return 1;
}
