/*
  Exercise 03 — Programmatic Service Installer
  ----------------------------------------------
  Build a general-purpose service manager utility that can:
    install   — create a service
    start     — start a service
    stop      — stop a service
    status    — query service state
    delete    — stop + delete a service
    failact   — set failure recovery (auto-restart on crash)

  Tasks:
  1. Implement installService(name, displayName, binPath, startType).
     startType: "auto" / "manual" / "disabled"
  2. Implement startService(name).
  3. Implement stopService(name).
  4. Implement queryService(name) → print SERVICE_STATUS.
  5. Implement deleteService(name).
  6. Implement setFailureActions(name) → configure SC_ACTION_RESTART
     with 3 attempts before giving up.

  Compile:
    g++ -std=c++17 -Wall -o svcmgr.exe ex03_service_installer.cpp -ladvapi32
  Usage:
    svcmgr.exe install  <name> <binPath> [auto|manual|disabled] [displayName]
    svcmgr.exe start    <name>
    svcmgr.exe stop     <name>
    svcmgr.exe status   <name>
    svcmgr.exe delete   <name>
    svcmgr.exe failact  <name>
*/

#include <windows.h>
#include <string>
#include <cstdio>

const char* serviceStateStr(DWORD s) {
    switch (s) {
        case SERVICE_STOPPED:          return "STOPPED";
        case SERVICE_START_PENDING:    return "START_PENDING";
        case SERVICE_STOP_PENDING:     return "STOP_PENDING";
        case SERVICE_RUNNING:          return "RUNNING";
        case SERVICE_PAUSED:           return "PAUSED";
        default:                       return "UNKNOWN";
    }
}

SC_HANDLE openSvcMgr(DWORD access) {
    SC_HANDLE h = OpenSCManagerA(nullptr, nullptr, access);
    if (!h) printf("[-] OpenSCManager: %lu\n", GetLastError());
    return h;
}

SC_HANDLE openSvc(SC_HANDLE hScm, const char* name, DWORD access) {
    SC_HANDLE h = OpenServiceA(hScm, name, access);
    if (!h) printf("[-] OpenService(%s): %lu\n", name, GetLastError());
    return h;
}

// ---------- TODO 1: installService ----------
bool installService(const char* name, const char* displayName,
                    const char* binPath, const char* startType) {
    DWORD st = SERVICE_DEMAND_START;
    if (_stricmp(startType, "auto")     == 0) st = SERVICE_AUTO_START;
    if (_stricmp(startType, "disabled") == 0) st = SERVICE_DISABLED;

    SC_HANDLE hScm = openSvcMgr(SC_MANAGER_CREATE_SERVICE);
    if (!hScm) return false;

    // YOUR CODE HERE:
    // SC_HANDLE hSvc = CreateServiceA(hScm, name, displayName,
    //     SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
    //     st, SERVICE_ERROR_NORMAL, binPath,
    //     nullptr, nullptr, nullptr, nullptr, nullptr);
    // if (!hSvc) { ... }
    // CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    // printf("[+] Installed: %s (%s)\n", name, startType);
    // return true;

    (void)name; (void)displayName; (void)binPath; (void)st;
    CloseServiceHandle(hScm);
    return false;
}

// ---------- TODO 2: startService ----------
bool startService(const char* name) {
    SC_HANDLE hScm = openSvcMgr(SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = openSvc(hScm, name, SERVICE_START);
    if (!hSvc) { CloseServiceHandle(hScm); return false; }
    // YOUR CODE HERE: StartServiceA(hSvc, 0, nullptr);
    bool ok = StartServiceA(hSvc, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    if (ok) printf("[+] Started: %s\n", name);
    else printf("[-] StartService(%s): %lu\n", name, GetLastError());
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ok;
}

// ---------- TODO 3: stopService ----------
bool stopService(const char* name) {
    SC_HANDLE hScm = openSvcMgr(SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = openSvc(hScm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hScm); return false; }
    SERVICE_STATUS ss = {};
    bool ok = ControlService(hSvc, SERVICE_CONTROL_STOP, &ss) == TRUE;
    if (ok) printf("[+] Stop sent to: %s (was %s)\n", name, serviceStateStr(ss.dwCurrentState));
    else printf("[-] ControlService(%s): %lu\n", name, GetLastError());
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ok;
}

// ---------- TODO 4: queryService ----------
void queryService(const char* name) {
    SC_HANDLE hScm = openSvcMgr(SC_MANAGER_CONNECT);
    if (!hScm) return;
    SC_HANDLE hSvc = openSvc(hScm, name, SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hScm); return; }
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                         (BYTE*)&ssp, sizeof(ssp), &needed);
    printf("[*] %s: %s  PID=%lu\n", name, serviceStateStr(ssp.dwCurrentState), ssp.dwProcessId);
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
}

// ---------- TODO 5: deleteService ----------
bool deleteService(const char* name) {
    SC_HANDLE hScm = openSvcMgr(SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = openSvc(hScm, name, DELETE | SERVICE_STOP);
    if (!hSvc) { CloseServiceHandle(hScm); return false; }
    SERVICE_STATUS ss = {};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    Sleep(500);
    bool ok = DeleteService(hSvc) == TRUE;
    if (ok) printf("[+] Deleted: %s\n", name);
    else printf("[-] DeleteService(%s): %lu\n", name, GetLastError());
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ok;
}

// ---------- TODO 6: setFailureActions ----------
bool setFailureActions(const char* name) {
    SC_HANDLE hScm = openSvcMgr(SC_MANAGER_CONNECT);
    SC_HANDLE hSvc = openSvc(hScm, name, SERVICE_CHANGE_CONFIG | SERVICE_START);
    if (!hSvc) { if (hScm) CloseServiceHandle(hScm); return false; }

    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000  },  // restart after 5s on first failure
        { SC_ACTION_RESTART, 10000 },  // restart after 10s on second failure
        { SC_ACTION_NONE,    0     },  // give up on third failure
    };
    SERVICE_FAILURE_ACTIONSA fa = {};
    fa.dwResetPeriod = 86400;  // reset failure count after 24h
    fa.cActions      = 3;
    fa.lpsaActions   = actions;

    bool ok = ChangeServiceConfig2A(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa) == TRUE;
    if (ok) printf("[+] Failure actions set for: %s\n", name);
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage:\n"
               "  svcmgr.exe install  <name> <binPath> [auto|manual] [displayName]\n"
               "  svcmgr.exe start    <name>\n"
               "  svcmgr.exe stop     <name>\n"
               "  svcmgr.exe status   <name>\n"
               "  svcmgr.exe delete   <name>\n"
               "  svcmgr.exe failact  <name>\n");
        return 1;
    }
    const char* cmd  = argv[1];
    const char* name = argv[2];

    if (strcmp(cmd, "install") == 0) {
        if (argc < 4) { printf("install requires binPath\n"); return 1; }
        return installService(name, argc>5?argv[5]:name, argv[3], argc>4?argv[4]:"manual") ? 0 : 1;
    }
    if (strcmp(cmd, "start")   == 0) return startService(name)   ? 0 : 1;
    if (strcmp(cmd, "stop")    == 0) return stopService(name)     ? 0 : 1;
    if (strcmp(cmd, "status")  == 0) { queryService(name); return 0; }
    if (strcmp(cmd, "delete")  == 0) return deleteService(name)   ? 0 : 1;
    if (strcmp(cmd, "failact") == 0) return setFailureActions(name) ? 0 : 1;
    printf("Unknown command: %s\n", cmd);
    return 1;
}
