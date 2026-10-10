// service_manager.cpp — Windows service management toolkit
// Compile: g++ -std=c++17 -o service_manager.exe service_manager.cpp -ladvapi32
// Usage: service_manager.exe install | start | stop | query | delete | list | scan | pipe-ipc

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>

// Demo service name/binary
static const char* SVC_NAME    = "DemoService";
static const char* SVC_DISPLAY = "Demo Security Service";
static const char* PIPE_NAME   = "\\\\.\\pipe\\ServiceIPC";

// ─── Helpers ─────────────────────────────────────────────────────────────────

static SC_HANDLE open_scm(DWORD access = SC_MANAGER_ALL_ACCESS) {
    SC_HANDLE h = OpenSCManagerA(nullptr, nullptr, access);
    if (!h) fprintf(stderr, "[!] OpenSCManager failed: %lu\n", GetLastError());
    return h;
}

static SC_HANDLE open_svc(SC_HANDLE hScm, const char* name, DWORD access = SERVICE_ALL_ACCESS) {
    SC_HANDLE h = OpenServiceA(hScm, name, access);
    if (!h) fprintf(stderr, "[!] OpenService(%s) failed: %lu\n", name, GetLastError());
    return h;
}

// ─── install ─────────────────────────────────────────────────────────────────

static void cmd_install() {
    char self[MAX_PATH]{};
    GetModuleFileNameA(nullptr, self, MAX_PATH);

    SC_HANDLE hScm = open_scm(); if (!hScm) return;
    SC_HANDLE hSvc = CreateServiceA(hScm, SVC_NAME, SVC_DISPLAY,
                                    SERVICE_ALL_ACCESS,
                                    SERVICE_WIN32_OWN_PROCESS,
                                    SERVICE_DEMAND_START,
                                    SERVICE_ERROR_NORMAL,
                                    self,
                                    nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) printf("[*] Service already installed\n");
        else fprintf(stderr, "[!] CreateService failed: %lu\n", e);
    } else {
        printf("[+] Installed: %s -> %s\n", SVC_NAME, self);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
}

// ─── start ────────────────────────────────────────────────────────────────────

static void cmd_start() {
    SC_HANDLE hScm = open_scm(); if (!hScm) return;
    SC_HANDLE hSvc = open_svc(hScm, SVC_NAME); if (!hSvc) { CloseServiceHandle(hScm); return; }
    if (!StartServiceA(hSvc, 0, nullptr)) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING) printf("[*] Already running\n");
        else fprintf(stderr, "[!] StartService failed: %lu\n", e);
    } else printf("[+] Started %s\n", SVC_NAME);
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
}

// ─── stop ─────────────────────────────────────────────────────────────────────

static void cmd_stop() {
    SC_HANDLE hScm = open_scm(); if (!hScm) return;
    SC_HANDLE hSvc = open_svc(hScm, SVC_NAME); if (!hSvc) { CloseServiceHandle(hScm); return; }
    SERVICE_STATUS ss{};
    if (!ControlService(hSvc, SERVICE_CONTROL_STOP, &ss))
        fprintf(stderr, "[!] ControlService(STOP) failed: %lu\n", GetLastError());
    else printf("[+] Stop signal sent\n");
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
}

// ─── query ────────────────────────────────────────────────────────────────────

static void cmd_query() {
    SC_HANDLE hScm = open_scm(); if (!hScm) return;
    SC_HANDLE hSvc = open_svc(hScm, SVC_NAME); if (!hSvc) { CloseServiceHandle(hScm); return; }
    SERVICE_STATUS ss{};
    if (QueryServiceStatus(hSvc, &ss)) {
        const char* state;
        switch (ss.dwCurrentState) {
            case SERVICE_STOPPED:          state = "STOPPED"; break;
            case SERVICE_START_PENDING:    state = "START_PENDING"; break;
            case SERVICE_STOP_PENDING:     state = "STOP_PENDING"; break;
            case SERVICE_RUNNING:          state = "RUNNING"; break;
            case SERVICE_PAUSE_PENDING:    state = "PAUSE_PENDING"; break;
            case SERVICE_PAUSED:           state = "PAUSED"; break;
            default:                       state = "UNKNOWN";
        }
        printf("Service: %s  State: %s  PID: %lu\n", SVC_NAME, state, ss.dwWin32ExitCode);
    }
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
}

// ─── delete ───────────────────────────────────────────────────────────────────

static void cmd_delete() {
    SC_HANDLE hScm = open_scm(); if (!hScm) return;
    SC_HANDLE hSvc = open_svc(hScm, SVC_NAME); if (!hSvc) { CloseServiceHandle(hScm); return; }
    if (!DeleteService(hSvc)) fprintf(stderr, "[!] DeleteService failed: %lu\n", GetLastError());
    else printf("[+] Deleted %s\n", SVC_NAME);
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
}

// ─── list ─────────────────────────────────────────────────────────────────────

static void cmd_list() {
    SC_HANDLE hScm = open_scm(SC_MANAGER_ENUMERATE_SERVICE); if (!hScm) return;
    DWORD bytes = 0, count = 0, handle = 0;
    EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0, &bytes, &count, &handle, nullptr);
    std::vector<BYTE> buf(bytes);
    EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, buf.data(), bytes, &bytes, &count, &handle, nullptr);
    auto* svcs = (ENUM_SERVICE_STATUS_PROCESSA*)buf.data();
    printf("%-40s  %-12s  %s\n", "Name", "State", "Display");
    printf("%s\n", std::string(80, '-').c_str());
    for (DWORD i = 0; i < count; ++i) {
        const char* state;
        switch (svcs[i].ServiceStatusProcess.dwCurrentState) {
            case SERVICE_RUNNING: state = "RUNNING"; break;
            case SERVICE_STOPPED: state = "STOPPED"; break;
            default: state = "OTHER";
        }
        printf("  %-38s  %-12s  %s\n",
               svcs[i].lpServiceName, state, svcs[i].lpDisplayName);
    }
    CloseServiceHandle(hScm);
}

// ─── scan: flag non-system service binaries ───────────────────────────────────

static void cmd_scan() {
    printf("[*] Scanning for non-system service paths\n\n");
    SC_HANDLE hScm = open_scm(SC_MANAGER_ENUMERATE_SERVICE); if (!hScm) return;
    DWORD bytes = 0, count = 0, handle = 0;
    EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0, &bytes, &count, &handle, nullptr);
    std::vector<BYTE> buf(bytes);
    EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, buf.data(), bytes, &bytes, &count, &handle, nullptr);
    auto* svcs = (ENUM_SERVICE_STATUS_PROCESSA*)buf.data();
    char sysroot[MAX_PATH]{};
    GetEnvironmentVariableA("SystemRoot", sysroot, MAX_PATH);
    std::string syslow(sysroot);
    for (auto& c : syslow) c = (char)tolower(c);

    for (DWORD i = 0; i < count; ++i) {
        SC_HANDLE hSvc = OpenServiceA(hScm, svcs[i].lpServiceName,
                                      SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;
        DWORD cb = 0;
        QueryServiceConfigA(hSvc, nullptr, 0, &cb);
        std::vector<BYTE> cfg(cb);
        if (QueryServiceConfigA(hSvc, (QUERY_SERVICE_CONFIGA*)cfg.data(), cb, &cb)) {
            auto* qsc = (QUERY_SERVICE_CONFIGA*)cfg.data();
            if (qsc->lpBinaryPathName) {
                std::string bp(qsc->lpBinaryPathName);
                std::string bplow = bp;
                for (auto& c : bplow) c = (char)tolower(c);
                if (bplow.find(syslow) == std::string::npos) {
                    printf("  [NON-SYS] %-35s  %s\n",
                           svcs[i].lpServiceName, qsc->lpBinaryPathName);
                }
            }
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
}

// ─── pipe-ipc: simple IPC demo over named pipe ───────────────────────────────

static void cmd_pipe_ipc() {
    printf("[*] Named pipe IPC server: %s\n", PIPE_NAME);
    printf("    Waiting for connection...\n");

    HANDLE hPipe = CreateNamedPipeA(PIPE_NAME,
                                    PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                    1, 4096, 4096, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] CreateNamedPipe failed: %lu\n", GetLastError()); return;
    }
    ConnectNamedPipe(hPipe, nullptr);
    printf("[+] Client connected\n");

    char buf[4096]{};
    DWORD rd = 0;
    while (ReadFile(hPipe, buf, sizeof(buf)-1, &rd, nullptr) && rd > 0) {
        buf[rd] = 0;
        printf("[ipc] recv: %s\n", buf);
        const char* resp = "SERVICE_OK";
        DWORD wr = 0;
        WriteFile(hPipe, resp, (DWORD)strlen(resp), &wr, nullptr);
    }
    CloseHandle(hPipe);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  service_manager.exe install | start | stop | query | delete\n"
               "                         list | scan | pipe-ipc\n"
               "  (install/start/stop/query/delete operate on service: %s)\n", SVC_NAME);
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "install")   cmd_install();
    else if (cmd == "start")     cmd_start();
    else if (cmd == "stop")      cmd_stop();
    else if (cmd == "query")     cmd_query();
    else if (cmd == "delete")    cmd_delete();
    else if (cmd == "list")      cmd_list();
    else if (cmd == "scan")      cmd_scan();
    else if (cmd == "pipe-ipc")  cmd_pipe_ipc();
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
