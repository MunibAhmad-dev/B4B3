/*
  Solution 04 — Service-Based Persistence Simulation
  ----------------------------------------------------
  Demonstrates how malware uses auto-start services for persistence, and how
  defenders detect and remove such services.

  EDUCATIONAL USE ONLY — run in a lab VM, clean up with the 'remove' verb.

  Compile:
    g++ -std=c++17 -Wall -o sol04.exe sol04_service_persistence_sim.cpp -ladvapi32
  Usage:
    sol04.exe install   [service_name]   # simulate malware dropping + installing
    sol04.exe detect                     # blue-team: find suspicious services
    sol04.exe remove    [service_name]   # clean up
*/

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

#define DEFAULT_NAME   "SvcHelper64"
#define DEFAULT_DISPLAY "Windows Service Helper"

// ── installPersistence ────────────────────────────────────────────────────────
// Simulates a dropper: copy binary to Temp, register as AUTO_START service.
bool installPersistence(const char* serviceName) {
    // 1. Get own exe path
    char srcPath[MAX_PATH];
    GetModuleFileNameA(NULL, srcPath, MAX_PATH);

    // 2. Build drop path in %TEMP%
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    char dropPath[MAX_PATH];
    snprintf(dropPath, MAX_PATH, "%s%s.exe", tempDir, serviceName);

    // 3. Copy to drop location
    if (!CopyFileA(srcPath, dropPath, FALSE)) {
        printf("[-] CopyFile to %s failed: %lu\n", dropPath, GetLastError());
        return false;
    }
    printf("[*] Dropped to: %s\n", dropPath);

    // 4. Install as AUTO_START service
    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) { printf("[-] OpenSCManager: %lu\n", GetLastError()); return false; }

    SC_HANDLE hSvc = CreateServiceA(
        hScm, serviceName, DEFAULT_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,            // survives reboots
        SERVICE_ERROR_IGNORE,          // don't nag if it fails to start
        dropPath,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        printf("[-] CreateService: %lu\n", GetLastError());
        CloseServiceHandle(hScm); return false;
    }

    printf("[+] Persistence installed: service '%s' → %s (AUTO_START)\n", serviceName, dropPath);
    printf("[*] This binary will auto-start on next boot.\n");

    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return true;
}

// ── detectSuspiciousServices ──────────────────────────────────────────────────
// Blue-team: enumerate all services, flag those with binaries outside trusted paths.
void detectSuspiciousServices() {
    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) { printf("[-] OpenSCManager: %lu\n", GetLastError()); return; }

    DWORD needed = 0, count = 0, resumeHandle = 0;
    EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO,
                          SERVICE_WIN32, SERVICE_STATE_ALL,
                          NULL, 0, &needed, &count, &resumeHandle, NULL);

    std::string buf(needed, '\0');
    if (!EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO,
                               SERVICE_WIN32, SERVICE_STATE_ALL,
                               (BYTE*)buf.data(), needed, &needed, &count, &resumeHandle, NULL)) {
        printf("[-] EnumServicesStatusEx: %lu\n", GetLastError());
        CloseServiceHandle(hScm); return;
    }

    printf("\n[*] Scanning %lu services for suspicious binary paths...\n\n", count);
    int suspects = 0;

    auto* entries = (ENUM_SERVICE_STATUS_PROCESSA*)buf.data();
    for (DWORD i = 0; i < count; i++) {
        SC_HANDLE hSvc = OpenServiceA(hScm, entries[i].lpServiceName,
                                       SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD cfgNeeded = 0;
        QueryServiceConfigA(hSvc, NULL, 0, &cfgNeeded);
        if (!cfgNeeded) { CloseServiceHandle(hSvc); continue; }

        std::string cfgBuf(cfgNeeded, '\0');
        auto* cfg = (QUERY_SERVICE_CONFIGA*)cfgBuf.data();
        if (!QueryServiceConfigA(hSvc, cfg, cfgNeeded, &cfgNeeded)) {
            CloseServiceHandle(hSvc); continue;
        }

        std::string binPath = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "";
        // Strip leading quotes
        if (!binPath.empty() && binPath[0] == '"') {
            binPath = binPath.substr(1, binPath.find('"', 1) - 1);
        }
        // Strip svchost args like "svchost.exe -k netsvcs"
        auto space = binPath.find(' ');
        if (space != std::string::npos) binPath = binPath.substr(0, space);

        // Trusted locations (case-insensitive check)
        auto lowerPath = binPath;
        for (auto& c : lowerPath) c = tolower(c);

        bool trusted = lowerPath.find("\\windows\\") != std::string::npos ||
                       lowerPath.find("\\program files\\") != std::string::npos ||
                       lowerPath.find("\\program files (x86)\\") != std::string::npos ||
                       lowerPath.empty();

        bool suspicious = !trusted && (
            lowerPath.find("\\temp\\")    != std::string::npos ||
            lowerPath.find("\\appdata\\") != std::string::npos ||
            lowerPath.find("\\users\\")   != std::string::npos
        );

        if (suspicious) {
            suspects++;
            DWORD state = entries[i].ServiceStatusProcess.dwCurrentState;
            printf("[SUSPICIOUS] %s\n", entries[i].lpServiceName);
            printf("  DisplayName: %s\n", entries[i].lpDisplayName);
            printf("  BinaryPath:  %s\n", binPath.c_str());
            printf("  State:       %s\n", state == SERVICE_RUNNING ? "RUNNING" :
                                          state == SERVICE_STOPPED ? "STOPPED" : "OTHER");
            printf("  StartType:   %s\n",
                   cfg->dwStartType == SERVICE_AUTO_START   ? "AUTO_START" :
                   cfg->dwStartType == SERVICE_DEMAND_START ? "DEMAND_START" : "OTHER");
            printf("\n");
        }

        CloseServiceHandle(hSvc);
    }

    if (suspects == 0)
        printf("[=] No suspicious services found (all binaries in trusted paths)\n");
    else
        printf("[!] Found %d suspicious service(s)\n", suspects);

    CloseServiceHandle(hScm);
}

// ── removePersistence ─────────────────────────────────────────────────────────
bool removePersistence(const char* serviceName) {
    // 1. Stop service
    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) { printf("[-] OpenSCManager: %lu\n", GetLastError()); return false; }

    SC_HANDLE hSvc = OpenServiceA(hScm, serviceName,
                                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hSvc) {
        printf("[-] OpenService '%s': %lu\n", serviceName, GetLastError());
        CloseServiceHandle(hScm); return false;
    }

    // Query binary path before deleting
    DWORD cfgNeeded = 0;
    QueryServiceConfigA(hSvc, NULL, 0, &cfgNeeded);
    std::string dropPath;
    if (cfgNeeded) {
        std::string cfgBuf(cfgNeeded, '\0');
        auto* cfg = (QUERY_SERVICE_CONFIGA*)cfgBuf.data();
        QueryServiceConfigA(hSvc, cfg, cfgNeeded, &cfgNeeded);
        if (cfg->lpBinaryPathName) dropPath = cfg->lpBinaryPathName;
    }

    // Stop
    SERVICE_STATUS ss;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    for (int i = 0; i < 20; i++) {
        SERVICE_STATUS_PROCESS ssp = {}; DWORD needed;
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (BYTE*)&ssp, sizeof(ssp), &needed);
        if (ssp.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(500);
    }

    // Delete service record
    bool ok = DeleteService(hSvc) != 0;
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);

    if (ok) printf("[+] Service '%s' removed from SCM\n", serviceName);
    else printf("[-] DeleteService: %lu\n", GetLastError());

    // 2. Delete dropped binary
    if (!dropPath.empty()) {
        if (DeleteFileA(dropPath.c_str()))
            printf("[+] Deleted: %s\n", dropPath.c_str());
        else
            printf("[!] Could not delete %s (may need reboot): %lu\n",
                   dropPath.c_str(), GetLastError());
    }

    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  %s install  [name]   # install persistence (WARNING: modifies system)\n"
               "  %s detect            # scan for suspicious services\n"
               "  %s remove   [name]   # remove persistence\n",
               argv[0], argv[0], argv[0]);
        return 1;
    }

    const char* name = argc >= 3 ? argv[2] : DEFAULT_NAME;

    if (!strcmp(argv[1], "install")) return installPersistence(name) ? 0 : 1;
    if (!strcmp(argv[1], "detect"))  { detectSuspiciousServices(); return 0; }
    if (!strcmp(argv[1], "remove"))  return removePersistence(name) ? 0 : 1;

    printf("[-] Unknown verb: %s\n", argv[1]);
    return 1;
}
