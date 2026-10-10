/*
  Exercise 04 — Service Persistence Simulation (Blue Team Lab)
  -------------------------------------------------------------
  This exercise simulates how malware installs itself as a service
  for persistence, then shows you how to DETECT and REMOVE it.

  This is a BLUE TEAM exercise: you are building the detection/cleanup tool,
  not the malware. The simulation is contained (no payload, no network).

  SIMULATION — what the "malware" would do:
    1. Copy itself to a persistent path (C:\Windows\Temp\svc_sim.exe).
    2. Install itself as an auto-start service "SvcSim".
    3. Add a registry description to blend in.
    4. Optionally add itself to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
       (svchost group registration — advanced persistence).

  DETECTION — what your tool should find:
    1. Services with binaries in unusual paths (not System32/SysWOW64/Program Files).
    2. Services installed recently (creation timestamp comparison — tricky on Windows).
    3. Services with no signature on their binary.
    4. Services pointing to non-existent binaries (leftover/cleanup).

  Tasks:
  1. Implement installPersistence() — simulate the malware side.
     (No actual payload — just install a service pointing to this .exe with a --service flag.)
  2. Implement detectSuspiciousServices() — enumerate all services,
     check their binPaths, flag unusual locations.
  3. Implement removePersistence(svcName) — stop + delete the service + delete the file.
  4. Run: install → detect (find it) → remove → detect again (gone).

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_service_persistence_sim.cpp -ladvapi32
  Usage:
    ex04.exe --install    → install sim service
    ex04.exe --detect     → scan for suspicious services
    ex04.exe --remove     → remove the sim service
    ex04.exe --service    → (called by SCM — just Sleep forever)
*/

#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>

static const char* SIM_SVC_NAME = "SvcSim";
static const char* SIM_INSTALL  = "C:\\Windows\\Temp\\svc_sim.exe";

// ---- TODO 1: installPersistence ----
bool installPersistence() {
    // Step 1: copy ourselves to the persistent path
    char selfPath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, selfPath, sizeof(selfPath));

    if (!CopyFileA(selfPath, SIM_INSTALL, FALSE)) {
        printf("[-] CopyFile: %lu\n", GetLastError());
        return false;
    }
    printf("[*] Copied to: %s\n", SIM_INSTALL);

    // Step 2: install as auto-start service
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) return false;

    std::string binPath = std::string(SIM_INSTALL) + " --service";
    SC_HANDLE hSvc = CreateServiceA(
        hScm, SIM_SVC_NAME, "Windows System Configuration Helper",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hSvc && GetLastError() != ERROR_SERVICE_EXISTS) {
        printf("[-] CreateService: %lu\n", GetLastError());
        CloseServiceHandle(hScm); return false;
    }
    if (hSvc) CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    printf("[+] Service installed: %s (auto-start)\n", SIM_SVC_NAME);
    printf("[!] Persistence installed. Run --detect to find it.\n");
    return true;
}

// ---- TODO 2: detectSuspiciousServices ----
void detectSuspiciousServices() {
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) return;

    DWORD needed = 0, count = 0, resumeHandle = 0;
    EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                           SERVICE_STATE_ALL, nullptr, 0, &needed, &count, &resumeHandle, nullptr);
    std::vector<BYTE> buf(needed);
    EnumServicesStatusExA(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                           SERVICE_STATE_ALL, buf.data(), needed, &needed, &count, &resumeHandle, nullptr);

    auto* svcs = (ENUM_SERVICE_STATUS_PROCESSA*)buf.data();
    printf("\n[DETECT] Scanning %lu services...\n", count);

    for (DWORD i = 0; i < count; i++) {
        // Query config to get binary path
        SC_HANDLE hSvc = OpenServiceA(hScm, svcs[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD cfgNeeded = 0;
        QueryServiceConfigA(hSvc, nullptr, 0, &cfgNeeded);
        std::vector<BYTE> cfgBuf(cfgNeeded);
        auto* cfg = (QUERY_SERVICE_CONFIGA*)cfgBuf.data();
        QueryServiceConfigA(hSvc, cfg, cfgNeeded, &cfgNeeded);
        CloseServiceHandle(hSvc);

        if (!cfg->lpBinaryPathName) continue;
        std::string binPath = cfg->lpBinaryPathName;

        // Flag suspicious paths
        bool suspicious = false;
        std::string lower = binPath;
        for (auto& c : lower) c = (char)tolower((unsigned char)c);

        if (lower.find("\\temp\\")    != std::string::npos ||
            lower.find("\\appdata\\") != std::string::npos ||
            lower.find("\\users\\")   != std::string::npos) {
            suspicious = true;
        }

        // Check if binary exists
        bool exists = (GetFileAttributesA(cfg->lpBinaryPathName) != INVALID_FILE_ATTRIBUTES);

        if (suspicious || !exists) {
            printf("  [%s] %-35s  %s%s\n",
                   suspicious ? "SUSPICIOUS" : "MISSING_BIN",
                   svcs[i].lpServiceName,
                   binPath.substr(0, 60).c_str(),
                   !exists ? "  [FILE MISSING]" : "");
        }
    }
    CloseServiceHandle(hScm);
    printf("[DETECT] Done\n");
}

// ---- TODO 3: removePersistence ----
void removePersistence() {
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE hSvc = OpenServiceA(hScm, SIM_SVC_NAME,
                                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (hSvc) {
        SERVICE_STATUS ss = {};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(1000);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        printf("[+] Service removed: %s\n", SIM_SVC_NAME);
    }
    if (hScm) CloseServiceHandle(hScm);

    if (DeleteFileA(SIM_INSTALL))
        printf("[+] File removed: %s\n", SIM_INSTALL);
    else
        printf("[-] DeleteFile(%s): %lu\n", SIM_INSTALL, GetLastError());
}

void serviceMain() {
    printf("[SVC] Running as service. Sleeping...\n");
    while (true) Sleep(5000);
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--install") == 0) return installPersistence() ? 0 : 1;
        if (strcmp(argv[1], "--detect")  == 0) { detectSuspiciousServices(); return 0; }
        if (strcmp(argv[1], "--remove")  == 0) { removePersistence(); return 0; }
        if (strcmp(argv[1], "--service") == 0) { serviceMain(); return 0; }
    }
    printf("Usage:\n"
           "  ex04.exe --install  → install simulation persistence\n"
           "  ex04.exe --detect   → scan for suspicious services\n"
           "  ex04.exe --remove   → remove the simulation\n");
    return 1;
}
