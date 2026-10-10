// driver_client.cpp — usermode client for MyDriver kernel driver
// Compile: g++ -std=c++17 -o driver_client.exe driver_client.cpp -ladvapi32
// Usage: driver_client.exe ping | getpid <name> | install <sys_path> | uninstall <svc_name>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string>
#include <wchar.h>

// IOCTL definitions (mirrors driver_interface.h without kernel headers)
#define IOCTL_MYDRIVER_PING   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYDRIVER_GETPID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MYDRIVER_DEVICE_NAME  "\\\\.\\MyDriver"

// ─── Open device handle ───────────────────────────────────────────────────────

static HANDLE open_driver() {
    HANDLE h = CreateFileA(MYDRIVER_DEVICE_NAME,
                           GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        fprintf(stderr, "[!] Cannot open " MYDRIVER_DEVICE_NAME ": %lu\n"
                "    (Is the driver loaded? Run: driver_client.exe install <sys>)\n",
                GetLastError());
    return h;
}

// ─── ping ─────────────────────────────────────────────────────────────────────

static void cmd_ping() {
    HANDLE h = open_driver();
    if (h == INVALID_HANDLE_VALUE) return;

    char inbuf[4]  = {0};
    char outbuf[16] = {0};
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_MYDRIVER_PING,
                              inbuf, sizeof(inbuf),
                              outbuf, sizeof(outbuf),
                              &returned, nullptr);
    if (ok) printf("[+] Driver responded: %.*s\n", returned, outbuf);
    else    fprintf(stderr, "[!] DeviceIoControl failed: %lu\n", GetLastError());
    CloseHandle(h);
}

// ─── getpid ───────────────────────────────────────────────────────────────────

static void cmd_getpid(const char* name) {
    HANDLE h = open_driver();
    if (h == INVALID_HANDLE_VALUE) return;

    wchar_t wname[256]{};
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 256);
    DWORD pid = 0;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_MYDRIVER_GETPID,
                              wname, (DWORD)(wcslen(wname)+1) * sizeof(wchar_t),
                              &pid, sizeof(pid),
                              &returned, nullptr);
    if (ok) printf("[+] PID of \"%s\": %lu\n", name, pid);
    else    fprintf(stderr, "[!] DeviceIoControl failed: %lu\n", GetLastError());
    CloseHandle(h);
}

// ─── install: load kernel driver via SCM ─────────────────────────────────────

static void cmd_install(const char* sys_path) {
    printf("[*] Installing driver from: %s\n", sys_path);

    // Resolve absolute path
    char abs[MAX_PATH]{};
    if (!GetFullPathNameA(sys_path, MAX_PATH, abs, nullptr)) {
        fprintf(stderr, "[!] GetFullPathNameA failed: %lu\n", GetLastError()); return;
    }

    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) { fprintf(stderr, "[!] OpenSCManager failed: %lu\n", GetLastError()); return; }

    SC_HANDLE hSvc = CreateServiceA(hScm, "MyDriver", "MyDriver",
                                    SERVICE_ALL_ACCESS,
                                    SERVICE_KERNEL_DRIVER,
                                    SERVICE_DEMAND_START,
                                    SERVICE_ERROR_IGNORE,
                                    abs,
                                    nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            printf("[*] Service already exists; opening...\n");
            hSvc = OpenServiceA(hScm, "MyDriver", SERVICE_ALL_ACCESS);
        }
        if (!hSvc) { fprintf(stderr, "[!] CreateService failed: %lu\n", err);
                     CloseServiceHandle(hScm); return; }
    } else {
        printf("[+] Service created\n");
    }

    if (!StartServiceA(hSvc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) printf("[*] Driver already running\n");
        else fprintf(stderr, "[!] StartService failed: %lu\n", err);
    } else {
        printf("[+] Driver started\n");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

// ─── uninstall ────────────────────────────────────────────────────────────────

static void cmd_uninstall(const char* svc_name) {
    printf("[*] Uninstalling service: %s\n", svc_name);
    SC_HANDLE hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) { fprintf(stderr, "[!] OpenSCManager failed: %lu\n", GetLastError()); return; }

    SC_HANDLE hSvc = OpenServiceA(hScm, svc_name, SERVICE_ALL_ACCESS);
    if (!hSvc) { fprintf(stderr, "[!] OpenService failed: %lu\n", GetLastError());
                 CloseServiceHandle(hScm); return; }

    SERVICE_STATUS ss{};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    Sleep(500);

    if (DeleteService(hSvc)) printf("[+] Service deleted\n");
    else fprintf(stderr, "[!] DeleteService failed: %lu\n", GetLastError());

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  driver_client.exe ping\n"
               "  driver_client.exe getpid <process_name>\n"
               "  driver_client.exe install <sys_path>\n"
               "  driver_client.exe uninstall <svc_name>\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "ping")                      cmd_ping();
    else if (cmd == "getpid" && argc >= 3)        cmd_getpid(argv[2]);
    else if (cmd == "install" && argc >= 3)       cmd_install(argv[2]);
    else if (cmd == "uninstall" && argc >= 3)     cmd_uninstall(argv[2]);
    else { fprintf(stderr, "Unknown command or missing args.\n"); return 1; }
    return 0;
}
