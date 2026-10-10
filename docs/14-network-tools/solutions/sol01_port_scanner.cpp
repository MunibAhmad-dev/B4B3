/*
  Solution 01 — Threaded Port Scanner with Banner Grabbing
*/
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <string>
#include <iomanip>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

struct ScanResult {
    int port; bool open; std::string banner;
};
std::vector<ScanResult> g_results;
std::mutex              g_mtx;

const char* serviceName(int port) {
    switch (port) {
        case 21: return "FTP"; case 22: return "SSH"; case 23: return "Telnet";
        case 25: return "SMTP"; case 53: return "DNS"; case 80: return "HTTP";
        case 110: return "POP3"; case 143: return "IMAP"; case 443: return "HTTPS";
        case 445: return "SMB"; case 3306: return "MySQL"; case 3389: return "RDP";
        case 5432: return "PgSQL"; case 6379: return "Redis"; case 8080: return "HTTP-alt";
        default: return "";
    }
}

void scanPort(const char* host, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;

    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    connect(s, (sockaddr*)&addr, sizeof(addr));

    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_SET(s, &wfds);
    FD_ZERO(&efds); FD_SET(s, &efds);
    struct timeval tv = { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };

    bool open = (select(0, nullptr, &wfds, &efds, &tv) > 0 && FD_ISSET(s, &wfds));

    std::string banner;
    if (open) {
        // Brief wait for service banner
        mode = 0; ioctlsocket(s, FIONBIO, &mode);
        struct timeval rv = {0, 300000};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&rv, sizeof(rv));
        char buf[257] = {};
        int r = recv(s, buf, sizeof(buf)-1, 0);
        if (r > 0) {
            banner = std::string(buf, r);
            // Trim to first line
            size_t nl = banner.find_first_of("\r\n");
            if (nl != std::string::npos) banner = banner.substr(0, nl);
            // Strip non-printable
            for (char& c : banner) if ((unsigned char)c < 32 || (unsigned char)c > 126) c = '.';
        }
    }

    closesocket(s);

    std::lock_guard<std::mutex> lk(g_mtx);
    g_results.push_back({port, open, banner});
}

void portScan(const char* host, int startPort, int endPort, int maxThreads, int timeoutMs) {
    std::vector<std::thread> pool;
    for (int port = startPort; port <= endPort; port++) {
        pool.emplace_back(scanPort, host, port, timeoutMs);
        if ((int)pool.size() >= maxThreads) {
            for (auto& t : pool) t.join();
            pool.clear();
        }
    }
    for (auto& t : pool) t.join();

    // Sort and print
    std::sort(g_results.begin(), g_results.end(),
              [](const ScanResult& a, const ScanResult& b){ return a.port < b.port; });

    for (const auto& r : g_results) {
        if (!r.open) continue;
        const char* svc = serviceName(r.port);
        printf("Port %5d  OPEN  %-10s  %s\n", r.port, svc,
               r.banner.empty() ? "(no banner)" : r.banner.c_str());
    }

    long openCount = std::count_if(g_results.begin(), g_results.end(),
                                   [](const ScanResult& r){ return r.open; });
    printf("\n[*] %ld open port(s) out of %d scanned\n", openCount, endPort - startPort + 1);
}

int main(int argc, char* argv[]) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    const char* host = (argc > 1) ? argv[1] : "127.0.0.1";
    int startPort    = (argc > 2) ? atoi(argv[2]) : 1;
    int endPort      = (argc > 3) ? atoi(argv[3]) : 1024;
    int threads      = (argc > 4) ? atoi(argv[4]) : 64;
    printf("Scanning %s ports %d–%d (%d threads)\n\n", host, startPort, endPort, threads);
    portScan(host, startPort, endPort, threads, 500);
    WSACleanup();
    return 0;
}
