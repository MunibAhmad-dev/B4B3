/*
  Exercise 01 — Threaded Port Scanner with Banner Grabbing
  ---------------------------------------------------------
  Build a port scanner that:
  1. Takes a host and port range as arguments (or defaults)
  2. Spawns up to N threads concurrently (default 64)
  3. For each open port, attempts to read the first banner bytes the service sends
  4. Prints results sorted by port number

  Expected output (example against localhost):
    Port  22   OPEN  SSH-2.0-OpenSSH_8.9
    Port  80   OPEN  HTTP/1.1 400 Bad Request
    Port  443  OPEN  (no banner — TLS handshake required)
    Port  3306 OPEN  5.7.44-MySQL...

  Tasks:
  1. Implement scanPort() — non-blocking connect with select() timeout, then
     attempt banner grab.
  2. Implement portScan() — thread pool with max N concurrent threads.
  3. Print results sorted by port number after all threads finish.

  BONUS:
  - Add service name detection from well-known port mapping.
  - Add a UDP scan mode (send an empty packet, check for ICMP port unreachable).
  - Output to CSV file.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_port_scanner.cpp -lws2_32
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
    int    port;
    bool   open;
    std::string banner;
};

std::vector<ScanResult> g_results;
std::mutex              g_resultsMtx;

// Known port → service name mapping (add more as needed)
const char* serviceName(int port) {
    switch (port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-alt";
        default:   return "";
    }
}

// TODO: Implement this function.
// 1. Create a non-blocking TCP socket.
// 2. Attempt connect() to host:port.
// 3. Use select() with timeoutMs to wait for connection.
// 4. If connected, recv() up to 256 bytes as the banner.
// 5. Store result in g_results (thread-safe with g_resultsMtx).
void scanPort(const char* host, int port, int timeoutMs) {
    // YOUR CODE HERE
}

// TODO: Implement this function.
// Scan ports [startPort..endPort] using up to maxThreads concurrent threads.
// Collect all results, then print them sorted by port number.
void portScan(const char* host, int startPort, int endPort, int maxThreads, int timeoutMs) {
    // YOUR CODE HERE
}

int main(int argc, char* argv[]) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    const char* host      = (argc > 1) ? argv[1] : "127.0.0.1";
    int         startPort = (argc > 2) ? atoi(argv[2]) : 1;
    int         endPort   = (argc > 3) ? atoi(argv[3]) : 1024;
    int         threads   = (argc > 4) ? atoi(argv[4]) : 64;

    printf("Scanning %s ports %d–%d (%d threads)\n\n", host, startPort, endPort, threads);

    portScan(host, startPort, endPort, threads, 500);

    WSACleanup();
    return 0;
}
