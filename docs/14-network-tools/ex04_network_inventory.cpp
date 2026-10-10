/*
  Exercise 04 — Network Inventory Tool
  --------------------------------------
  Scan the local /24 subnet for:
  1. Live hosts (ICMP ping or TCP-connect to port 80/443)
  2. Common open ports on live hosts: 21 22 23 25 80 443 445 3306 3389 8080
  3. Hostname via reverse DNS lookup

  This is what a blue team uses on Day 1 when they inherit an unknown network.

  Expected output:
    192.168.1.1   router.local         80 443
    192.168.1.10  workstation-1.local  445 3389
    192.168.1.20  (no rDNS)            22 80

  Tasks:
  1. Auto-detect the local subnet (GetAdaptersInfo or GetAdaptersAddresses).
  2. For each .1–.254 address in the /24, attempt a fast TCP connect to any
     of the common ports. If any port responds, mark host as live.
  3. Reverse-DNS lookup the live hosts (getnameinfo or DnsQuery).
  4. Full port scan of the common port set for live hosts.
  5. Print a sorted inventory table.

  BONUS:
  - Export to CSV.
  - Add NetBIOS name resolution (send a broadcast UDP query to port 137).
  - Detect OS from TTL value in ping response.

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_network_inventory.cpp -lws2_32 -liphlpapi -ldnsapi
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windns.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <algorithm>
#include <iomanip>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")

struct HostInfo {
    std::string ip;
    std::string hostname;
    std::vector<int> openPorts;
};

std::vector<HostInfo> g_inventory;
std::mutex            g_inventoryMtx;

static const int COMMON_PORTS[] = { 21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080 };
static const int N_PORTS        = (int)(sizeof(COMMON_PORTS)/sizeof(COMMON_PORTS[0]));

// TODO: Fast connect check — does host:port accept TCP within timeoutMs?
bool isPortOpen(const char* host, int port, int timeoutMs) {
    // YOUR CODE HERE
    return false;
}

// TODO: Reverse-DNS lookup for an IP address string.
// Returns hostname or empty string if no rDNS record.
std::string reverseDns(const char* ip) {
    // YOUR CODE HERE
    return "";
}

// TODO: Get the local machine's first non-loopback IPv4 address.
// Use GetAdaptersInfo() or GetAdaptersAddresses().
// Returns e.g. "192.168.1.50"
std::string getLocalIp() {
    // YOUR CODE HERE
    return "127.0.0.1";
}

// Derive /24 base from an IP string: "192.168.1.50" → "192.168.1."
std::string subnetBase(const std::string& ip) {
    size_t last = ip.rfind('.');
    if (last == std::string::npos) return "";
    return ip.substr(0, last + 1);
}

// TODO: Scan a single host — probe common ports, do rDNS, add to g_inventory if live.
void scanHost(const std::string& ip) {
    // YOUR CODE HERE
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    std::string localIp  = getLocalIp();
    std::string base     = subnetBase(localIp);

    if (base.empty()) {
        printf("[-] Could not determine subnet\n");
        return 1;
    }

    printf("[*] Local IP: %s\n", localIp.c_str());
    printf("[*] Scanning subnet: %s0/24\n\n", base.c_str());

    // TODO: Launch scanHost() for .1–.254 using a thread pool (max 64 threads).
    // YOUR CODE HERE

    // Print inventory table
    std::sort(g_inventory.begin(), g_inventory.end(),
              [](const HostInfo& a, const HostInfo& b){ return a.ip < b.ip; });

    printf("\n%-18s %-30s %s\n", "IP", "Hostname", "Open Ports");
    printf("%s\n", std::string(70, '-').c_str());

    for (const auto& host : g_inventory) {
        std::string portList;
        for (int p : host.openPorts) {
            if (!portList.empty()) portList += " ";
            portList += std::to_string(p);
        }
        printf("%-18s %-30s %s\n",
               host.ip.c_str(),
               host.hostname.empty() ? "(no rDNS)" : host.hostname.c_str(),
               portList.c_str());
    }

    printf("\n[*] Total live hosts: %zu\n", g_inventory.size());

    WSACleanup();
    return 0;
}
