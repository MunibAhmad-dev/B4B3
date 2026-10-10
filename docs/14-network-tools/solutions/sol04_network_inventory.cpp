// sol04_network_inventory.cpp — Network Inventory Tool
// Enumerates local adapters, ARP table, routing table, and active connections.
//
// Compile:
//   g++ -std=c++17 -Wall -o sol04.exe solutions/sol04_network_inventory.cpp -liphlpapi -lws2_32
//
// Usage:
//   sol04.exe                -- text output
//   sol04.exe --format json  -- JSON output

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static bool g_json = false;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::string mac_to_str(const BYTE* mac, DWORD len)
{
    if (len == 0) return "(none)";
    char buf[64] = {};
    for (DWORD i = 0; i < len && i < 6; i++) {
        if (i > 0) strcat_s(buf, ":");
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X", mac[i]);
        strcat_s(buf, hex);
    }
    return buf;
}

static std::string ip_to_str(DWORD ip_le)
{
    char buf[INET_ADDRSTRLEN];
    struct in_addr a; a.s_addr = ip_le;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

static std::string get_process_name(DWORD pid)
{
    if (pid == 0) return "System";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "?";
    PROCESSENTRY32 pe = {}; pe.dwSize = sizeof(pe);
    std::string name = "?";
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) { name = pe.szExeFile; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return name;
}

static std::string json_escape(const std::string& s)
{
    std::string out;
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else                out += c;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Section 1: Local adapters via GetAdaptersAddresses
// ---------------------------------------------------------------------------
static void print_adapters()
{
    ULONG buf_size = 15000;
    std::vector<char> buf(buf_size);
    DWORD rc = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
        NULL,
        (PIP_ADAPTER_ADDRESSES)buf.data(),
        &buf_size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(buf_size);
        rc = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
            NULL, (PIP_ADAPTER_ADDRESSES)buf.data(), &buf_size);
    }
    if (rc != NO_ERROR) { printf("  GetAdaptersAddresses failed: %lu\n", rc); return; }

    if (g_json) printf("  \"adapters\": [\n");
    else        printf("\n=== Network Adapters ===\n");

    bool first = true;
    for (PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)buf.data();
         aa != NULL; aa = aa->Next)
    {
        // Convert friendly name from wchar
        char fname[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, aa->FriendlyName, -1, fname, sizeof(fname), NULL, NULL);

        static const char* types[] = {"Other","Ethernet","Token Ring","FDDI","PPP","Loopback","Slip"};
        const char* tstr = (aa->IfType < 7) ? types[aa->IfType] : "Unknown";

        if (g_json) {
            if (!first) printf(",\n");
            first = false;
            printf("    {\"name\":\"%s\",\"type\":\"%s\",\"mac\":\"%s\",\"mtu\":%lu,",
                   json_escape(fname).c_str(), tstr,
                   mac_to_str(aa->PhysicalAddress, aa->PhysicalAddressLength).c_str(),
                   aa->Mtu);
            printf("\"addresses\":[");
            bool fa = true;
            for (PIP_ADAPTER_UNICAST_ADDRESS ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
                char ip[INET6_ADDRSTRLEN] = {};
                getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength,
                            ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
                if (!fa) printf(",");
                fa = false;
                printf("\"%s\"", ip);
            }
            printf("]}");
        } else {
            printf("\nAdapter: %s\n", fname);
            printf("  Type:    %s\n", tstr);
            printf("  MAC:     %s\n", mac_to_str(aa->PhysicalAddress, aa->PhysicalAddressLength).c_str());
            printf("  MTU:     %lu\n", aa->Mtu);
            for (PIP_ADAPTER_UNICAST_ADDRESS ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
                char ip[INET6_ADDRSTRLEN] = {};
                int fam = ua->Address.lpSockaddr->sa_family;
                getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength,
                            ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
                printf("  %s  %s\n", fam == AF_INET ? "IPv4:" : "IPv6:", ip);
            }
            // DHCP server
            if (aa->Dhcpv4Enabled) {
                char dhcp[INET_ADDRSTRLEN] = {};
                getnameinfo((struct sockaddr*)&aa->Dhcpv4Server.iSockaddrLength,
                            aa->Dhcpv4Server.iSockaddrLength, dhcp, sizeof(dhcp),
                            NULL, 0, NI_NUMERICHOST);
                // Simpler: just print the address bytes
                printf("  DHCP:    enabled\n");
            }
        }
    }
    if (g_json) printf("\n  ],\n");
}

// ---------------------------------------------------------------------------
// Section 2: ARP table
// ---------------------------------------------------------------------------
static void print_arp()
{
    ULONG size = 0;
    GetIpNetTable(NULL, &size, FALSE);
    std::vector<char> buf(size);
    PMIB_IPNETTABLE table = (PMIB_IPNETTABLE)buf.data();
    if (GetIpNetTable(table, &size, TRUE) != NO_ERROR) {
        printf("  GetIpNetTable failed\n"); return;
    }

    if (g_json) printf("  \"arp\": [\n");
    else        printf("\n=== ARP Table ===\n");

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPNETROW& row = table->table[i];
        std::string ip  = ip_to_str(row.dwAddr);
        std::string mac = mac_to_str(row.bPhysAddr, row.dwPhysAddrLen);
        const char* type = (row.dwType == MIB_IPNET_TYPE_DYNAMIC) ? "dynamic" :
                           (row.dwType == MIB_IPNET_TYPE_STATIC)  ? "static"  : "other";
        if (g_json) {
            if (i > 0) printf(",\n");
            printf("    {\"ip\":\"%s\",\"mac\":\"%s\",\"type\":\"%s\"}", ip.c_str(), mac.c_str(), type);
        } else {
            printf("  %-18s  %-20s  %s\n", ip.c_str(), mac.c_str(), type);
        }
    }
    if (g_json) printf("\n  ],\n");
}

// ---------------------------------------------------------------------------
// Section 3: Routing table
// ---------------------------------------------------------------------------
static void print_routes()
{
    ULONG size = 0;
    GetIpForwardTable(NULL, &size, FALSE);
    std::vector<char> buf(size);
    PMIB_IPFORWARDTABLE table = (PMIB_IPFORWARDTABLE)buf.data();
    if (GetIpForwardTable(table, &size, TRUE) != NO_ERROR) {
        printf("  GetIpForwardTable failed\n"); return;
    }

    if (g_json) printf("  \"routes\": [\n");
    else {
        printf("\n=== Routing Table ===\n");
        printf("  %-18s %-18s %-18s  If   Metric\n", "Destination", "Mask", "Gateway");
        printf("  %s\n", std::string(70, '-').c_str());
    }

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPFORWARDROW& r = table->table[i];
        std::string dst  = ip_to_str(r.dwForwardDest);
        std::string mask = ip_to_str(r.dwForwardMask);
        std::string gw   = ip_to_str(r.dwForwardNextHop);

        if (g_json) {
            if (i > 0) printf(",\n");
            printf("    {\"dst\":\"%s\",\"mask\":\"%s\",\"gw\":\"%s\",\"if\":%lu,\"metric\":%lu}",
                   dst.c_str(), mask.c_str(), gw.c_str(),
                   r.dwForwardIfIndex, r.dwForwardMetric1);
        } else {
            printf("  %-18s %-18s %-18s  %-4lu  %lu\n",
                   dst.c_str(), mask.c_str(), gw.c_str(),
                   r.dwForwardIfIndex, r.dwForwardMetric1);
        }
    }
    if (g_json) printf("\n  ],\n");
}

// ---------------------------------------------------------------------------
// Section 4: Active TCP/UDP connections
// ---------------------------------------------------------------------------
static void print_connections()
{
    // TCP
    ULONG tcp_size = 0;
    GetExtendedTcpTable(NULL, &tcp_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<char> tcp_buf(tcp_size);
    PMIB_TCPTABLE_OWNER_PID tcpt = (PMIB_TCPTABLE_OWNER_PID)tcp_buf.data();
    GetExtendedTcpTable(tcpt, &tcp_size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    // UDP
    ULONG udp_size = 0;
    GetExtendedUdpTable(NULL, &udp_size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<char> udp_buf(udp_size);
    PMIB_UDPTABLE_OWNER_PID udpt = (PMIB_UDPTABLE_OWNER_PID)udp_buf.data();
    GetExtendedUdpTable(udpt, &udp_size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    static const char* tcp_states[] = {
        "CLOSED","LISTENING","SYN_SENT","SYN_RCVD","ESTABLISHED",
        "FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT","CLOSING","LAST_ACK","TIME_WAIT","DELETE_TCB"
    };

    if (g_json) printf("  \"connections\": [\n");
    else {
        printf("\n=== Active Connections ===\n");
        printf("  %-6s %-22s %-22s %-14s  PID    Process\n", "Proto","Local","Remote","State");
        printf("  %s\n", std::string(90, '-').c_str());
    }

    bool first = true;
    char la[22], ra[22];

    for (DWORD i = 0; i < tcpt->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID& r = tcpt->table[i];
        struct in_addr la_addr; la_addr.s_addr = r.dwLocalAddr;
        struct in_addr ra_addr; ra_addr.s_addr = r.dwRemoteAddr;
        char la_ip[INET_ADDRSTRLEN], ra_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &la_addr, la_ip, sizeof(la_ip));
        inet_ntop(AF_INET, &ra_addr, ra_ip, sizeof(ra_ip));
        snprintf(la, sizeof(la), "%s:%u", la_ip, ntohs((u_short)r.dwLocalPort));
        snprintf(ra, sizeof(ra), "%s:%u", ra_ip, ntohs((u_short)r.dwRemotePort));
        const char* state = (r.dwState >= 1 && r.dwState <= 12) ? tcp_states[r.dwState-1] : "?";
        std::string proc = get_process_name(r.dwOwningPid);

        if (g_json) {
            if (!first) printf(",\n"); first = false;
            printf("    {\"proto\":\"TCP\",\"local\":\"%s\",\"remote\":\"%s\","
                   "\"state\":\"%s\",\"pid\":%lu,\"process\":\"%s\"}",
                   la, ra, state, r.dwOwningPid, json_escape(proc).c_str());
        } else {
            printf("  %-6s %-22s %-22s %-14s  %-6lu  %s\n",
                   "TCP", la, ra, state, r.dwOwningPid, proc.c_str());
        }
    }

    for (DWORD i = 0; i < udpt->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID& r = udpt->table[i];
        struct in_addr la_addr; la_addr.s_addr = r.dwLocalAddr;
        char la_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &la_addr, la_ip, sizeof(la_ip));
        snprintf(la, sizeof(la), "%s:%u", la_ip, ntohs((u_short)r.dwLocalPort));
        std::string proc = get_process_name(r.dwOwningPid);

        if (g_json) {
            if (!first) printf(",\n"); first = false;
            printf("    {\"proto\":\"UDP\",\"local\":\"%s\",\"remote\":\"*:*\","
                   "\"state\":\"LISTEN\",\"pid\":%lu,\"process\":\"%s\"}",
                   la, r.dwOwningPid, json_escape(proc).c_str());
        } else {
            printf("  %-6s %-22s %-22s %-14s  %-6lu  %s\n",
                   "UDP", la, "*:*", "LISTEN", r.dwOwningPid, proc.c_str());
        }
    }

    if (g_json) printf("\n  ]\n");
}

// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0 && i+1 < argc && strcmp(argv[i+1], "json") == 0)
            g_json = true;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    if (g_json) printf("{\n");
    else printf("=== Network Inventory ===\n");

    print_adapters();
    print_arp();
    print_routes();
    print_connections();

    if (g_json) printf("}\n");

    WSACleanup();
    return 0;
}
