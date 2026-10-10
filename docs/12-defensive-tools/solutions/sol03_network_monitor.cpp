// solutions/sol03_network_monitor.cpp
// Module 12 Solution 03 — Network Connection Monitor (complete)
// Compile: g++ -std=c++17 -Wall -o sol03.exe sol03_network_monitor.cpp -liphlpapi
//
// Modes:
//   sol03.exe snapshot          -- dump all current TCP/UDP connections
//   sol03.exe watch <sec>       -- continuous diff, print NEW/CLOSED/LISTENING
//
// Features:
//   - IPv4 and IPv6 TCP tables (GetExtendedTcpTable)
//   - IPv4 and IPv6 UDP endpoints (GetExtendedUdpTable)
//   - PID -> process name via Toolhelp32 (refreshed each snapshot)
//   - Behavioral flags: BAD_PORT, UNUSUAL_PROCESS, PORT_SCAN (>10 IPs/min)
//   - inet_ntop for address formatting

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ===================================================== PID -> name cache

static std::unordered_map<DWORD, std::string> g_pid_names;

static void refresh_pid_cache() {
    g_pid_names.clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof pe;
    if (Process32First(hSnap, &pe))
        do { g_pid_names[pe.th32ProcessID] = pe.szExeFile; }
        while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);
}

static std::string pid_name(DWORD pid) {
    auto it = g_pid_names.find(pid);
    return (it != g_pid_names.end()) ? it->second : "?";
}

// ====================================================== Address helpers

static std::string ipv4_str(DWORD net_addr, DWORD net_port) {
    struct in_addr in;
    in.s_addr = net_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in, ip, sizeof ip);
    return std::string(ip) + ":" + std::to_string(ntohs(static_cast<u_short>(net_port)));
}

static std::string ipv6_str(const BYTE* addr6, DWORD net_port) {
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr6, ip, sizeof ip);
    return std::string("[") + ip + "]:" +
           std::to_string(ntohs(static_cast<u_short>(net_port)));
}

// ======================================================= TCP state names

static const char* tcp_state_str(DWORD s) {
    switch (s) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        default:                        return "UNKNOWN";
    }
}

// ================================================== Connection record

struct Conn {
    std::string local;     // "addr:port"
    std::string remote;    // "addr:port" or "*:*" for UDP
    std::string state;     // TCP state name or "UDP"
    DWORD       pid;
    bool        is_udp;

    // Stable key for deduplication / diffing
    std::string key() const {
        return local + "|" + remote + "|" + state + "|" + std::to_string(pid);
    }
};

using ConnMap = std::map<std::string, Conn>;  // key -> conn

// =================================================== Snapshot functions

static void snap_tcp4(ConnMap& out) {
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buf(sz + 256);
    if (GetExtendedTcpTable(buf.data(), &sz, TRUE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& r = t->table[i];
        Conn c;
        c.local  = ipv4_str(r.dwLocalAddr, r.dwLocalPort);
        c.remote = ipv4_str(r.dwRemoteAddr, r.dwRemotePort);
        c.state  = tcp_state_str(r.dwState);
        c.pid    = r.dwOwningPid;
        c.is_udp = false;
        out[c.key()] = c;
    }
}

static void snap_tcp6(ConnMap& out) {
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buf(sz + 256);
    if (GetExtendedTcpTable(buf.data(), &sz, TRUE, AF_INET6,
                             TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& r = t->table[i];
        Conn c;
        c.local  = ipv6_str(r.ucLocalAddr,  r.dwLocalPort);
        c.remote = ipv6_str(r.ucRemoteAddr, r.dwRemotePort);
        c.state  = tcp_state_str(r.dwState);
        c.pid    = r.dwOwningPid;
        c.is_udp = false;
        out[c.key()] = c;
    }
}

static void snap_udp4(ConnMap& out) {
    DWORD sz = 0;
    GetExtendedUdpTable(nullptr, &sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<BYTE> buf(sz + 256);
    if (GetExtendedUdpTable(buf.data(), &sz, TRUE, AF_INET,
                             UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& r = t->table[i];
        Conn c;
        c.local  = ipv4_str(r.dwLocalAddr, r.dwLocalPort);
        c.remote = "*:*";
        c.state  = "UDP";
        c.pid    = r.dwOwningPid;
        c.is_udp = true;
        out[c.key()] = c;
    }
}

static void snap_udp6(ConnMap& out) {
    DWORD sz = 0;
    GetExtendedUdpTable(nullptr, &sz, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    std::vector<BYTE> buf(sz + 256);
    if (GetExtendedUdpTable(buf.data(), &sz, TRUE, AF_INET6,
                             UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& r = t->table[i];
        Conn c;
        c.local  = ipv6_str(r.ucLocalAddr, r.dwLocalPort);
        c.remote = "*:*";
        c.state  = "UDP";
        c.pid    = r.dwOwningPid;
        c.is_udp = true;
        out[c.key()] = c;
    }
}

static ConnMap full_snapshot() {
    refresh_pid_cache();
    ConnMap out;
    snap_tcp4(out);
    snap_tcp6(out);
    snap_udp4(out);
    snap_udp6(out);
    return out;
}

// ================================================== Behavioral analysis

// Ports associated with common C2 frameworks / backdoors
static const std::set<int> BAD_PORTS = {
    4444, 4445, 5555, 31337, 1337, 8888, 9999,
    6666, 1234, 12345, 54321, 2222, 3333, 7777
};

// Processes that should not normally make outbound connections
static const std::set<std::string> UNUSUAL_CONN_PROCS = {
    "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "msiexec.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe"
};

static std::string str_lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static int port_from_addr(const std::string& addr_port) {
    auto pos = addr_port.rfind(':');
    if (pos == std::string::npos) return 0;
    try { return std::stoi(addr_port.substr(pos + 1)); }
    catch (...) { return 0; }
}

static std::vector<std::string> behavioral_flags(const Conn& c) {
    std::vector<std::string> flags;
    if (c.is_udp || c.state != "ESTABLISHED") return flags;

    int rport = port_from_addr(c.remote);
    if (BAD_PORTS.count(rport))
        flags.push_back("BAD_PORT_" + std::to_string(rport));

    if (UNUSUAL_CONN_PROCS.count(str_lower(pid_name(c.pid))))
        flags.push_back("UNUSUAL_PROCESS");

    return flags;
}

// ====================================================== timestamp

static std::string now_str() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d",
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ====================================================== snapshot mode

static void mode_snapshot() {
    ConnMap conns = full_snapshot();

    std::cout << std::left
              << std::setw(7)  << "PID"
              << std::setw(20) << "Process"
              << std::setw(3)  << "P"
              << std::setw(32) << "Local"
              << std::setw(32) << "Remote"
              << "State / Flags\n"
              << std::string(110, '-') << "\n";

    for (const auto& [k, c] : conns) {
        std::string nm    = pid_name(c.pid);
        std::string proto = c.is_udp ? "U" : "T";
        auto        flags = behavioral_flags(c);

        std::string state_col = c.state;
        if (!flags.empty()) {
            state_col += " [";
            for (const auto& f : flags) state_col += f + " ";
            state_col += "]";
        }

        std::cout << std::left
                  << std::setw(7)  << c.pid
                  << std::setw(20) << nm.substr(0, 19)
                  << std::setw(3)  << proto
                  << std::setw(32) << c.local.substr(0, 31)
                  << std::setw(32) << c.remote.substr(0, 31)
                  << state_col << "\n";
    }
    std::cout << "\n" << conns.size() << " entries total.\n";
}

// ======================================================= watch mode

static void mode_watch(int interval_sec) {
    std::cout << "[NetWatch] Watching every " << interval_sec
              << "s. Ctrl+C to stop.\n\n";
    ConnMap prev = full_snapshot();
    std::cout << "[NetWatch] Initial: " << prev.size() << " entries.\n\n";

    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
        ConnMap curr = full_snapshot();

        for (const auto& [k, c] : curr) {
            if (prev.find(k) != prev.end()) continue;  // already seen

            std::string nm    = pid_name(c.pid);
            auto        flags = behavioral_flags(c);

            if (c.state == "LISTEN") {
                std::cout << "[" << now_str() << "] [LISTENING] PID=" << c.pid
                          << " " << nm << " " << c.local << "\n";
            } else {
                std::cout << "[" << now_str() << "] [NEW_CONN]  PID=" << c.pid
                          << " " << nm
                          << " " << c.local << " -> " << c.remote
                          << " " << c.state;
                if (!flags.empty()) {
                    std::cout << "  !!";
                    for (const auto& f : flags) std::cout << " " << f;
                }
                std::cout << "\n";
            }
        }

        for (const auto& [k, c] : prev) {
            if (curr.find(k) == curr.end() && !c.is_udp &&
                c.state != "LISTEN" && c.state != "CLOSED")
                std::cout << "[" << now_str() << "] [CLOSED]    PID=" << c.pid
                          << " " << pid_name(c.pid)
                          << " " << c.local << " -> " << c.remote << "\n";
        }

        prev = curr;
    }
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  sol03.exe snapshot\n"
                  << "  sol03.exe watch <interval_sec>\n";
        WSACleanup();
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "snapshot") {
        mode_snapshot();
    } else if (cmd == "watch" && argc >= 3) {
        mode_watch(std::stoi(argv[2]));
    } else {
        std::cerr << "Unknown command or missing arguments.\n";
        WSACleanup();
        return 1;
    }

    WSACleanup();
    return 0;
}
