// exercise_03_network_monitor.cpp
// Module 12 Exercise 03 — Network Connection Monitor
// Compile: g++ -std=c++17 -Wall -o ex03.exe exercise_03_network_monitor.cpp -liphlpapi
//
// Goal: Snapshot TCP connections using the IP Helper API and detect new / closed
//       connections over time.  This is a key signal for C2 traffic detection.
//
// What you will practice:
//   - GetExtendedTcpTable to enumerate TCP owner-PID rows
//   - Using inet_ntop to convert DWORD addresses to dotted-decimal strings
//   - Building a connection key and storing state in a std::map
//   - Printing NEW / CLOSED events with local:port -> remote:port and state name

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>

// ========================================================= TCP state names ===

static const char* tcp_state_name(DWORD state) {
    switch (state) {
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
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                        return "UNKNOWN";
    }
}

// ===================================================== Address formatting ====

// Converts a network-order DWORD address and port to "a.b.c.d:p" string.
static std::string addr_str(DWORD addr, DWORD net_port) {
    struct in_addr in;
    in.s_addr = addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in, ip, sizeof ip);
    return std::string(ip) + ":" + std::to_string(ntohs(static_cast<u_short>(net_port)));
}

// ======================================================= Connection record ===

// A connection is uniquely identified by its 5-tuple (proto implicit = TCP/IPv4).
struct ConnKey {
    DWORD local_addr, local_port;
    DWORD remote_addr, remote_port;
    DWORD pid;

    bool operator<(const ConnKey& o) const {
        if (local_addr  != o.local_addr)  return local_addr  < o.local_addr;
        if (local_port  != o.local_port)  return local_port  < o.local_port;
        if (remote_addr != o.remote_addr) return remote_addr < o.remote_addr;
        if (remote_port != o.remote_port) return remote_port < o.remote_port;
        return pid < o.pid;
    }
};

struct ConnInfo {
    ConnKey     key;
    DWORD       state;
};

using ConnMap = std::map<ConnKey, ConnInfo>;

// ============================================================ TCP snapshot ===

// Returns all current IPv4 TCP connections keyed by their 5-tuple.
static ConnMap snapshot_tcp() {
    ConnMap result;

    // Step 1: query required buffer size
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    // Step 2: allocate and fill
    std::vector<BYTE> buf(size + 128);  // small extra margin for TOCTOU
    if (GetExtendedTcpTable(buf.data(), &size, TRUE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return result;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        ConnKey k{
            row.dwLocalAddr,  row.dwLocalPort,
            row.dwRemoteAddr, row.dwRemotePort,
            row.dwOwningPid
        };
        result[k] = { k, row.dwState };
    }
    return result;
}

// ========================================================= Diff and print ===

static void diff_conns(const ConnMap& prev, const ConnMap& curr) {
    // Entries in curr not in prev = NEW connections
    for (const auto& [k, info] : curr) {
        if (prev.find(k) == prev.end()) {
            std::cout << "  [NEW]    PID=" << std::setw(6) << k.pid
                      << "  " << addr_str(k.local_addr, k.local_port)
                      << " -> " << addr_str(k.remote_addr, k.remote_port)
                      << "  " << tcp_state_name(info.state) << "\n";
        }
    }
    // Entries in prev not in curr = CLOSED connections
    for (const auto& [k, info] : prev) {
        if (curr.find(k) == curr.end()) {
            std::cout << "  [CLOSED] PID=" << std::setw(6) << k.pid
                      << "  " << addr_str(k.local_addr, k.local_port)
                      << " -> " << addr_str(k.remote_addr, k.remote_port) << "\n";
        }
    }
}

// =========================================================== Timestamp ======

static std::string now_str() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d",
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    int interval_s = 3;
    if (argc >= 2) {
        try { interval_s = std::stoi(argv[1]); }
        catch (...) {}
    }

    std::cout << "[NetMon] Monitoring TCP connections every "
              << interval_s << "s. Ctrl+C to stop.\n\n";

    // Print initial state
    ConnMap prev = snapshot_tcp();
    std::cout << "[NetMon] Initial snapshot: " << prev.size() << " connection(s).\n";
    for (const auto& [k, info] : prev) {
        std::cout << "  PID=" << std::setw(6) << k.pid
                  << "  " << addr_str(k.local_addr, k.local_port)
                  << " -> " << addr_str(k.remote_addr, k.remote_port)
                  << "  " << tcp_state_name(info.state) << "\n";
    }
    std::cout << "\n";

    for (;;) {
        Sleep(static_cast<DWORD>(interval_s) * 1000);

        ConnMap curr = snapshot_tcp();
        std::cout << "[" << now_str() << "] TCP snapshot ("
                  << curr.size() << " connections)\n";

        diff_conns(prev, curr);

        prev = curr;
    }

    WSACleanup();
    return 0;
}
