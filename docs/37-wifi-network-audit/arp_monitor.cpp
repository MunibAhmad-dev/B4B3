/*
 * arp_monitor.cpp — ARP Cache Anomaly Detector
 *
 * Monitors the Windows ARP cache continuously and alerts when:
 *   1. A MAC address is seen on multiple IPs (classic ARP poisoning)
 *   2. The gateway MAC address changes unexpectedly
 *   3. New devices appear on the network
 *
 * Compile:
 *   g++ -std=c++17 -o arp_monitor.exe arp_monitor.cpp -liphlpapi -lws2_32
 *
 * Run (as Administrator for full access):
 *   arp_monitor.exe
 *   arp_monitor.exe --gateway 192.168.1.1
 *   arp_monitor.exe --interval 5 --log arp_log.txt
 */

#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <fstream>
#include <ctime>
#include <algorithm>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct ArpEntry {
    std::string ip;
    std::string mac;
    DWORD type; // MIB_IPNET_TYPE_DYNAMIC, STATIC, etc.
};

struct Config {
    int interval_sec  = 3;
    std::string gateway_ip;
    std::string log_file;
    bool verbose = false;
};

// ─── helpers ────────────────────────────────────────────────────────────────

static std::string ip_to_str(DWORD ip_network_order) {
    in_addr a;
    a.s_addr = ip_network_order;
    return std::string(inet_ntoa(a));
}

static std::string mac_to_str(const BYTE* mac, DWORD len) {
    if (len == 0) return "(none)";
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

static std::string timestamp() {
    time_t t = time(nullptr);
    struct tm tm_info;
    localtime_s(&tm_info, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    return std::string(buf);
}

static void log_alert(const std::string& msg, const Config& cfg) {
    std::string line = "[ALERT][" + timestamp() + "] " + msg;
    printf("\033[91m%s\033[0m\n", line.c_str()); // red
    if (!cfg.log_file.empty()) {
        std::ofstream f(cfg.log_file, std::ios::app);
        if (f) f << line << "\n";
    }
}

static void log_info(const std::string& msg, const Config& cfg) {
    if (!cfg.verbose) return;
    std::string line = "[INFO][" + timestamp() + "] " + msg;
    printf("\033[90m%s\033[0m\n", line.c_str()); // grey
    if (!cfg.log_file.empty()) {
        std::ofstream f(cfg.log_file, std::ios::app);
        if (f) f << line << "\n";
    }
}

// ─── ARP table reader ────────────────────────────────────────────────────────

static std::vector<ArpEntry> read_arp_table() {
    std::vector<ArpEntry> result;

    ULONG buf_size = sizeof(MIB_IPNETTABLE) + 512 * sizeof(MIB_IPNETROW);
    std::vector<BYTE> buf(buf_size);
    MIB_IPNETTABLE* table = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());

    DWORD ret = GetIpNetTable(table, &buf_size, FALSE);
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
        buf.resize(buf_size);
        table = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());
        ret = GetIpNetTable(table, &buf_size, FALSE);
    }
    if (ret != NO_ERROR) return result;

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPNETROW& row = table->table[i];
        if (row.dwType == MIB_IPNET_TYPE_INVALID) continue;

        ArpEntry e;
        e.ip   = ip_to_str(row.dwAddr);
        e.mac  = mac_to_str(row.bPhysAddr, row.dwPhysAddrLen);
        e.type = row.dwType;
        result.push_back(e);
    }
    return result;
}

// ─── anomaly detection ───────────────────────────────────────────────────────

static void detect_anomalies(
    const std::vector<ArpEntry>& current,
    const std::map<std::string, std::string>& baseline, // ip → mac
    const std::string& gateway_ip,
    const std::string& gateway_mac_baseline,
    std::map<std::string, std::string>& known_devices, // ip → mac (grows)
    const Config& cfg)
{
    // Build mac → [ips] map for duplicate MAC detection
    std::map<std::string, std::vector<std::string>> mac_to_ips;
    for (auto& e : current) {
        mac_to_ips[e.mac].push_back(e.ip);
    }

    // Check 1: same MAC on multiple IPs (ARP poisoning signature)
    for (auto& [mac, ips] : mac_to_ips) {
        if (ips.size() > 1) {
            std::string ip_list;
            for (auto& ip : ips) ip_list += ip + " ";
            log_alert("DUPLICATE MAC " + mac + " seen on multiple IPs: " + ip_list, cfg);
        }
    }

    for (auto& e : current) {
        // Check 2: gateway MAC changed
        if (!gateway_ip.empty() && e.ip == gateway_ip) {
            if (!gateway_mac_baseline.empty() && e.mac != gateway_mac_baseline) {
                log_alert(
                    "GATEWAY MAC CHANGED! "
                    + gateway_ip + " was " + gateway_mac_baseline
                    + " now " + e.mac
                    + " — possible ARP poisoning!", cfg);
            }
        }

        // Check 3: MAC changed for a known device
        auto it = baseline.find(e.ip);
        if (it != baseline.end() && it->second != e.mac) {
            log_alert(
                "MAC CHANGED for " + e.ip
                + " was " + it->second
                + " now " + e.mac, cfg);
        }

        // Track new devices
        if (known_devices.find(e.ip) == known_devices.end()) {
            known_devices[e.ip] = e.mac;
            log_info("New device: " + e.ip + " (" + e.mac + ")", cfg);
        }
    }
}

// ─── display ─────────────────────────────────────────────────────────────────

static void print_arp_table(const std::vector<ArpEntry>& entries) {
    printf("\n  %-18s %-20s %s\n", "IP", "MAC", "Type");
    printf("  %-18s %-20s %s\n",
           "------------------", "-------------------", "-------");
    for (auto& e : entries) {
        const char* type_str = "dynamic";
        if (e.type == MIB_IPNET_TYPE_STATIC)  type_str = "static";
        if (e.type == MIB_IPNET_TYPE_OTHER)   type_str = "other";
        printf("  %-18s %-20s %s\n", e.ip.c_str(), e.mac.c_str(), type_str);
    }
    printf("\n");
}

// ─── main ─────────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("  --gateway  <ip>    Monitor this IP as the gateway (extra alert if MAC changes)\n");
    printf("  --interval <sec>   Poll interval in seconds (default: 3)\n");
    printf("  --log      <file>  Write alerts to log file\n");
    printf("  --verbose          Show info messages (new devices, etc.)\n");
    printf("  --once             Print ARP table once and exit\n");
}

int main(int argc, char** argv) {
    Config cfg;
    bool once = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--gateway"  && i+1 < argc) cfg.gateway_ip  = argv[++i];
        else if (arg == "--interval" && i+1 < argc) cfg.interval_sec = atoi(argv[++i]);
        else if (arg == "--log"      && i+1 < argc) cfg.log_file     = argv[++i];
        else if (arg == "--verbose")  cfg.verbose = true;
        else if (arg == "--once")     once = true;
        else if (arg == "--help" || arg == "-h") { print_usage(argv[0]); return 0; }
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║       ARP Cache Monitor v1.0             ║\n");
    printf("║  Detects ARP poisoning / MITM attacks    ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    printf("[*] Poll interval : %d seconds\n", cfg.interval_sec);
    if (!cfg.gateway_ip.empty())
        printf("[*] Monitoring gateway: %s\n", cfg.gateway_ip.c_str());
    if (!cfg.log_file.empty())
        printf("[*] Log file: %s\n", cfg.log_file.c_str());
    printf("[*] Started: %s\n\n", timestamp().c_str());

    // --once mode
    if (once) {
        auto entries = read_arp_table();
        printf("[*] Current ARP cache (%zu entries):\n", entries.size());
        print_arp_table(entries);

        // Check for duplicate MACs right now
        std::map<std::string, std::vector<std::string>> mac_map;
        for (auto& e : entries) mac_map[e.mac].push_back(e.ip);
        bool clean = true;
        for (auto& [mac, ips] : mac_map) {
            if (ips.size() > 1) {
                printf("[!] WARNING: MAC %s appears on %zu IPs: ", mac.c_str(), ips.size());
                for (auto& ip : ips) printf("%s ", ip.c_str());
                printf("\n");
                clean = false;
            }
        }
        if (clean) printf("[+] No duplicate MACs found — ARP cache looks clean.\n");
        WSACleanup();
        return 0;
    }

    // Continuous monitoring mode
    printf("[*] Taking baseline snapshot...\n");
    auto baseline_entries = read_arp_table();
    std::map<std::string, std::string> baseline; // ip → mac
    std::string gateway_mac_baseline;

    for (auto& e : baseline_entries) {
        baseline[e.ip] = e.mac;
        if (e.ip == cfg.gateway_ip)
            gateway_mac_baseline = e.mac;
    }

    printf("[*] Baseline: %zu devices in ARP cache\n", baseline.size());
    if (!cfg.gateway_ip.empty() && !gateway_mac_baseline.empty())
        printf("[*] Gateway baseline MAC: %s\n\n", gateway_mac_baseline.c_str());
    else if (!cfg.gateway_ip.empty())
        printf("[!] Gateway %s not in ARP cache yet — will track when seen\n\n",
               cfg.gateway_ip.c_str());

    printf("[*] Monitoring... Press Ctrl+C to stop.\n\n");

    std::map<std::string, std::string> known_devices = baseline;
    std::string current_gw_mac = gateway_mac_baseline;

    while (true) {
        Sleep(cfg.interval_sec * 1000);

        auto current = read_arp_table();

        // Update gateway MAC baseline if we just first saw it
        if (!cfg.gateway_ip.empty() && current_gw_mac.empty()) {
            for (auto& e : current) {
                if (e.ip == cfg.gateway_ip) {
                    current_gw_mac = e.mac;
                    printf("[*] Gateway %s MAC set to %s\n",
                           cfg.gateway_ip.c_str(), current_gw_mac.c_str());
                    break;
                }
            }
        }

        detect_anomalies(current, baseline, cfg.gateway_ip, current_gw_mac,
                         known_devices, cfg);

        // Update baseline for non-gateway IPs (normal MACs drift as devices reconnect)
        // Only update for non-alert entries
        for (auto& e : current) {
            if (e.ip != cfg.gateway_ip)
                baseline[e.ip] = e.mac;
        }
    }

    WSACleanup();
    return 0;
}
