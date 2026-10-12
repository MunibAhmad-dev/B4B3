#include "NetScan.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Icmp.lib")

// ── ICMP ping-sweep ────────────────────────────────────────────────────────────
// Detection: IcmpSendEcho from a non-ping process, 254 rapid probes in sequence
// (Sysmon network connection events, Windows Defender Network Inspection).
// MITRE T1018 Remote System Discovery.

std::string NetScan::PingSweep(const std::string& prefix) {
    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2,2), &wsa);

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        WSACleanup();
        return "netscan sweep: IcmpCreateFile failed err=" + std::to_string(GetLastError());
    }

    BYTE reqData[32] = {};
    DWORD replyBufSz = sizeof(ICMP_ECHO_REPLY) + sizeof(reqData) + 16;
    std::vector<BYTE> replyBuf(replyBufSz);

    std::string out = "ICMP sweep " + prefix + ".0/24\n";
    int alive = 0;

    for (int i = 1; i <= 254; ++i) {
        std::string ip = prefix + "." + std::to_string(i);
        DWORD dst = inet_addr(ip.c_str());
        if (dst == INADDR_NONE) continue;

        memset(replyBuf.data(), 0, replyBufSz);
        DWORD ret = IcmpSendEcho(hIcmp, dst, reqData, (WORD)sizeof(reqData),
                                  NULL, replyBuf.data(), replyBufSz, 300);
        if (ret > 0) {
            auto* reply = (ICMP_ECHO_REPLY*)replyBuf.data();
            if (reply->Status == IP_SUCCESS) {
                out += "  ALIVE  " + ip +
                       "  RTT=" + std::to_string(reply->RoundTripTime) + "ms\n";
                ++alive;
            }
        }
    }

    IcmpCloseHandle(hIcmp);
    WSACleanup();
    out += "\n" + std::to_string(alive) + " host(s) alive out of 254 probed";
    return out;
}

// ── TCP port scan ──────────────────────────────────────────────────────────────
// Detection: rapid outbound SYN to sequential ports on a single target.
// Sysmon EventID 3 (NetworkConnect) fires on each, generating a burst.
// MITRE T1046 Network Service Scanning.

std::string NetScan::PortScan(const std::string& ip, int startPort, int endPort) {
    if (startPort < 1 || endPort > 65535 || startPort > endPort)
        return "portscan: invalid range";

    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2,2), &wsa);

    std::string out = "TCP scan " + ip + " [" +
                      std::to_string(startPort) + "-" + std::to_string(endPort) + "]\n";
    int open = 0;

    for (int port = startPort; port <= endPort; ++port) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;

        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);

        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((u_short)port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        connect(s, (sockaddr*)&addr, sizeof(addr));

        fd_set wr;
        FD_ZERO(&wr);
        FD_SET(s, &wr);
        timeval tv = {0, 300000};
        int sel = select(0, NULL, &wr, NULL, &tv);

        if (sel > 0) {
            int err = 0, len = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
            if (err == 0) {
                out += "  OPEN  " + std::to_string(port) + "\n";
                ++open;
            }
        }
        closesocket(s);
    }

    WSACleanup();
    out += "\n" + std::to_string(open) + " open port(s)";
    return out;
}

// ── ARP cache dump ─────────────────────────────────────────────────────────────
// Reads the OS ARP table via GetIpNetTable — no packets sent, purely passive.
// Still a detection signal: a suspicious process reading the full ARP table is
// logged by some EDRs as T1016 System Network Configuration Discovery.

std::string NetScan::ArpCache() {
    ULONG sz = 0;
    GetIpNetTable(NULL, &sz, FALSE);
    if (sz == 0) return "arpcache: GetIpNetTable size=0";

    std::vector<BYTE> buf(sz);
    auto* table = (MIB_IPNETTABLE*)buf.data();
    DWORD ret = GetIpNetTable(table, &sz, TRUE);
    if (ret != NO_ERROR && ret != ERROR_INSUFFICIENT_BUFFER)
        return "arpcache: GetIpNetTable failed err=" + std::to_string(ret);

    std::string out = "ARP cache (" + std::to_string(table->dwNumEntries) + " entries):\n";
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& e = table->table[i];

        // Format IP
        in_addr ia; ia.s_addr = e.dwAddr;
        char ipStr[20] = {}; inet_ntop(AF_INET, &ia, ipStr, sizeof(ipStr));

        // Format MAC
        char macStr[24] = {};
        if (e.dwPhysAddrLen == 6) {
            snprintf(macStr, sizeof(macStr), "%02X-%02X-%02X-%02X-%02X-%02X",
                     e.bPhysAddr[0], e.bPhysAddr[1], e.bPhysAddr[2],
                     e.bPhysAddr[3], e.bPhysAddr[4], e.bPhysAddr[5]);
        } else {
            snprintf(macStr, sizeof(macStr), "(no MAC)");
        }

        const char* typeStr =
            e.dwType == MIB_IPNET_TYPE_DYNAMIC ? "dynamic" :
            e.dwType == MIB_IPNET_TYPE_STATIC  ? "static"  :
            e.dwType == MIB_IPNET_TYPE_OTHER   ? "other"   : "invalid";

        out += "  " + std::string(ipStr) + "\t" + macStr + "\t" + typeStr + "\n";
    }
    return out;
}
