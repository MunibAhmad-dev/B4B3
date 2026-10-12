#pragma once
#ifndef NETSCAN_H
#define NETSCAN_H
#include "common.h"

namespace NetScan {
    // ICMP ping-sweep every .1–.254 on the given /24 prefix (e.g. "192.168.1").
    // Detection: rapid ICMP echo requests from a non-network tool = T1018 Remote System Discovery.
    std::string PingSweep(const std::string& prefix);

    // TCP connect-scan ip:startPort..endPort (300 ms timeout per port).
    // Detection: rapid SYN connections to sequential ports = T1046 Network Service Scanning.
    std::string PortScan(const std::string& ip, int startPort, int endPort);

    // Dump the local ARP cache (no new packets — purely passive read via GetIpNetTable).
    // Detection: GetIpNetTable from a suspicious process = T1016 System Network Configuration Discovery.
    std::string ArpCache();
}

#endif
