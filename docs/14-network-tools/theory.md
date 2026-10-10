# Module 14 — Network Tools

## 1. Port Scanner

A port scanner finds open TCP ports on a target. Essential for reconnaissance
and for building internal network scanners for your blue team.

```cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <thread>
#include <mutex>

struct ScanResult { int port; bool open; };
std::vector<ScanResult> results;
std::mutex resultsMtx;

void scanPort(const char* host, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Set non-blocking
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    connect(s, (sockaddr*)&addr, sizeof(addr));

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    struct timeval tv = { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };

    bool open = (select(0, nullptr, &fds, nullptr, &tv) > 0);

    closesocket(s);

    std::lock_guard<std::mutex> lock(resultsMtx);
    results.push_back({port, open});
}

void portScan(const char* host, int startPort, int endPort, int threads) {
    std::vector<std::thread> pool;
    for (int port = startPort; port <= endPort; port++) {
        pool.emplace_back(scanPort, host, port, 500);
        if ((int)pool.size() >= threads) {
            for (auto& t : pool) t.join();
            pool.clear();
        }
    }
    for (auto& t : pool) t.join();
}
```

**Banner grabbing** — after connecting, read the first bytes the server sends:
```cpp
// After connect, read banner:
char banner[256] = {};
int r = recv(s, banner, sizeof(banner)-1, 0);
if (r > 0) printf("  Banner: %s\n", banner);
```

---

## 2. Packet Capture (Raw Sockets)

Raw sockets let you receive all packets at the network layer.
Requires admin on Windows.

```cpp
// Promiscuous mode capture using raw socket
SOCKET raw = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

struct sockaddr_in local = {};
local.sin_family      = AF_INET;
local.sin_addr.s_addr = inet_addr("192.168.1.100");  // your local IP
bind(raw, (sockaddr*)&local, sizeof(local));

// Enable promiscuous mode
DWORD optval = 1;
ioctlsocket(raw, SIO_RCVALL, &optval);

char buf[65535];
while (true) {
    int r = recv(raw, buf, sizeof(buf), 0);
    if (r > 0) {
        // buf contains raw IP packet
        struct iphdr* ip = (struct iphdr*)buf;
        // ip->protocol: 6=TCP, 17=UDP, 1=ICMP
        // ip->saddr, ip->daddr: source/dest IP
    }
}
```

**Better approach:** use WinPcap / Npcap for production packet capture.
Raw sockets on Windows don't capture sent traffic, only received.

---

## 3. DNS Query

```cpp
#include <windns.h>

void dnsLookup(const char* hostname) {
    PDNS_RECORD records = nullptr;
    DNS_STATUS status = DnsQuery_A(hostname, DNS_TYPE_A, DNS_QUERY_STANDARD,
                                    nullptr, &records, nullptr);
    if (status == ERROR_SUCCESS) {
        for (PDNS_RECORD r = records; r; r = r->pNext) {
            if (r->wType == DNS_TYPE_A) {
                IN_ADDR addr;
                addr.s_addr = r->Data.A.IpAddress;
                printf("%s → %s\n", hostname, inet_ntoa(addr));
            }
        }
        DnsFree(records, DnsFreeRecordList);
    }
}

// DNS C2 channel: encode data as subdomain labels
// data.AABB.c2domain.com → the C2 sees "AABB" in the DNS query logs
// Harder to block than HTTP — DNS is rarely filtered entirely
```

---

## 4. HTTP Server (Minimal)

Sometimes a company wants a lightweight HTTP server for their tooling —
a webhook receiver, a simple API endpoint, or an internal dashboard.

```cpp
#include <winsock2.h>

void serveHttp(int port) {
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(server, (sockaddr*)&addr, sizeof(addr));
    listen(server, 10);

    while (true) {
        SOCKET client = accept(server, nullptr, nullptr);

        char buf[4096] = {};
        recv(client, buf, sizeof(buf)-1, 0);
        // buf now contains HTTP request: "GET /path HTTP/1.1\r\nHost: ...\r\n\r\n"

        // Parse: first line = method + path
        std::string request(buf);
        std::string response;

        if (request.find("GET /health") != std::string::npos)
            response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        else
            response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

        send(client, response.c_str(), (int)response.size(), 0);
        closesocket(client);
    }
}
```

---

## 5. HTTPS Proxy / MITM (Concept)

An HTTPS proxy sits between a client and a server. For security testing:

1. Client sends `CONNECT target:443 HTTP/1.1` to the proxy
2. Proxy connects to `target:443`
3. Proxy presents its own certificate to the client (must trust proxy CA)
4. Proxy decrypts the client's TLS, reads the plaintext, re-encrypts to target

**Blue team use:** corporate HTTPS inspection proxies do this legitimately.
Install the corporate CA cert in the trust store → all HTTPS is inspectable.

**Red team use:** intercept credentials on a network segment you control.
Requires ARP spoofing or being a default gateway.

**Not built in this module** (requires a TLS library like OpenSSL) — but
understanding the concept is essential for interpreting network traffic.

---

## 6. ARP Spoofing (Concept — LAN Only)

Send gratuitous ARP replies telling the network "I am the router" to intercept
traffic. Requires raw socket access and typically admin on the attacker machine.

```
Normal:
  Victim → Router → Internet

After ARP spoof:
  Victim → Attacker → Router → Internet (attacker can see/modify all traffic)
```

Detected by: ARP inspection (dynamic ARP inspection on managed switches),
network anomaly detection (multiple MACs claiming same IP).

---

## Exercises

- `ex01_port_scanner.cpp` — threaded port scanner with banner grabbing
- `ex02_dns_resolver.cpp` — DNS lookup, reverse lookup, MX/TXT record query
- `ex03_http_server.cpp` — minimal HTTP server, routes, request parsing
- `ex04_network_inventory.cpp` — scan local /24 subnet for live hosts + open ports
