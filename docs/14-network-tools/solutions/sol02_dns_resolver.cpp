// sol02_dns_resolver.cpp — DNS Resolution Tool
// Performs forward, reverse, MX, TXT, A, and CNAME lookups.
//
// Compile:
//   g++ -std=c++17 -Wall -o sol02.exe solutions/sol02_dns_resolver.cpp -lws2_32 -ldnsapi
//
// Usage:
//   sol02.exe <hostname>          -- all lookups
//   sol02.exe --mx <domain>       -- MX records only
//   sol02.exe --reverse <ip>      -- reverse lookup only

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

// ---------------------------------------------------------------------------
// Forward lookup: A and AAAA records via getaddrinfo
// ---------------------------------------------------------------------------
static void lookup_forward(const char* hostname)
{
    printf("\n[Forward Lookup] %s\n", hostname);

    struct addrinfo hints = {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* results = NULL;
    int rc = getaddrinfo(hostname, NULL, &hints, &results);
    if (rc != 0) {
        printf("  getaddrinfo failed: %s\n", gai_strerrorA(rc));
        return;
    }

    int count = 0;
    for (struct addrinfo* ai = results; ai != NULL; ai = ai->ai_next) {
        char ip[INET6_ADDRSTRLEN] = {};
        if (ai->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)ai->ai_addr)->sin_addr, ip, sizeof(ip));
            printf("  A     %s\n", ip);
        } else if (ai->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)ai->ai_addr)->sin6_addr, ip, sizeof(ip));
            printf("  AAAA  %s\n", ip);
        }
        count++;
    }
    if (count == 0) printf("  (no results)\n");
    freeaddrinfo(results);
}

// ---------------------------------------------------------------------------
// Reverse lookup: getnameinfo on an IP string
// ---------------------------------------------------------------------------
static void lookup_reverse(const char* ip_str)
{
    printf("\n[Reverse Lookup] %s\n", ip_str);

    struct sockaddr_storage ss = {};
    int addr_len = 0;

    // Try IPv4
    struct sockaddr_in* sin4 = (struct sockaddr_in*)&ss;
    if (inet_pton(AF_INET, ip_str, &sin4->sin_addr) == 1) {
        sin4->sin_family = AF_INET;
        addr_len = sizeof(struct sockaddr_in);
    } else {
        // Try IPv6
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&ss;
        if (inet_pton(AF_INET6, ip_str, &sin6->sin6_addr) == 1) {
            sin6->sin6_family = AF_INET6;
            addr_len = sizeof(struct sockaddr_in6);
        } else {
            printf("  Invalid IP address: %s\n", ip_str);
            return;
        }
    }

    char hostname[NI_MAXHOST] = {};
    int rc = getnameinfo((struct sockaddr*)&ss, addr_len,
                         hostname, sizeof(hostname),
                         NULL, 0, NI_NAMEREQD);
    if (rc == 0) {
        printf("  PTR   %s\n", hostname);
    } else {
        printf("  getnameinfo failed: %s\n", gai_strerrorA(rc));
    }
}

// ---------------------------------------------------------------------------
// MX records via DnsQuery_A
// ---------------------------------------------------------------------------
static void lookup_mx(const char* domain)
{
    printf("\n[MX Records] %s\n", domain);

    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_A(domain, DNS_TYPE_MX,
                                    DNS_QUERY_STANDARD, NULL,
                                    &pDnsRecord, NULL);
    if (status != ERROR_SUCCESS) {
        printf("  DnsQuery_A(MX) failed: %lu\n", status);
        return;
    }

    int count = 0;
    for (PDNS_RECORD r = pDnsRecord; r != NULL; r = r->pNext) {
        if (r->wType == DNS_TYPE_MX) {
            printf("  MX    priority=%-5u  %s\n",
                   r->Data.MX.wPreference,
                   r->Data.MX.pNameExchange);
            count++;
        }
    }
    if (count == 0) printf("  (no MX records)\n");
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
}

// ---------------------------------------------------------------------------
// TXT records — SPF, DMARC, DKIM, etc.
// ---------------------------------------------------------------------------
static void lookup_txt(const char* domain)
{
    printf("\n[TXT Records] %s\n", domain);

    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_A(domain, DNS_TYPE_TEXT,
                                    DNS_QUERY_STANDARD, NULL,
                                    &pDnsRecord, NULL);
    if (status != ERROR_SUCCESS) {
        printf("  DnsQuery_A(TXT) failed: %lu\n", status);
        return;
    }

    int count = 0;
    for (PDNS_RECORD r = pDnsRecord; r != NULL; r = r->pNext) {
        if (r->wType == DNS_TYPE_TEXT) {
            for (DWORD i = 0; i < r->Data.TXT.dwStringCount; i++) {
                printf("  TXT   \"%s\"\n", r->Data.TXT.pStringArray[i]);
            }
            count++;
        }
    }
    if (count == 0) printf("  (no TXT records)\n");
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
}

// ---------------------------------------------------------------------------
// CNAME records
// ---------------------------------------------------------------------------
static void lookup_cname(const char* hostname)
{
    printf("\n[CNAME Records] %s\n", hostname);

    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_A(hostname, DNS_TYPE_CNAME,
                                    DNS_QUERY_STANDARD, NULL,
                                    &pDnsRecord, NULL);
    if (status != ERROR_SUCCESS) {
        if (status == DNS_INFO_NO_RECORDS) {
            printf("  (no CNAME records)\n");
        } else {
            printf("  DnsQuery_A(CNAME) failed: %lu\n", status);
        }
        return;
    }

    int count = 0;
    for (PDNS_RECORD r = pDnsRecord; r != NULL; r = r->pNext) {
        if (r->wType == DNS_TYPE_CNAME) {
            printf("  CNAME %s\n", r->Data.CNAME.pNameHost);
            count++;
        }
    }
    if (count == 0) printf("  (no CNAME records)\n");
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
}

// ---------------------------------------------------------------------------
static void usage(const char* prog)
{
    printf("Usage:\n");
    printf("  %s <hostname>           -- forward + MX + TXT + CNAME\n", prog);
    printf("  %s --mx <domain>        -- MX records only\n", prog);
    printf("  %s --txt <domain>       -- TXT records only\n", prog);
    printf("  %s --reverse <ip>       -- reverse (PTR) lookup\n", prog);
    printf("  %s --cname <hostname>   -- CNAME records only\n", prog);
}

int main(int argc, char* argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    if (strcmp(argv[1], "--mx") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        lookup_mx(argv[2]);
    } else if (strcmp(argv[1], "--txt") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        lookup_txt(argv[2]);
    } else if (strcmp(argv[1], "--reverse") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        lookup_reverse(argv[2]);
    } else if (strcmp(argv[1], "--cname") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        lookup_cname(argv[2]);
    } else {
        const char* host = argv[1];
        printf("=== DNS Lookup: %s ===", host);
        lookup_forward(host);
        lookup_cname(host);
        lookup_mx(host);
        lookup_txt(host);

        // Also try reverse on the first resolved IPv4
        struct addrinfo hints = {};
        hints.ai_family = AF_INET;
        struct addrinfo* res = NULL;
        if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET,
                      &((struct sockaddr_in*)res->ai_addr)->sin_addr,
                      ip, sizeof(ip));
            freeaddrinfo(res);
            lookup_reverse(ip);
        }
    }

    WSACleanup();
    return 0;
}
