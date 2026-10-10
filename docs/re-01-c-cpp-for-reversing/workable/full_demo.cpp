// RE-01 Full Demo: C/C++ Internals Inspector
// Combines struct layout, vtable inspection, calling convention analysis,
// and FNV-1a hash (malware pattern recognition) in one runnable tool.
//
// COMPILE (MSVC):  cl /W4 /std:c++17 full_demo.cpp /Fe:re01_demo.exe
// COMPILE (GCC):   g++ -Wall -std=c++17 full_demo.cpp -o re01_demo
// RUN:             re01_demo.exe [or ./re01_demo]

#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>

#ifdef _WIN32
  #define NOINLINE __declspec(noinline)
#else
  #define NOINLINE __attribute__((noinline))
#endif

// ============================================================
// SECTION 1: Struct Layout Visualizer
// ============================================================

#define PRINT_FIELD(T, f) \
    printf("  %-20s  offset=%3zu  size=%3zu\n", \
           #f, offsetof(T,f), sizeof(((T*)0)->f))

struct CommonMalwareHeader {
    uint32_t magic;        // 0x4D414C57 "MALW"
    uint16_t version;
    uint16_t flags;
    uint32_t payload_size;
    uint32_t checksum;
    uint64_t timestamp;
    uint8_t  key[16];
};

void section1_struct_layout() {
    printf("\n========== SECTION 1: Struct Layout ==========\n");
    printf("CommonMalwareHeader size = %zu bytes\n", sizeof(CommonMalwareHeader));
    PRINT_FIELD(CommonMalwareHeader, magic);
    PRINT_FIELD(CommonMalwareHeader, version);
    PRINT_FIELD(CommonMalwareHeader, flags);
    PRINT_FIELD(CommonMalwareHeader, payload_size);
    PRINT_FIELD(CommonMalwareHeader, checksum);
    PRINT_FIELD(CommonMalwareHeader, timestamp);
    PRINT_FIELD(CommonMalwareHeader, key);
    assert(sizeof(CommonMalwareHeader) == 40);  // no padding needed — all naturally aligned

    // Build a sample header and dump bytes
    CommonMalwareHeader hdr = {};
    hdr.magic        = 0x4D414C57;
    hdr.version      = 1;
    hdr.flags        = 0x0003;
    hdr.payload_size = 0x1000;
    hdr.checksum     = 0xDEADBEEF;
    hdr.timestamp    = 0x0000000100000000ULL;
    memset(hdr.key, 0xAA, 16);

    printf("\nRaw bytes of sample header:\n  ");
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&hdr);
    for (size_t i = 0; i < sizeof(hdr); i++) {
        printf("%02X ", p[i]);
        if ((i+1) % 8 == 0) printf("\n  ");
    }
    printf("\n");
}

// ============================================================
// SECTION 2: vtable Inspection
// ============================================================

class C2Channel {
public:
    uint32_t id;
    explicit C2Channel(uint32_t i) : id(i) {}
    virtual bool connect(const char* host, uint16_t port) = 0;
    virtual int  send(const void* data, size_t len)       = 0;
    virtual int  recv(void* buf, size_t maxlen)           = 0;
    virtual void disconnect()                             = 0;
    virtual ~C2Channel() {}
};

class HttpChannel : public C2Channel {
public:
    explicit HttpChannel(uint32_t i) : C2Channel(i) {}
    bool connect(const char* host, uint16_t port) override {
        printf("  [HTTP] Connecting to %s:%u\n", host, port);
        return true;
    }
    int send(const void* data, size_t len) override {
        printf("  [HTTP] Sending %zu bytes\n", len);
        return (int)len;
    }
    int recv(void* buf, size_t maxlen) override {
        (void)buf; printf("  [HTTP] Recv up to %zu bytes\n", maxlen); return 0;
    }
    void disconnect() override { printf("  [HTTP] Disconnected\n"); }
};

class DnsChannel : public C2Channel {
public:
    explicit DnsChannel(uint32_t i) : C2Channel(i) {}
    bool connect(const char* host, uint16_t port) override {
        printf("  [DNS] Tunneling to %s:%u\n", host, port);
        return true;
    }
    int send(const void* data, size_t len) override {
        printf("  [DNS] Encoding %zu bytes as DNS labels\n", len);
        return (int)len;
    }
    int recv(void* buf, size_t maxlen) override {
        (void)buf; printf("  [DNS] Recv via TXT records, max %zu\n", maxlen); return 0;
    }
    void disconnect() override { printf("  [DNS] Flushed DNS cache\n"); }
};

void section2_vtable() {
    printf("\n========== SECTION 2: vtable Inspection ==========\n");

    HttpChannel http(1);
    DnsChannel  dns(2);

    // Show vtable pointer
    auto show_vptr = [](C2Channel* ch, const char* lbl) {
        uintptr_t vptr = *reinterpret_cast<uintptr_t*>(ch);
        printf("[%s] vptr=0x%016llX\n", lbl, (unsigned long long)vptr);
        // vtable layout: [dtor, connect, send, recv, disconnect, ...]
        uintptr_t* vt = reinterpret_cast<uintptr_t*>(vptr);
        const char* names[] = {"dtor","connect","send","recv","disconnect"};
        for (int i = 0; i < 5; i++)
            printf("  vtable[%d] %-12s = 0x%016llX\n", i, names[i], (unsigned long long)vt[i]);
    };

    show_vptr(&http, "HttpChannel");
    printf("\n");
    show_vptr(&dns,  "DnsChannel");

    // Virtual dispatch demo
    printf("\n[Dispatch through base pointer]\n");
    C2Channel* channels[] = { &http, &dns };
    for (auto* ch : channels) {
        ch->connect("192.168.1.100", 4444);
        const char msg[] = "beacon";
        ch->send(msg, sizeof(msg));
        ch->disconnect();
        printf("\n");
    }
}

// ============================================================
// SECTION 3: FNV-1a Hash (Common Malware Pattern)
// ============================================================

NOINLINE uint32_t fnv1a_32(const char* s) {
    uint32_t h = 0x811C9DC5u;
    while (*s) { h ^= (uint8_t)*s++; h *= 0x01000193u; }
    return h;
}

// Malware often uses a hash of the API name instead of the string
// to avoid detection.  Pre-compute expected hashes at compile time.
constexpr uint32_t FNV_BASIS = 0x811C9DC5u;
constexpr uint32_t FNV_PRIME = 0x01000193u;

constexpr uint32_t fnv1a_ct(const char* s, uint32_t h = FNV_BASIS) {
    return (*s == 0) ? h : fnv1a_ct(s+1, (h ^ (uint8_t)*s) * FNV_PRIME);
}

void section3_hash_api() {
    printf("\n========== SECTION 3: FNV-1a API Name Hashing ==========\n");
    struct { const char* name; uint32_t expected; } apis[] = {
        {"VirtualAlloc",     fnv1a_ct("VirtualAlloc")    },
        {"VirtualProtect",   fnv1a_ct("VirtualProtect")  },
        {"CreateRemoteThread",fnv1a_ct("CreateRemoteThread")},
        {"LoadLibraryA",     fnv1a_ct("LoadLibraryA")    },
        {"GetProcAddress",   fnv1a_ct("GetProcAddress")  },
        {"WriteProcessMemory",fnv1a_ct("WriteProcessMemory")},
    };

    for (auto& a : apis) {
        uint32_t computed = fnv1a_32(a.name);
        printf("  %-25s  hash=0x%08X  match=%s\n",
               a.name, computed, computed == a.expected ? "OK" : "FAIL");
    }

    printf("\nWhen you see 0x%08X in disasm, it's VirtualAlloc being looked up.\n",
           fnv1a_ct("VirtualAlloc"));
}

// ============================================================
// SECTION 4: Function Pointer Table (Malware Dispatch)
// ============================================================

typedef void (*HandlerFn)(const uint8_t* data, size_t len);

NOINLINE void cmd_exec   (const uint8_t* d, size_t n) { printf("[exec]   %zu bytes\n", n); (void)d; }
NOINLINE void cmd_upload (const uint8_t* d, size_t n) { printf("[upload] %zu bytes\n", n); (void)d; }
NOINLINE void cmd_download(const uint8_t* d, size_t n){ printf("[dl]     %zu bytes\n", n); (void)d; }
NOINLINE void cmd_shell  (const uint8_t* d, size_t n) { printf("[shell]  %zu bytes\n", n); (void)d; }

void section4_dispatch_table() {
    printf("\n========== SECTION 4: Function Pointer Dispatch Table ==========\n");

    // This is exactly how a RAT's command dispatcher looks in disasm:
    // A table of function pointers indexed by command ID.
    HandlerFn dispatch[4] = { cmd_exec, cmd_upload, cmd_download, cmd_shell };

    printf("Dispatch table addresses:\n");
    for (int i = 0; i < 4; i++)
        printf("  [%d] = 0x%016llX\n", i, (unsigned long long)(uintptr_t)dispatch[i]);

    // Simulate receiving commands
    const char* names[] = {"exec","upload","download","shell"};
    uint8_t dummy[8] = {0};
    for (int cmd = 0; cmd < 4; cmd++) {
        printf("Executing cmd %d (%s): ", cmd, names[cmd]);
        dispatch[cmd](dummy, sizeof(dummy));  // generates: call [rax+N] in asm
    }
}

// ============================================================
// MAIN
// ============================================================

int main() {
    printf("RE-01 C/C++ Internals Demo\n");
    printf("===========================\n");

    section1_struct_layout();
    section2_vtable();
    section3_hash_api();
    section4_dispatch_table();

    printf("\n[Done]\n");
    return 0;
}
