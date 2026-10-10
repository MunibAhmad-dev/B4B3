// Solution 1: Struct Memory Layout (complete implementation)

#include <cstdint>
#include <cstddef>
#include <cstdio>

struct Padded {
    char    a;   // offset 0, size 1
    // 3 bytes padding (align int to 4)
    int     b;   // offset 4, size 4
    char    c;   // offset 8, size 1
    // 7 bytes padding (align double to 8)
    double  d;   // offset 16, size 8
};              // total: 24 bytes

#pragma pack(push, 1)
struct PaddedPacked {
    char    a;   // offset 0
    int     b;   // offset 1 (no padding!)
    char    c;   // offset 5
    double  d;   // offset 6
};              // total: 15 bytes
#pragma pack(pop)

struct PackedNetwork {
    uint8_t  version;  // offset 0
    uint8_t  flags;    // offset 1
    uint16_t port;     // offset 2  (naturally aligned to 2)
    uint32_t ip;       // offset 4  (naturally aligned to 4)
};                     // total: 8 bytes — no padding needed!

struct Nested {
    int      x;     // offset 0
    // 4 bytes padding (Padded starts at 8 due to double inside)
    Padded   inner; // offset 8
    uint64_t y;     // offset 8+24=32
};                  // total: 40 bytes

struct WithPointer {
    char*    name;   // offset 0  (8 bytes, pointer)
    uint32_t id;     // offset 8  (4 bytes)
    uint8_t  active; // offset 12 (1 byte)
    // 3 bytes padding (struct size must be multiple of 8 for alignment)
};                   // total: 16 bytes

#define SHOW_FIELD(T, field) \
    printf("  %-12s  offset=%2zu  size=%2zu\n", \
           #field, offsetof(T, field), sizeof(((T*)0)->field))

void dump_bytes(const void* ptr, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(ptr);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", p[i]);
        if ((i+1) % 8 == 0) printf("\n");
    }
    if (len % 8 != 0) printf("\n");
}

int main() {
    printf("=== Padded (with compiler padding) ===\n");
    printf("  total size = %zu  (predicted: 24)\n", sizeof(Padded));
    SHOW_FIELD(Padded, a);
    SHOW_FIELD(Padded, b);
    SHOW_FIELD(Padded, c);
    SHOW_FIELD(Padded, d);

    printf("\n=== PaddedPacked (#pragma pack 1) ===\n");
    printf("  total size = %zu  (predicted: 15)\n", sizeof(PaddedPacked));
    SHOW_FIELD(PaddedPacked, a);
    SHOW_FIELD(PaddedPacked, b);
    SHOW_FIELD(PaddedPacked, c);
    SHOW_FIELD(PaddedPacked, d);

    printf("\n=== PackedNetwork ===\n");
    printf("  total size = %zu  (predicted: 8)\n", sizeof(PackedNetwork));
    SHOW_FIELD(PackedNetwork, version);
    SHOW_FIELD(PackedNetwork, flags);
    SHOW_FIELD(PackedNetwork, port);
    SHOW_FIELD(PackedNetwork, ip);

    printf("\n=== Nested ===\n");
    printf("  total size = %zu\n", sizeof(Nested));
    SHOW_FIELD(Nested, x);
    SHOW_FIELD(Nested, inner);
    SHOW_FIELD(Nested, y);

    printf("\n=== WithPointer ===\n");
    printf("  total size = %zu  (predicted: 16)\n", sizeof(WithPointer));
    SHOW_FIELD(WithPointer, name);
    SHOW_FIELD(WithPointer, id);
    SHOW_FIELD(WithPointer, active);

    printf("\n=== Raw bytes of PackedNetwork (192.168.1.1:8080) ===\n");
    // Note: port and IP are in host byte order here — in a real network packet
    // they'd be big-endian (htons/htonl). This shows the raw struct layout.
    PackedNetwork pkt = { 0x04, 0x01, 0x1F90, 0xC0A80101 };
    dump_bytes(&pkt, sizeof(pkt));
    // Expected (little-endian): 04 01 90 1F 01 01 A8 C0
    // port 0x1F90 = 8080 stored as 90 1F (little-endian)
    // ip 0xC0A80101 = 192.168.1.1 stored as 01 01 A8 C0

    return 0;
}
