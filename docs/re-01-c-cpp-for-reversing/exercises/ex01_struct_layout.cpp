// Exercise 1: Struct Memory Layout
// Goal: understand how the compiler lays out structs in memory.
//
// TASKS:
//  1. Print the size and offset of each field in each struct below.
//  2. Predict the output BEFORE running — write your prediction as a comment.
//  3. Add #pragma pack(1) to Padded and re-run. Explain the change.
//  4. Write a function that walks a byte* over a struct and prints each byte as hex.
//     Use it to print the raw memory of a PackedNetwork value.
//
// COMPILE (MSVC):  cl /W4 /std:c++17 ex01_struct_layout.cpp
// COMPILE (GCC):   g++ -Wall -std=c++17 ex01_struct_layout.cpp -o ex01

#include <cstdint>
#include <cstddef>
#include <cstdio>

// -- Struct definitions --

struct Padded {
    char    a;
    int     b;
    char    c;
    double  d;
};

// #pragma pack(1) — uncomment for task 3
// struct Padded { char a; int b; char c; double d; };

struct PackedNetwork {
    uint8_t  version;
    uint8_t  flags;
    uint16_t port;
    uint32_t ip;
};

struct Nested {
    int      x;
    Padded   inner;
    uint64_t y;
};

struct WithPointer {
    char*    name;
    uint32_t id;
    uint8_t  active;
};

// -- Helper macro --
#define SHOW_FIELD(T, field) \
    printf("  %-12s  offset=%2zu  size=%2zu\n", \
           #field, offsetof(T, field), sizeof(((T*)0)->field))

// -- Functions --

void print_struct_info() {
    printf("=== Padded ===\n");
    printf("  total size = %zu\n", sizeof(Padded));
    SHOW_FIELD(Padded, a);
    SHOW_FIELD(Padded, b);
    SHOW_FIELD(Padded, c);
    SHOW_FIELD(Padded, d);

    printf("\n=== PackedNetwork ===\n");
    printf("  total size = %zu\n", sizeof(PackedNetwork));
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
    printf("  total size = %zu\n", sizeof(WithPointer));
    SHOW_FIELD(WithPointer, name);
    SHOW_FIELD(WithPointer, id);
    SHOW_FIELD(WithPointer, active);
}

// TODO: implement for task 4
void dump_bytes(const void* ptr, size_t len) {
    // Walk ptr byte-by-byte and print as hex
    (void)ptr; (void)len;
    printf("[TODO: implement dump_bytes]\n");
}

int main() {
    print_struct_info();

    printf("\n=== Raw bytes of PackedNetwork ===\n");
    PackedNetwork pkt = { 0x04, 0x01, 0x1F90, 0xC0A80101 }; // 192.168.1.1:8080
    dump_bytes(&pkt, sizeof(pkt));

    return 0;
}
