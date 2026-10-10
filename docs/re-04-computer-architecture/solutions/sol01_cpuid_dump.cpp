// sol01_cpuid_dump.cpp — CPUID solution
// Compile: g++ -std=c++17 -o sol01.exe sol01_cpuid_dump.cpp
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>

static void print_cpuid(uint32_t leaf) {
    int r[4]{};
    __cpuid(r, leaf);
    printf("  leaf=0x%08X  EAX=%08X EBX=%08X ECX=%08X EDX=%08X\n",
           leaf, r[0], r[1], r[2], r[3]);
}

int main() {
    int r[4]{};
    printf("=== CPUID Dump ===\n\n");

    __cpuid(r, 0);
    char vendor[13]{};
    *(int*)(vendor+0) = r[1];
    *(int*)(vendor+4) = r[3];
    *(int*)(vendor+8) = r[2];
    printf("Vendor: %s  MaxLeaf: 0x%X\n\n", vendor, r[0]);

    printf("Standard leaves:\n");
    for (uint32_t leaf = 0; leaf <= 0x07; ++leaf) print_cpuid(leaf);

    __cpuid(r, 1);
    bool hypervisor = (r[2] >> 31) & 1;
    printf("\nHypervisor bit: %s\n", hypervisor ? "SET (VM detected!)" : "clear");

    if (hypervisor) {
        __cpuid(r, 0x40000000);
        char hv[13]{};
        *(int*)(hv+0) = r[1];
        *(int*)(hv+4) = r[2];
        *(int*)(hv+8) = r[3];
        printf("Hypervisor vendor: %.12s\n", hv);
    }

    printf("\nBrand string:\n  ");
    for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
        __cpuid(r, leaf);
        for (int i = 0; i < 4; ++i) printf("%.4s", (char*)&r[i]);
    }
    printf("\n");
    return 0;
}
