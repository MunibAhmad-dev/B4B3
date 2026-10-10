// ex01_cpuid_dump.cpp — CPUID leaf inspection
// TODO: Call CPUID at leaves 0x00, 0x01, 0x07, 0x40000000, 0x80000002-04
//       and print the results in a readable table.
// TODO: Detect hypervisor bit (ECX[31] at leaf 1) and hypervisor vendor string.
// Compile: g++ -std=c++17 -o ex01.exe ex01_cpuid_dump.cpp
#include <intrin.h>
#include <stdio.h>
int main() {
    // YOUR CODE HERE
    printf("CPUID exercise — implement the TODOs\n");
    return 0;
}
