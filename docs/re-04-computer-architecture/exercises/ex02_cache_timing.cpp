// ex02_cache_timing.cpp — Cache timing + RDTSC anti-debug
// TODO 1: Allocate a 4MB buffer. Access all of it to warm caches.
//         Measure RDTSC delta for cached vs cold (after Sleep) access.
// TODO 2: Implement RDTSC anti-debug: measure time for a NOP loop;
//         if delta > 1,000,000 cycles, print "single-step detected".
// TODO 3: Use CLFLUSH intrinsic to flush a cache line and re-measure.
// Compile: g++ -std=c++17 -O2 -o ex02.exe ex02_cache_timing.cpp
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
int main() {
    printf("Cache timing exercise — implement the TODOs\n");
    return 0;
}
