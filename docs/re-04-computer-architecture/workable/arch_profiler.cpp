// arch_profiler.cpp — CPU architecture profiling and sandbox detection
// Compile: g++ -std=c++17 -O2 -o arch_profiler.exe arch_profiler.cpp
// Usage: arch_profiler.exe cpuid | cache | rdtsc | simd | all

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <intrin.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>

// ─── cpuid ────────────────────────────────────────────────────────────────────

static void cmd_cpuid() {
    int r[4]{};
    printf("=== CPUID ===\n");
    __cpuid(r, 0);
    char vendor[13]{}; *(int*)(vendor+0)=r[1]; *(int*)(vendor+4)=r[3]; *(int*)(vendor+8)=r[2];
    printf("  Vendor:    %s\n  MaxLeaf:   0x%X\n", vendor, r[0]);

    __cpuid(r, 1);
    printf("  Family:    %u  Model: %u  Stepping: %u\n",
           ((r[0]>>8)&0xF) + ((r[0]>>20)&0xFF),
           ((r[0]>>4)&0xF) + ((r[0]>>12)&0xF0),
           r[0]&0xF);
    bool hv = (r[2]>>31)&1;
    printf("  Hypervisor bit: %s\n", hv?"SET — VM!":"clear");

    if (hv) {
        __cpuid(r, 0x40000000);
        char hvv[13]{}; *(int*)(hvv+0)=r[1]; *(int*)(hvv+4)=r[2]; *(int*)(hvv+8)=r[3];
        printf("  Hypervisor:  %.12s\n", hvv);
    }

    printf("  Brand:  ");
    for (uint32_t l=0x80000002;l<=0x80000004;++l) { __cpuid(r,l); for(int i=0;i<4;++i) printf("%.4s",(char*)&r[i]); }
    printf("\n");
}

// ─── cache timing ─────────────────────────────────────────────────────────────

static uint64_t rdtsc() { return __rdtsc(); }

static void cmd_cache() {
    printf("=== Cache Timing ===\n");
    const int N = 4*1024*1024;
    std::vector<uint8_t> buf(N, 0x41);

    // Warm up
    for (int i = 0; i < N; i += 64) { volatile uint8_t x = buf[i]; (void)x; }

    uint64_t t0 = rdtsc();
    for (int i = 0; i < N; i += 64) { volatile uint8_t x = buf[i]; (void)x; }
    uint64_t t_cached = rdtsc() - t0;

    // Flush
    for (int i = 0; i < N; i += 64) _mm_clflush(&buf[i]);
    _mm_mfence();

    uint64_t t1 = rdtsc();
    for (int i = 0; i < N; i += 64) { volatile uint8_t x = buf[i]; (void)x; }
    uint64_t t_cold = rdtsc() - t1;

    printf("  Cached  read (%d lines): %llu cycles  (%.1f ns @ 3GHz)\n",
           N/64, (unsigned long long)t_cached, t_cached/3.0);
    printf("  Cold    read (%d lines): %llu cycles  (%.1f ns @ 3GHz)\n",
           N/64, (unsigned long long)t_cold, t_cold/3.0);
    printf("  Ratio (cold/cached): %.1f×\n", (double)t_cold/t_cached);
}

// ─── rdtsc anti-debug ─────────────────────────────────────────────────────────

static void cmd_rdtsc() {
    printf("=== RDTSC Anti-Debug Check ===\n");
    // Measure a fixed-count loop; single-stepping inflates this dramatically
    uint64_t t0 = __rdtsc();
    for (volatile int i = 0; i < 10000; ++i);
    uint64_t delta = __rdtsc() - t0;
    printf("  Loop delta: %llu cycles\n", (unsigned long long)delta);
    if (delta > 5000000ULL)
        printf("  [!] Very high delta — possible single-step / debugger\n");
    else
        printf("  [OK] Normal execution speed\n");
}

// ─── simd: SSE2 XOR benchmark ────────────────────────────────────────────────

static void cmd_simd() {
    printf("=== SIMD (SSE2) XOR Benchmark ===\n");
    const int SZ = 1024*1024;
    std::vector<uint8_t> src(SZ, 0xAA), dst(SZ);
    __m128i key = _mm_set1_epi8(0x5A);

    uint64_t t0 = rdtsc();
    for (int i = 0; i < SZ; i += 16) {
        __m128i v = _mm_loadu_si128((__m128i*)(src.data()+i));
        v = _mm_xor_si128(v, key);
        _mm_storeu_si128((__m128i*)(dst.data()+i), v);
    }
    uint64_t t_simd = rdtsc() - t0;

    // Scalar reference
    uint64_t t1 = rdtsc();
    for (int i = 0; i < SZ; ++i) dst[i] = src[i] ^ 0x5A;
    uint64_t t_scalar = rdtsc() - t1;

    printf("  SIMD   XOR %d bytes: %llu cycles\n", SZ, (unsigned long long)t_simd);
    printf("  Scalar XOR %d bytes: %llu cycles\n", SZ, (unsigned long long)t_scalar);
    printf("  Speedup: %.1f×\n", (double)t_scalar/t_simd);
    printf("  First 8 bytes of result: ");
    for (int i=0;i<8;++i) printf("%02X ",dst[i]);
    printf("\n");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  arch_profiler.exe cpuid\n"
               "  arch_profiler.exe cache\n"
               "  arch_profiler.exe rdtsc\n"
               "  arch_profiler.exe simd\n"
               "  arch_profiler.exe all\n");
        return 1;
    }
    std::string cmd(argv[1]);
    bool all = (cmd == "all");
    if (all || cmd == "cpuid") { cmd_cpuid(); if(all) printf("\n"); }
    if (all || cmd == "cache") { cmd_cache(); if(all) printf("\n"); }
    if (all || cmd == "rdtsc") { cmd_rdtsc(); if(all) printf("\n"); }
    if (all || cmd == "simd")  { cmd_simd();  }
    if (!all && cmd!="cpuid"&&cmd!="cache"&&cmd!="rdtsc"&&cmd!="simd")
        { fprintf(stderr,"Unknown command\n"); return 1; }
    return 0;
}
