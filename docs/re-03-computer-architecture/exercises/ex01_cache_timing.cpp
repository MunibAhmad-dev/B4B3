// Exercise 1: Cache Timing Side-Channel Demo
// Demonstrates how cache access time reveals whether data was accessed.
// This is the foundation of Flush+Reload attacks (Spectre, covert channels).
//
// TASKS:
//  1. Run the program and observe the histogram. Understand the bimodal distribution.
//  2. Implement probe_cache_time() using RDTSC.
//  3. Change the probe_size to 4096 (one page per slot) and observe the difference.
//  4. Add a second thread that accesses a random slot; detect which one from main.
//
// COMPILE: cl /W4 /std:c++17 /O2 ex01_cache_timing.cpp /Fe:ex01.exe
//          g++ -Wall -std=c++17 -O2 ex01_cache_timing.cpp -o ex01

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
  #include <windows.h>
  #include <intrin.h>
  static inline uint64_t rdtsc() { return __rdtsc(); }
  static inline void clflush(void* p) { _mm_clflush(p); }
  static inline void mfence() { _mm_mfence(); }
#else
  #include <x86intrin.h>
  static inline uint64_t rdtsc() { return __rdtsc(); }
  static inline void clflush(void* p) { _mm_clflush(p); }
  static inline void mfence() { _mm_mfence(); }
#endif

static const int PROBE_COUNT  = 256;  // one slot per possible byte value
static const int PROBE_STRIDE = 64;   // == cache line size; one line per slot
// Total buffer: 256 * 64 = 16 KB

static uint8_t probe_buf[PROBE_COUNT * PROBE_STRIDE + 64]; // + padding

// Get aligned start
uint8_t* get_probe_base() {
    uintptr_t base = (uintptr_t)probe_buf;
    base = (base + 63) & ~(uintptr_t)63; // align to 64
    return (uint8_t*)base;
}

// Measure access time to probe_base[slot * PROBE_STRIDE]
// Returns cycle count
uint64_t probe_slot(uint8_t* base, int slot) {
    volatile uint8_t* addr = &base[slot * PROBE_STRIDE];
    uint64_t t1 = rdtsc();
    mfence();
    (void)*addr; // access
    mfence();
    uint64_t t2 = rdtsc();
    return t2 - t1;
}

// Flush all probe slots from cache
void flush_all(uint8_t* base) {
    for (int i = 0; i < PROBE_COUNT; i++)
        clflush(&base[i * PROBE_STRIDE]);
    mfence();
}

// "Victim" function: accesses one slot based on a secret value
// In a real Spectre gadget this would be inside a speculative window
void victim_access(uint8_t* base, uint8_t secret) {
    (void)base[secret * PROBE_STRIDE]; // loads the secret-th cache line
}

// Collect timing histogram for all slots
void measure_all(uint8_t* base, uint64_t times[PROBE_COUNT]) {
    for (int i = 0; i < PROBE_COUNT; i++)
        times[i] = probe_slot(base, i);
}

int main() {
    uint8_t* base = get_probe_base();

    printf("Cache Timing Demo\n");
    printf("=================\n");
    printf("probe_buf base = %p\n", (void*)base);
    printf("Cache line size = %d bytes\n", PROBE_STRIDE);
    printf("Total probe region = %d bytes (%.1f KB)\n",
           PROBE_COUNT * PROBE_STRIDE, PROBE_COUNT * PROBE_STRIDE / 1024.0);

    // --- Baseline: measure access time to cold (flushed) vs warm (cached) data ---
    printf("\n--- Baseline: cold vs warm ---\n");

    flush_all(base);
    uint64_t cold_times[10];
    for (int i = 0; i < 10; i++) {
        clflush(&base[i * PROBE_STRIDE]);
        mfence();
        cold_times[i] = probe_slot(base, i);
    }

    uint64_t warm_times[10];
    for (int i = 0; i < 10; i++) {
        (void)base[i * PROBE_STRIDE]; // warm
        warm_times[i] = probe_slot(base, i);
    }

    printf("Slot | Cold (miss) | Warm (hit)\n");
    for (int i = 0; i < 10; i++)
        printf("  %3d|   %8llu  | %8llu\n", i,
               (unsigned long long)cold_times[i],
               (unsigned long long)warm_times[i]);

    // --- Secret byte recovery via Flush+Reload ---
    printf("\n--- Secret Byte Recovery (Flush+Reload) ---\n");

    const int TRIALS = 1000;
    uint8_t secret = 0x42; // pretend this is "unknown" to attacker

    uint64_t scores[PROBE_COUNT] = {};

    for (int trial = 0; trial < TRIALS; trial++) {
        flush_all(base);
        victim_access(base, secret);  // "victim" touches secret-th cache line
        mfence();

        uint64_t times[PROBE_COUNT];
        measure_all(base, times);

        // Score: low time = cache hit = likely the secret byte
        for (int i = 0; i < PROBE_COUNT; i++)
            if (times[i] < 150) scores[i]++;
    }

    // Find highest score
    int best = 0;
    for (int i = 1; i < PROBE_COUNT; i++)
        if (scores[i] > scores[best]) best = i;

    printf("Recovered secret: 0x%02X (actual: 0x%02X) %s\n",
           best, secret, best == secret ? "CORRECT" : "WRONG");
    printf("Hit count for 0x%02X: %llu / %d\n",
           best, (unsigned long long)scores[best], TRIALS);

    // Print top 5 candidates
    printf("\nTop 5 candidates:\n");
    int sorted[PROBE_COUNT];
    for (int i = 0; i < PROBE_COUNT; i++) sorted[i] = i;
    std::sort(sorted, sorted + PROBE_COUNT,
              [&](int a, int b){ return scores[a] > scores[b]; });
    for (int i = 0; i < 5; i++)
        printf("  [%d] byte=0x%02X  hits=%llu\n", i+1, sorted[i],
               (unsigned long long)scores[sorted[i]]);

    return 0;
}
