// Exercise 2: Inline Assembly in C++
// Practice reading and writing x64 inline assembly.
//
// TASKS:
//  1. Implement the TODO functions using inline assembly.
//  2. For GCC: use __asm__ volatile("..." : outputs : inputs : clobbers)
//  3. For MSVC x64: inline asm is not supported; use intrinsics or _BitScanForward64
//  4. After implementing, compile in debug mode and step through in x64dbg.
//     Set a breakpoint on each function and watch the registers change.
//
// COMPILE (GCC x64):   g++ -Wall -std=c++17 ex02_inline_asm.cpp -o ex02
// COMPILE (MSVC x64):  Not all inline asm works; use intrinsics where noted

#include <cstdint>
#include <cstdio>
#include <intrin.h>   // MSVC intrinsics

// -- Task A: CPUID — identify the processor --
struct CpuidResult { uint32_t eax, ebx, ecx, edx; };

CpuidResult get_cpuid(uint32_t leaf) {
    CpuidResult r = {};
#if defined(_MSC_VER)
    int info[4];
    __cpuid(info, (int)leaf);
    r.eax = info[0]; r.ebx = info[1]; r.ecx = info[2]; r.edx = info[3];
#elif defined(__GNUC__)
    // TODO: use __asm__ volatile with cpuid instruction
    // inputs: leaf in eax
    // outputs: eax, ebx, ecx, edx
    (void)leaf;
#endif
    return r;
}

// -- Task B: RDTSC — read timestamp counter --
uint64_t read_tsc() {
#if defined(_MSC_VER)
    return __rdtsc();
#elif defined(__GNUC__)
    uint32_t lo, hi;
    // TODO: use __asm__ volatile with rdtsc instruction
    // rdtsc stores result in edx:eax
    (void)lo; (void)hi;
    return 0; // replace with (uint64_t)hi << 32 | lo
#endif
}

// -- Task C: Bit scan — find lowest set bit --
int lowest_set_bit(uint64_t val) {
    if (val == 0) return -1;
#if defined(_MSC_VER)
    unsigned long idx;
    _BitScanForward64(&idx, val);
    return (int)idx;
#elif defined(__GNUC__)
    // TODO: use __builtin_ctzll or inline asm with bsf instruction
    return 0; // placeholder
#endif
}

// -- Task D: XCHG — atomic swap (simple spinlock demo) --
// In real code this uses lock prefix, but for asm practice:
uint32_t atomic_xchg(volatile uint32_t* ptr, uint32_t newval) {
#if defined(_MSC_VER)
    return (uint32_t)_InterlockedExchange((volatile long*)ptr, (long)newval);
#elif defined(__GNUC__)
    uint32_t old;
    // TODO: use __asm__ volatile with xchg instruction
    // xchg is implicitly locked when accessing memory
    (void)ptr; (void)newval;
    old = 0; // placeholder
    return old;
#endif
}

// -- Task E: ROL/ROR (rotate) — common in crypto --
uint32_t rotl32(uint32_t v, int n) {
    n &= 31;
#if defined(_MSC_VER)
    return _rotl(v, n);
#elif defined(__GNUC__)
    uint32_t result;
    // TODO: use __asm__ volatile with rol instruction
    (void)v; (void)n;
    result = 0; // placeholder
    return result;
#endif
}

// -- Timing demo: measure function latency via RDTSC --
void timing_demo() {
    printf("\n=== RDTSC Timing Demo ===\n");
    uint64_t t1 = read_tsc();
    volatile uint64_t sum = 0;
    for (int i = 0; i < 1000000; i++) sum += i;
    uint64_t t2 = read_tsc();
    printf("1M additions took ~%llu cycles\n", (unsigned long long)(t2 - t1));
    printf("Sum = %llu (to prevent optimization)\n", (unsigned long long)sum);
}

int main() {
    printf("=== CPUID ===\n");
    CpuidResult leaf0 = get_cpuid(0);
    // EBX+EDX+ECX form the vendor string ("GenuineIntel" or "AuthenticAMD")
    char vendor[13] = {};
    *(uint32_t*)(vendor + 0) = leaf0.ebx;
    *(uint32_t*)(vendor + 4) = leaf0.edx;
    *(uint32_t*)(vendor + 8) = leaf0.ecx;
    printf("Vendor: %s\n", vendor);
    printf("Max basic leaf: %u\n", leaf0.eax);

    CpuidResult leaf1 = get_cpuid(1);
    printf("Family/Model: 0x%08X  Features: 0x%08X\n", leaf1.eax, leaf1.edx);

    printf("\n=== RDTSC ===\n");
    printf("TSC = %llu\n", (unsigned long long)read_tsc());

    printf("\n=== Bit Scan ===\n");
    printf("lowest_set_bit(0x00F0) = %d (expected 4)\n", lowest_set_bit(0x00F0));
    printf("lowest_set_bit(0x0001) = %d (expected 0)\n", lowest_set_bit(0x0001));
    printf("lowest_set_bit(0x8000) = %d (expected 15)\n", lowest_set_bit(0x8000));
    printf("lowest_set_bit(0)      = %d (expected -1)\n", lowest_set_bit(0));

    printf("\n=== ROL32 ===\n");
    printf("rotl32(0x12345678, 8) = 0x%08X (expected 0x34567812)\n", rotl32(0x12345678, 8));
    printf("rotl32(0x80000000, 1) = 0x%08X (expected 0x00000001)\n", rotl32(0x80000000u, 1));

    timing_demo();

    return 0;
}
