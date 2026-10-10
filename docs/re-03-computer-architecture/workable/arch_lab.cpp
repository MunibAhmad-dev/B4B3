// RE-03 Full Demo: Architecture Lab
// Cache timing, virtual memory walker, RDTSC anti-debug, ROP gadget finder
//
// COMPILE: cl /W4 /O2 /std:c++17 arch_lab.cpp /Fe:re03_arch_lab.exe
// PLATFORM: Windows x64

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <vector>
#pragma comment(lib, "psapi.lib")

// ============================================================
// PART 1: Cache Hit/Miss Timer
// ============================================================
static uint8_t g_probe_buf[256 * 64 + 64];

static inline void clflush_addr(void* p) { _mm_clflush(p); }
static inline uint64_t tsc()  { return __rdtsc(); }
static inline void fence()    { _mm_mfence(); }

uint8_t* probe_base() {
    return (uint8_t*)(((uintptr_t)g_probe_buf + 63) & ~(uintptr_t)63);
}

uint64_t time_access(volatile uint8_t* addr) {
    fence();
    uint64_t t1 = tsc();
    (void)*addr;
    fence();
    return tsc() - t1;
}

void part1_cache() {
    printf("\n========== PART 1: Cache Hit vs Miss ==========\n");
    uint8_t* base = probe_base();

    // Flush then measure (MISS)
    clflush_addr(base);
    fence();
    uint64_t miss = time_access(base);

    // Access again (HIT)
    uint64_t hit = time_access(base);

    printf("Cache MISS: ~%llu cycles\n", (unsigned long long)miss);
    printf("Cache HIT:  ~%llu cycles\n", (unsigned long long)hit);
    printf("Ratio: %.1fx\n", (double)miss / (hit > 0 ? hit : 1));
    printf("\nThreshold for Flush+Reload detection: ~150 cycles\n");
    printf("  < 150 = cache hit = data was recently accessed\n");
    printf("  > 150 = cache miss = data was not in cache\n");
}

// ============================================================
// PART 2: RDTSC Anti-Debug Timing Check
// ============================================================
void part2_antidebug_timing() {
    printf("\n========== PART 2: RDTSC Anti-Debug ==========\n");

    const uint64_t NORMAL_THRESHOLD = 5000000ULL; // ~5M cycles

    uint64_t t1 = tsc();
    // Simulated work (replace with actual sensitive code in real scenario)
    volatile uint64_t dummy = 0;
    for (int i = 0; i < 10000; i++) dummy += i;
    uint64_t t2 = tsc();

    uint64_t delta = t2 - t1;
    printf("Work took: %llu cycles\n", (unsigned long long)delta);
    printf("Threshold: %llu cycles\n", (unsigned long long)NORMAL_THRESHOLD);

    if (delta > NORMAL_THRESHOLD) {
        printf("STATUS: DEBUGGER DETECTED (execution too slow)\n");
    } else {
        printf("STATUS: Clean (no debugger delay detected)\n");
    }

    // Additional anti-debug: CheckRemoteDebuggerPresent
    BOOL dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
    printf("CheckRemoteDebugger: %s\n", dbg ? "DEBUGGER PRESENT" : "clean");

    // IsDebuggerPresent (trivially bypassable but fast)
    printf("IsDebuggerPresent:   %s\n",
           IsDebuggerPresent() ? "DEBUGGER PRESENT" : "clean");

    // NtGlobalFlag check (PEB-based)
    PPEB peb = (PPEB)__readgsqword(0x60);
    // NtGlobalFlag at PEB+0xBC (x64)
    DWORD ntgf = *(DWORD*)((uint8_t*)peb + 0xBC);
    printf("NtGlobalFlag (PEB+BC): 0x%08X %s\n", ntgf,
           (ntgf & 0x70) ? "(debug flags set!)" : "(clean)");
}

// ============================================================
// PART 3: Virtual Memory Summary
// ============================================================
void part3_vas_summary() {
    printf("\n========== PART 3: VAS Summary (Self) ==========\n");
    HANDLE hp = GetCurrentProcess();
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    size_t total_commit = 0, total_rwx = 0;
    int rwx_count = 0, region_count = 0;

    while (VirtualQueryEx(hp, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            total_commit += mbi.RegionSize;
            region_count++;
            DWORD p = mbi.Protect & ~(PAGE_GUARD|PAGE_NOCACHE|PAGE_WRITECOMBINE);
            if (p == PAGE_EXECUTE_READWRITE) {
                total_rwx += mbi.RegionSize;
                rwx_count++;
                printf("  RWX: %p  size=%zu KB\n",
                       mbi.BaseAddress, mbi.RegionSize/1024);
            }
        }
        if ((uintptr_t)mbi.BaseAddress + mbi.RegionSize <= addr) break;
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    printf("Committed regions: %d\n", region_count);
    printf("Total committed:   %.2f MB\n", total_commit/1048576.0);
    printf("RWX regions:       %d (%s)\n", rwx_count,
           rwx_count ? "SUSPICIOUS" : "clean");
}

// ============================================================
// PART 4: Simple ROP Gadget Scanner
// Scans mapped image regions for useful ROP gadgets
// ============================================================

struct Gadget { uintptr_t addr; const char* desc; };

// Patterns to search for (byte sequences)
struct GadgetPattern {
    const uint8_t* bytes;
    size_t         len;
    const char*    desc;
};

// Common ROP gadgets (x64)
static const uint8_t g_ret[]          = {0xC3};                       // ret
static const uint8_t g_pop_rax_ret[]  = {0x58, 0xC3};                 // pop rax; ret
static const uint8_t g_pop_rcx_ret[]  = {0x59, 0xC3};                 // pop rcx; ret
static const uint8_t g_xchg_rax_rsp[] = {0x48, 0x94, 0xC3};           // xchg rax,rsp; ret
static const uint8_t g_jmp_rax[]      = {0xFF, 0xE0};                 // jmp rax

#define GADGET_PATTERN(b, d) { b, sizeof(b), d }

static const GadgetPattern g_patterns[] = {
    GADGET_PATTERN(g_ret,          "ret"),
    GADGET_PATTERN(g_pop_rax_ret,  "pop rax; ret"),
    GADGET_PATTERN(g_pop_rcx_ret,  "pop rcx; ret"),
    GADGET_PATTERN(g_xchg_rax_rsp, "xchg rax,rsp; ret"),
    GADGET_PATTERN(g_jmp_rax,      "jmp rax"),
};

void part4_rop_scanner() {
    printf("\n========== PART 4: ROP Gadget Scanner ==========\n");
    printf("Scanning executable regions of this process...\n\n");

    HANDLE hp = GetCurrentProcess();
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    int total_found = 0;
    int limit = 20; // cap output

    while (VirtualQueryEx(hp, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        DWORD prot = mbi.Protect & ~(PAGE_GUARD|PAGE_NOCACHE|PAGE_WRITECOMBINE);
        bool executable = (prot == PAGE_EXECUTE       ||
                           prot == PAGE_EXECUTE_READ  ||
                           prot == PAGE_EXECUTE_READWRITE);

        if (mbi.State == MEM_COMMIT && executable && mbi.RegionSize > 0) {
            // Read the region
            std::vector<uint8_t> buf(mbi.RegionSize);
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(hp, mbi.BaseAddress, buf.data(),
                                  mbi.RegionSize, &bytes_read)) {
                for (auto& pat : g_patterns) {
                    for (size_t i = 0; i + pat.len <= bytes_read; i++) {
                        if (memcmp(&buf[i], pat.bytes, pat.len) == 0) {
                            if (total_found < limit) {
                                printf("  %p  %s\n",
                                       (void*)((uintptr_t)mbi.BaseAddress + i),
                                       pat.desc);
                            }
                            total_found++;
                        }
                    }
                }
            }
        }

        if ((uintptr_t)mbi.BaseAddress + mbi.RegionSize <= addr) break;
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    if (total_found > limit)
        printf("  ... and %d more\n", total_found - limit);
    printf("Total gadgets found: %d\n", total_found);
    printf("\nNote: These are all usable ROP gadgets in THIS process's memory.\n");
    printf("A real ROP chain selects and chains them to achieve arbitrary execution.\n");
}

// ============================================================
// MAIN
// ============================================================
int main() {
    printf("RE-03 Architecture Lab\n");
    printf("======================\n");

    part1_cache();
    part2_antidebug_timing();
    part3_vas_summary();
    part4_rop_scanner();

    printf("\n[Done]\n");
    return 0;
}
#else
int main() { puts("Windows x64 only."); return 0; }
#endif
