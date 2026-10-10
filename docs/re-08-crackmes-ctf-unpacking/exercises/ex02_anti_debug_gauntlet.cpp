// ex02_anti_debug_gauntlet.cpp — anti-debug checks; bypass all to reach the flag
// Run without a debugger first to see what happens.
// Then attach x64dbg / use ScyllaHide and reach "FLAG: ..."
// Compile: g++ -std=c++17 -O1 -o ex02.exe ex02_anti_debug_gauntlet.cpp
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
static void bail(const char* msg) { printf("DETECTED: %s — exiting\n", msg); ExitProcess(1); }
int main() {
    // Check 1: PEB.BeingDebugged
    if (IsDebuggerPresent()) bail("IsDebuggerPresent");
    // Check 2: NtGlobalFlag (heap flags set by debugger)
#ifdef _WIN64
    DWORD ntgf = *(DWORD*)((BYTE*)__readgsqword(0x60) + 0xBC);
#else
    DWORD ntgf = *(DWORD*)((BYTE*)__readfsdword(0x30) + 0x68);
#endif
    if (ntgf & 0x70) bail("NtGlobalFlag");
    // Check 3: RDTSC timing
    uint64_t t0 = __rdtsc(); Sleep(0); uint64_t t1 = __rdtsc();
    if (t1-t0 > 10000000ULL) bail("RDTSC timing");
    // Check 4: Heap magic (DebugHeap sets extra header bytes)
    PVOID heap = HeapAlloc(GetProcessHeap(),0,0x10);
    BYTE* hdr = (BYTE*)heap - 8;
    DWORD flags = *(DWORD*)(hdr); (void)flags;
    HeapFree(GetProcessHeap(),0,heap);
    // All checks passed
    printf("FLAG: re08{y0u_bypassed_all_antidebug}\n");
    return 0;
}
