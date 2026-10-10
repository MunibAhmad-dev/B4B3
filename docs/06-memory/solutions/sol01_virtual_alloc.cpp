// sol01_virtual_alloc.cpp
// Demonstrates VirtualAlloc / VirtualProtect / VirtualFree lifecycle.
//
// Compile:
//   g++ -std=c++17 -Wall -o sol01.exe solutions/sol01_virtual_alloc.cpp
//
// Educational purpose: shows the correct RW → fill → RX pattern for
// executable memory and how to inspect page protection at each step.

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Helper: decode MEMORY_BASIC_INFORMATION.Protect flags into a readable string.
static const char* ProtectName(DWORD prot)
{
    switch (prot & 0xFF) {
        case PAGE_NOACCESS:          return "PAGE_NOACCESS";
        case PAGE_READONLY:          return "PAGE_READONLY";
        case PAGE_READWRITE:         return "PAGE_READWRITE";
        case PAGE_WRITECOPY:         return "PAGE_WRITECOPY";
        case PAGE_EXECUTE:           return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE (RWX — anti-pattern)";
        case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
        default:                     return "UNKNOWN";
    }
}

// Helper: query and print current protection of an address.
static void PrintRegionInfo(const char* label, LPVOID addr)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
        printf("  [!] VirtualQuery failed: %lu\n", GetLastError());
        return;
    }
    printf("  [%s] base=0x%p  size=0x%llX  protect=%s\n",
           label,
           mbi.BaseAddress,
           (unsigned long long)mbi.RegionSize,
           ProtectName(mbi.Protect));
}

int main()
{
    printf("=== VirtualAlloc / VirtualProtect / VirtualFree Demo ===\n\n");

    // ------------------------------------------------------------------
    // Step 1: Reserve + commit a 4 KB page with PAGE_READWRITE.
    //         MEM_RESERVE alone makes the range inaccessible (no physical
    //         backing).  MEM_COMMIT backs it with physical/page-file pages.
    // ------------------------------------------------------------------
    const SIZE_T ALLOC_SIZE = 4096; // one page

    LPVOID mem = VirtualAlloc(
        NULL,                        // let OS choose the address
        ALLOC_SIZE,
        MEM_RESERVE | MEM_COMMIT,    // reserve VA range AND commit
        PAGE_READWRITE               // initially: readable + writable
    );

    if (mem == NULL) {
        printf("[!] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] VirtualAlloc returned: 0x%p  (%llu bytes)\n",
           mem, (unsigned long long)ALLOC_SIZE);
    PrintRegionInfo("after alloc", mem);

    // ------------------------------------------------------------------
    // Step 2: Write data into the RW page.
    // ------------------------------------------------------------------
    const char payload[] = "Hello from VirtualAlloc! This is a test payload.";
    memcpy(mem, payload, sizeof(payload));
    printf("\n[+] Wrote %zu bytes to 0x%p\n", sizeof(payload), mem);
    printf("    Data: \"%s\"\n", (char*)mem);

    // ------------------------------------------------------------------
    // Step 3: Change protection to PAGE_EXECUTE_READ via VirtualProtect.
    //         We must no longer write after this point — the page is RX.
    //         Always save the old protection so you can restore if needed.
    // ------------------------------------------------------------------
    DWORD oldProtect = 0;
    BOOL ok = VirtualProtect(mem, ALLOC_SIZE, PAGE_EXECUTE_READ, &oldProtect);
    if (!ok) {
        printf("[!] VirtualProtect(PAGE_EXECUTE_READ) failed: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    printf("\n[+] VirtualProtect → PAGE_EXECUTE_READ  (old protect was: %s)\n",
           ProtectName(oldProtect));
    PrintRegionInfo("after VirtualProtect RX", mem);

    // ------------------------------------------------------------------
    // Step 4: Read data back from the now-RX page (reads still allowed).
    // ------------------------------------------------------------------
    char readback[sizeof(payload)] = {};
    memcpy(readback, mem, sizeof(payload));
    printf("\n[+] Read back from 0x%p: \"%s\"\n", mem, readback);

    // ------------------------------------------------------------------
    // Step 5: Restore to PAGE_READWRITE (optional — demonstrates round-trip).
    // ------------------------------------------------------------------
    DWORD tmp = 0;
    VirtualProtect(mem, ALLOC_SIZE, PAGE_READWRITE, &tmp);
    printf("\n[+] Restored protection to PAGE_READWRITE\n");
    PrintRegionInfo("after restore", mem);

    // ------------------------------------------------------------------
    // Step 6: VirtualFree with MEM_RELEASE.
    //         Size must be 0 when using MEM_RELEASE — the OS decommits and
    //         releases the entire region that was returned by VirtualAlloc.
    // ------------------------------------------------------------------
    if (!VirtualFree(mem, 0, MEM_RELEASE)) {
        printf("[!] VirtualFree failed: %lu\n", GetLastError());
        return 1;
    }
    printf("\n[+] VirtualFree(MEM_RELEASE) succeeded — memory returned to OS\n");

    // Confirm the VA is now free (should show MEM_FREE state).
    MEMORY_BASIC_INFORMATION mbi = {};
    VirtualQuery(mem, &mbi, sizeof(mbi));
    printf("    Post-free state: %s\n",
           (mbi.State == MEM_FREE) ? "MEM_FREE (correct)" : "NOT FREE — unexpected");

    // ------------------------------------------------------------------
    // Anti-pattern note:
    //   PAGE_EXECUTE_READWRITE (RWX) is a single flag that makes memory
    //   simultaneously writable AND executable.  Modern EDRs flag this
    //   pattern because it means code can be patched in-place and run
    //   immediately — a classic shellcode loader signature.
    //   Always use: alloc RW → fill → VirtualProtect to RX → execute.
    // ------------------------------------------------------------------
    printf("\n[NOTE] Anti-pattern: PAGE_EXECUTE_READWRITE (0x%02X) is flagged by EDRs.\n",
           PAGE_EXECUTE_READWRITE);
    printf("       Correct pattern: alloc PAGE_READWRITE → fill → "
           "VirtualProtect(PAGE_EXECUTE_READ) → execute.\n");

    printf("\n=== Done ===\n");
    return 0;
}
