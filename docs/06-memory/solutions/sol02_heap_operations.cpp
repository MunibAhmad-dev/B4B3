// sol02_heap_operations.cpp
// Demonstrates private heap creation, allocation, realloc, free, and
// compares HeapAlloc on the process heap vs. malloc.
//
// Compile:
//   g++ -std=c++17 -Wall -o sol02.exe solutions/sol02_heap_operations.cpp

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>   // malloc / free comparison

// Fill a buffer with a repeating byte pattern starting at `seed`.
static void FillPattern(BYTE* buf, SIZE_T len, BYTE seed)
{
    for (SIZE_T i = 0; i < len; i++)
        buf[i] = (BYTE)((seed + i) & 0xFF);
}

// Verify a buffer matches the expected repeating pattern.
static BOOL VerifyPattern(const BYTE* buf, SIZE_T len, BYTE seed)
{
    for (SIZE_T i = 0; i < len; i++)
        if (buf[i] != (BYTE)((seed + i) & 0xFF))
            return FALSE;
    return TRUE;
}

int main()
{
    printf("=== Private Heap Operations Demo ===\n\n");

    // ------------------------------------------------------------------
    // Part 1: Create a private heap.
    //
    // HeapCreate(0, initialSize, maxSize)
    //   - flOptions = 0       : default (not serialized with HEAP_NO_SERIALIZE,
    //                           not growable with HEAP_GENERATE_EXCEPTIONS)
    //   - dwInitialSize = 0   : OS picks a suitable initial commitment.
    //   - dwMaximumSize = 0   : heap is growable (no hard cap).
    // ------------------------------------------------------------------
    HANDLE hHeap = HeapCreate(0, 0, 0);
    if (hHeap == NULL) {
        printf("[!] HeapCreate failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] HeapCreate returned handle: 0x%p\n", hHeap);

    // ------------------------------------------------------------------
    // Part 2: Allocate 5 blocks of different sizes, fill with patterns.
    // ------------------------------------------------------------------
    const int NUM_BLOCKS = 5;
    SIZE_T sizes[NUM_BLOCKS] = { 16, 64, 256, 1024, 4096 };
    BYTE*  blocks[NUM_BLOCKS] = {};

    printf("\n--- Allocating %d blocks ---\n", NUM_BLOCKS);
    for (int i = 0; i < NUM_BLOCKS; i++) {
        blocks[i] = (BYTE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizes[i]);
        if (blocks[i] == NULL) {
            printf("[!] HeapAlloc(%llu) failed: %lu\n",
                   (unsigned long long)sizes[i], GetLastError());
            HeapDestroy(hHeap);
            return 1;
        }
        FillPattern(blocks[i], sizes[i], (BYTE)(i * 0x11));
        printf("  block[%d]  addr=0x%p  size=%5llu  pattern_seed=0x%02X\n",
               i, blocks[i], (unsigned long long)sizes[i], (BYTE)(i * 0x11));
    }

    // Verify patterns are intact.
    printf("\n--- Verifying patterns ---\n");
    for (int i = 0; i < NUM_BLOCKS; i++) {
        BOOL ok = VerifyPattern(blocks[i], sizes[i], (BYTE)(i * 0x11));
        printf("  block[%d]: %s\n", i, ok ? "OK" : "CORRUPTED");
    }

    // ------------------------------------------------------------------
    // Part 3: HeapReAlloc — grow block[2] (256 → 512 bytes).
    //         HEAP_REALLOC_IN_PLACE_ONLY fails if it cannot expand in place;
    //         omitting that flag allows the heap to move the block.
    // ------------------------------------------------------------------
    printf("\n--- HeapReAlloc block[2]: 256 → 512 bytes ---\n");
    SIZE_T newSize = 512;
    BYTE* resized = (BYTE*)HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, blocks[2], newSize);
    if (resized == NULL) {
        printf("[!] HeapReAlloc failed: %lu\n", GetLastError());
        // blocks[2] is still valid on failure — do not free the pointer yet.
    } else {
        printf("  Old addr: 0x%p  New addr: 0x%p  New size: %llu\n",
               blocks[2], resized, (unsigned long long)newSize);
        if (resized != blocks[2])
            printf("  (block was MOVED by the heap manager)\n");
        else
            printf("  (block was expanded IN PLACE)\n");
        blocks[2] = resized;
        sizes[2]  = newSize;
        // Verify original data still intact in the first 256 bytes.
        BOOL ok = VerifyPattern(blocks[2], 256, (BYTE)(2 * 0x11));
        printf("  Original 256-byte pattern after realloc: %s\n", ok ? "intact" : "LOST");
    }

    // ------------------------------------------------------------------
    // Part 4: HeapFree all blocks.
    // ------------------------------------------------------------------
    printf("\n--- Freeing all blocks ---\n");
    for (int i = 0; i < NUM_BLOCKS; i++) {
        if (blocks[i]) {
            BOOL freed = HeapFree(hHeap, 0, blocks[i]);
            printf("  HeapFree block[%d] @ 0x%p: %s\n",
                   i, blocks[i], freed ? "OK" : "FAILED");
            blocks[i] = NULL;
        }
    }

    // ------------------------------------------------------------------
    // Part 5: HeapDestroy — releases all memory belonging to the heap
    //         in a single call regardless of outstanding allocations.
    // ------------------------------------------------------------------
    if (!HeapDestroy(hHeap)) {
        printf("[!] HeapDestroy failed: %lu\n", GetLastError());
        return 1;
    }
    printf("\n[+] HeapDestroy: private heap released\n");
    hHeap = NULL;

    // ------------------------------------------------------------------
    // Part 6: GetProcessHeap + HeapAlloc vs. malloc.
    //
    // GetProcessHeap() returns the default heap of the process — the same
    // heap that malloc/new use internally (via the CRT).  Mixing HeapAlloc
    // (process heap) and malloc is fine because they share the same backing
    // store, but you must pair each allocator with its own free:
    //   HeapAlloc → HeapFree      malloc → free      new → delete
    // ------------------------------------------------------------------
    printf("\n--- GetProcessHeap + HeapAlloc vs. malloc ---\n");

    HANDLE hProcHeap = GetProcessHeap();
    printf("GetProcessHeap handle: 0x%p\n", hProcHeap);

    // Allocate with HeapAlloc on the process heap.
    char* ha_buf = (char*)HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, 128);
    if (!ha_buf) { printf("[!] HeapAlloc on process heap failed\n"); return 1; }
    strcpy(ha_buf, "Allocated via HeapAlloc on process heap");
    printf("HeapAlloc  @ 0x%p: \"%s\"\n", ha_buf, ha_buf);
    HeapFree(hProcHeap, 0, ha_buf);
    printf("HeapFree OK\n");

    // Allocate with malloc (uses CRT → same process heap internally).
    char* ml_buf = (char*)malloc(128);
    if (!ml_buf) { printf("[!] malloc failed\n"); return 1; }
    strcpy(ml_buf, "Allocated via malloc (CRT wraps process heap)");
    printf("malloc     @ 0x%p: \"%s\"\n", ml_buf, ml_buf);
    free(ml_buf);
    printf("free OK\n");

    printf("\n[NOTE] HeapAlloc(GetProcessHeap()) and malloc both use the default\n");
    printf("       process heap.  Private heaps (HeapCreate) are independent and\n");
    printf("       can be destroyed atomically — useful for isolating allocations.\n");

    printf("\n=== Done ===\n");
    return 0;
}
