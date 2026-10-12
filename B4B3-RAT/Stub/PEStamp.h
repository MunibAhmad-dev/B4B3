#pragma once
#ifndef PESTAMP_H
#define PESTAMP_H
#include "common.h"

// PEStamp — PE header stomping on the current process image.
//
// After a PE loads, the DOS/NT headers are no longer needed for execution.
// Zeroing them defeats memory scanners that look for "MZ" / "PE\0\0" magic
// bytes to identify loaded PE images, and removes the module from tools
// that walk the loaded module list by header signature rather than PEB.
//
// Layers:
//   1. Zero DOS header (MZ, e_lfanew field — makes module invisible to many scanners)
//   2. Zero NT headers (PE magic, file/optional header — MITRE T1027 Obfuscated Files)
//   3. Optionally wipe the entire header region (first 0x1000 bytes)
//
// What a strong detector still catches:
//   - VirtualProtect on module base: RO → RW → RO is a Sysmon EID 10 anomaly
//   - The module still exists in PEB.Ldr — it's just got wiped headers
//   - ETW process image load event fired before we stomp
//   - Kernel-mode scanners read the on-disk image, not the in-memory headers
//
// MITRE T1027, T1564.001

namespace PEStamp {
    // Wipe only the MZ magic bytes (minimal — breaks header-based scanners)
    std::string StompMZ();

    // Wipe DOS header + NT headers (aggressive — removes all PE identity)
    std::string StompFull();

    // Restore headers by reloading from disk (for cleanup / test validation)
    std::string RestoreHeaders();

    // Report what the headers look like now (for verifying detection gap)
    std::string CheckHeaders();
}

#endif
