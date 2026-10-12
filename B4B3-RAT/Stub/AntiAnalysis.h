#pragma once
#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H
#include "common.h"

// AntiAnalysis — anti-debug, anti-VM, anti-sandbox, and user-interaction checks.
//
// These tests determine whether the RAT is running in an analysis environment.
// In a real deployment, a positive result would cause the RAT to exit silently.
// In this curriculum, they return a detailed report so your detection system
// can verify whether its sandbox environment is fingerprint-resistant.
//
// Categories:
//
//   Anti-Debug (T1622):
//     IsDebuggerPresent, NtQueryInformationProcess (DebugPort, DebugFlags),
//     CheckRemoteDebuggerPresent, heap flags (ForceFlags != 0),
//     timing delta (RDTSC before/after a NOP sled — debugger slows execution)
//
//   Anti-VM (T1497.001):
//     CPUID hypervisor bit (ECX bit 31 of leaf 1),
//     VMware/VBox/Hyper-V CPUID vendor strings,
//     Registry keys: HKLM\SOFTWARE\VMware Inc.\VMware Tools,
//     MAC OUI prefix check (00:0C:29 = VMware, 08:00:27 = VBox, 00:15:5D = Hyper-V),
//     SMBIOS/firmware strings containing "VBOX", "VMWARE", "QEMU"
//
//   Anti-Sandbox (T1497.003):
//     Username in known sandbox list (John, sandbox, malware, test...),
//     Uptime < 10 minutes (sandbox reset),
//     Mouse cursor hasn't moved since process start,
//     Foreground window is the same as at startup (no user activity),
//     Disk size < 60 GB (sandbox usually has minimal disk),
//     CPU count == 1 (sandbox often single-core),
//     Screen resolution < 800x600
//
//   User interaction (T1497.002):
//     Mouse movement delta over 5 seconds,
//     Clipboard has content (user likely active),
//     Recent foreground window changes (GetForegroundWindow polling)

namespace AntiAnalysis {
    // Run all checks and return a comprehensive report.
    std::string FullReport();

    // Individual check groups
    std::string CheckDebugger();
    std::string CheckVM();
    std::string CheckSandbox();
    std::string CheckUserActivity();

    // Returns true if the environment appears safe (not debugged, not VM, not sandbox).
    // In a real RAT this gates execution; here it just reports.
    bool IsSafeEnvironment();
}

#endif
