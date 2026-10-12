#pragma once
#ifndef PPIDSPOOF_H
#define PPIDSPOOF_H
#include "common.h"

namespace PPIDSpoof {
    // Spawn cmdLine as a child of parentPid using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
    // The new process's PPID in the process tree will show parentPid instead of this exe.
    // Any parent-process anomaly detection rule (cmd.exe under OneDriveHelper.exe) breaks.
    //
    // Example: spawn cmd.exe under explorer.exe — looks like the user opened a terminal.
    // Detection: CreateProcess with EXTENDED_STARTUPINFO_PRESENT + PROC_THREAD_ATTRIBUTE_LIST
    //   is itself a detection signal in advanced EDRs (kernel callbacks can still see the
    //   real creator via PsGetCurrentProcess), but it defeats most SIEM-level rules.
    // MITRE T1134.004 — Parent PID Spoofing.
    std::string Spawn(DWORD parentPid, const std::string& cmdLine);

    // Convenience: find the PID of the first running instance of a named process.
    DWORD FindPid(const std::string& procName);
}

#endif
