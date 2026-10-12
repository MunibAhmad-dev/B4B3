#pragma once
#ifndef INDIRECTSYSCALL_H
#define INDIRECTSYSCALL_H
#include "common.h"

// IndirectSyscall — execute syscalls via a "syscall; ret" gadget found inside
// ntdll.dll's own address range.
//
// WHY this beats DirectSyscall (Hell's Gate) against advanced EDRs:
//   Some next-gen EDRs (CrowdStrike Falcon, SentinelOne) instrument the kernel
//   to check the return address of any syscall instruction. If the return
//   address (RSP at syscall time) points outside ntdll's .text section,
//   it is flagged as an "anomalous syscall origin" — a strong indicator of
//   shellcode or a custom syscall stub.
//
//   Indirect syscall: we find a real "0F 05 C3" (syscall; ret) gadget that
//   already exists inside ntdll.dll, set up registers (rax=SSN, r10=rcx)
//   ourselves, and jump into the gadget. The return address seen by the kernel
//   is inside ntdll — passes origin checks.
//
// What a strong detector still catches:
//   - Kernel ETW callbacks — fire regardless of how syscall was invoked
//   - Thread call-stack walk: the frame *above* the gadget points to our code
//   - Hardware breakpoints on the gadget address will still fire
//   - Sysmon EID 10/8 kernel callbacks are immune to all of this
//
// MITRE T1106 (Native API), T1027 (Obfuscated Files)

namespace IndirectSyscall {
    // Scan ntdll for a "syscall; ret" gadget and cache its address.
    // Returns the gadget address, or NULL if not found (very unlikely on Win10+).
    PVOID FindGadget();

    // Execute an NT syscall via the ntdll gadget.
    // Requires DirectSyscall::Init() to have been called first (for SSN lookup).
    // ssn = syscall number; args are passed via standard x64 ABI (rcx/rdx/r8/r9/stack).
    NTSTATUS Exec(int ssn,
                  ULONG_PTR a1=0, ULONG_PTR a2=0, ULONG_PTR a3=0, ULONG_PTR a4=0,
                  ULONG_PTR a5=0, ULONG_PTR a6=0, ULONG_PTR a7=0, ULONG_PTR a8=0);

    // Return gadget address as hex string (for reporting).
    std::string GadgetInfo();
}

#endif
