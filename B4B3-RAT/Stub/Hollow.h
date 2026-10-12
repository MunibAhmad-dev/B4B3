#pragma once
#ifndef HOLLOW_H
#define HOLLOW_H
#include "common.h"

namespace Hollow {
    // Process hollowing (thread-context hijacking variant):
    //   1. CreateProcess(target, CREATE_SUSPENDED | CREATE_NO_WINDOW)
    //   2. VirtualAllocEx RWX in the suspended process
    //   3. WriteProcessMemory shellcode into the allocation
    //   4. SetThreadContext — point RIP/EIP at the shellcode
    //   5. ResumeThread
    //
    // target     = full path to a legitimate Windows binary (e.g. svchost.exe)
    // shellcodeB64 = base64-encoded raw x64 shellcode bytes
    //
    // Detection signals (multiple independent rules triggered):
    //   CreateProcess(CREATE_SUSPENDED) from a suspicious binary
    //   VirtualAllocEx(PAGE_EXECUTE_READWRITE) in a freshly-created process
    //   WriteProcessMemory into that allocation
    //   SetThreadContext with modified RIP pointing outside any loaded module
    //   Thread resumed with RIP in non-image memory
    std::string HollowProcess(const std::string& target, const std::string& shellcodeB64);

    // Inject shellcode into an already-running process by PID via APC (Asynchronous
    // Procedure Call) rather than CreateRemoteThread — a different detection vector.
    //   1. OpenProcess + OpenThread on each alertable thread of the target PID
    //   2. VirtualAllocEx RWX, WriteProcessMemory
    //   3. QueueUserAPC(shellcode_addr, hThread, 0) on each thread
    //
    // Detection: QueueUserAPC from a foreign process targeting a non-alertable thread
    // or an unusual binary is flagged by behaviour-based EDR rules (MITRE T1055.004).
    std::string ApcInject(DWORD pid, const std::string& shellcodeB64);
}

#endif
