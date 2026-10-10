/*
  Exercise 01 — APC Injection
  ----------------------------
  Inject a shellcode stub into a running target process using
  QueueUserAPC instead of CreateRemoteThread.

  Tasks:
  1. Implement findTargetPid() — find the PID of notepad.exe (or any process
     you specify on the command line).
  2. Implement findAlertableThread() — enumerate threads of the target process
     and return a handle to the first one with THREAD_SET_CONTEXT access.
  3. Implement apcInject() — allocate RWX memory, write shellcode, queue APC.
  4. In main(): launch notepad.exe manually first, then run this tool against it.
     The shellcode stub below just calls MessageBoxA — you'll see a dialog
     pop inside notepad's UI thread.

  The shellcode provided is a minimal x64 MessageBox stub.
  Replace it with your own shellcode once the injection mechanism works.

  IMPORTANT: Run on your own test machine only.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_apc_inject.cpp -lkernel32 -luser32
*/

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Minimal x64 shellcode: calls MessageBoxA("APC Injected!", ...) then returns.
// Generated with msfvenom or written manually — replace with your own.
// This stub is intentionally incomplete — the exercise is the INJECTION MECHANISM.
// Swap in any position-independent shellcode.
static const BYTE TEST_SHELLCODE[] = {
    // sub rsp, 0x28 (shadow space)
    0x48, 0x83, 0xEC, 0x28,
    // xor rcx, rcx (hWnd = NULL)
    0x48, 0x31, 0xC9,
    // lea rdx, [rip+??] — would point to "APC Injected!" string
    // For this exercise, use a NOP sled so it just returns safely
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    // add rsp, 0x28
    0x48, 0x83, 0xC4, 0x28,
    // ret
    0xC3
};

// TODO: Enumerate running processes using CreateToolhelp32Snapshot.
// Return the PID of the first process whose name matches targetName.
// Return 0 if not found.
DWORD findTargetPid(const char* targetName) {
    // YOUR CODE HERE
    return 0;
}

// TODO: Enumerate threads using CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).
// Return a handle (THREAD_SET_CONTEXT access) to the first thread owned by pid.
// Return NULL if none found.
HANDLE findAlertableThread(DWORD pid) {
    // YOUR CODE HERE
    return nullptr;
}

// TODO: Implement APC injection.
// 1. OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid)
// 2. VirtualAllocEx(hProcess, nullptr, shellcodeLen, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
// 3. WriteProcessMemory(...)
// 4. VirtualProtectEx to PAGE_EXECUTE_READ (optional but better)
// 5. findAlertableThread(pid) → hThread
// 6. QueueUserAPC((PAPCFUNC)remoteMem, hThread, 0)
// 7. CloseHandle on everything
// Return true on success.
bool apcInject(DWORD pid, const BYTE* shellcode, size_t len) {
    // YOUR CODE HERE
    return false;
}

int main(int argc, char* argv[]) {
    const char* target = (argc > 1) ? argv[1] : "notepad.exe";

    printf("[*] Looking for process: %s\n", target);
    DWORD pid = findTargetPid(target);
    if (!pid) {
        printf("[-] Process not found. Launch %s first.\n", target);
        return 1;
    }
    printf("[+] Found PID: %lu\n", pid);

    printf("[*] Attempting APC injection...\n");
    if (apcInject(pid, TEST_SHELLCODE, sizeof(TEST_SHELLCODE))) {
        printf("[+] APC queued. Shellcode will execute when thread enters alertable wait.\n");
        printf("[*] If injecting into notepad, minimize and restore the window to trigger.\n");
    } else {
        printf("[-] Injection failed. Error: %lu\n", GetLastError());
    }

    return 0;
}
