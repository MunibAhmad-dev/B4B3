/*
  Exercise 02 — Early Bird APC Injection
  ----------------------------------------
  More reliable than standard APC because the shellcode fires before the
  target process's main() has even run — the process is in CREATE_SUSPENDED
  when we queue the APC, so the first thing it does on resume is execute our code.

  Tasks:
  1. Implement earlyBirdInject():
     a. CreateProcess("notepad.exe", ..., CREATE_SUSPENDED, ..., &pi)
     b. VirtualAllocEx into pi.hProcess
     c. WriteProcessMemory shellcode
     d. QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0)
        Note: pi.hThread is the MAIN THREAD of the new process, in suspended state.
     e. ResumeThread(pi.hThread)
        The main thread resumes, processes its APC queue, runs your shellcode,
        then continues into the real entry point (or doesn't, depending on shellcode).

  2. Observe: no window appears for notepad.exe until after your shellcode returns.
     The shellcode stub below just returns immediately — so notepad will still open.

  3. Experiment: replace the stub with shellcode that sleeps 2 seconds.
     You'll see notepad is "stuck" for 2 seconds before its window appears.

  BONUS:
  - Queue MULTIPLE APCs to the same thread — all will fire in order.
  - What happens if the shellcode crashes? (The whole process dies)
  - How would an EDR detect CREATE_SUSPENDED immediately followed by VirtualAllocEx?

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_early_bird.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>

// Minimal shellcode — just returns cleanly so notepad still starts
static const BYTE STUB[] = {
    0x48, 0x83, 0xEC, 0x28,  // sub rsp, 0x28
    0x90, 0x90, 0x90, 0x90,  // NOPs (your payload goes here)
    0x48, 0x83, 0xC4, 0x28,  // add rsp, 0x28
    0xC3                      // ret
};

// TODO: Implement Early Bird APC injection.
//
// Steps (all in one function):
//   1. CreateProcessA with CREATE_SUSPENDED flag
//   2. VirtualAllocEx into pi.hProcess, PAGE_EXECUTE_READWRITE
//   3. WriteProcessMemory shellcode into remoteMem
//   4. (Optional) VirtualProtectEx to PAGE_EXECUTE_READ
//   5. QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0)
//   6. ResumeThread(pi.hThread)
//
// On success: notepad.exe starts but executes your shellcode first.
// Return true on success, false on any failure (also TerminateProcess on failure).
bool earlyBirdInject(const char* targetPath, const BYTE* shellcode, size_t shellcodeLen) {
    // YOUR CODE HERE
    return false;
}

int main() {
    const char* target = "C:\\Windows\\System32\\notepad.exe";

    printf("[*] Early Bird APC injection into: %s\n", target);

    if (earlyBirdInject(target, STUB, sizeof(STUB))) {
        printf("[+] Success — notepad should open after shellcode runs.\n");
    } else {
        printf("[-] Failed. Error: %lu\n", GetLastError());
        return 1;
    }

    return 0;
}
