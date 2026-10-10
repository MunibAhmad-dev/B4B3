// sol01_debug_attach.cpp — debugger attach + single-step
// Compile: g++ -std=c++17 -o sol01.exe sol01_debug_attach.cpp
// Usage: sol01.exe <pid>   (Run as administrator)
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: sol01.exe <pid>\n"); return 1; }
    DWORD pid = (DWORD)strtoul(argv[1], nullptr, 10);

    if (!DebugActiveProcess(pid)) {
        fprintf(stderr, "DebugActiveProcess failed: %lu\n", GetLastError());
        return 1;
    }
    DebugSetProcessKillOnExit(FALSE);
    printf("[*] Attached to PID %lu\n", pid);

    int steps = 0;
    HANDLE hThread = nullptr;
    DEBUG_EVENT de{};
    bool stop = false;

    while (!stop && WaitForDebugEvent(&de, 5000)) {
        DWORD status = DBG_CONTINUE;
        switch (de.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            hThread = de.u.CreateProcessInfo.hThread;
            CloseHandle(de.u.CreateProcessInfo.hFile);
            printf("[+] Process attached; thread=0x%p\n", hThread);
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            if (!hThread) hThread = de.u.CreateThread.hThread;
            break;

        case EXCEPTION_DEBUG_EVENT: {
            auto& ex = de.u.Exception.ExceptionRecord;
            if (ex.ExceptionCode == EXCEPTION_BREAKPOINT) {
                printf("[BP] 0x%p  (first-chance=%d)\n",
                       ex.ExceptionAddress, de.u.Exception.dwFirstChance);
                // Enable single-step for next 10 instructions
                if (hThread) {
                    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
                    GetThreadContext(hThread, &ctx);
                    ctx.EFlags |= 0x100; // TF
                    SetThreadContext(hThread, &ctx);
                }
            } else if (ex.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
                if (hThread) GetThreadContext(hThread, &ctx);
                printf("[SS %2d] RIP=0x%p  RAX=0x%llX\n",
                       ++steps, ex.ExceptionAddress,
#ifdef _WIN64
                       (unsigned long long)ctx.Rax
#else
                       (unsigned long long)ctx.Eax
#endif
                );
                if (steps < 10 && hThread) {
                    ctx.EFlags |= 0x100;
                    SetThreadContext(hThread, &ctx);
                } else { stop = true; }
            } else {
                status = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[*] Process exited\n"); stop = true; break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status);
    }
    DebugActiveProcessStop(pid);
    printf("[*] Detached\n");
    return 0;
}
