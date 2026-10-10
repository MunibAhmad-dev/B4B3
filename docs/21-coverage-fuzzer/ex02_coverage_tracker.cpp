/*
  Exercise 02 — Coverage Tracking with Breakpoints
  --------------------------------------------------
  WinAFL needs DynamoRIO for coverage. This exercise implements a simpler
  alternative: software breakpoint (INT3) based coverage tracking using
  the Windows Debug API.

  The debugger:
    1. Spawns the target process with DEBUG_ONLY_THIS_PROCESS.
    2. On CREATE_PROCESS_DEBUG_EVENT, reads the PE header to enumerate
       all basic block entry points (simulated by breakpointing function
       entries from the export table).
    3. Sets INT3 breakpoints (saves original byte, writes 0xCC).
    4. On EXCEPTION_BREAKPOINT events, records the address as "hit",
       restores the original byte, and continues.
    5. At exit, prints a coverage bitmap: which breakpoints were hit.

  This is how early versions of coverage-guided fuzzers worked before
  compile-time instrumentation and hardware tracing (Intel PT) became common.

  Tasks:
  1. Implement spawnTarget(exe) — CreateProcess with DEBUG_ONLY_THIS_PROCESS.
  2. Implement setBreakpoint(hProcess, addr) — save original byte, write 0xCC.
  3. Implement removeBreakpoint(hProcess, addr) — restore original byte.
  4. Implement debugLoop() — handle CREATE_PROCESS, EXCEPTION_DEBUG_EVENT,
     EXIT_PROCESS; track hit/miss per breakpoint.
  5. Print coverage: total BPs set, how many were hit, hit percentage.

  BONUS:
  - Use Intel PT (PROCESSOR_TRACE) via perf_event on Linux or
    ipt.dll on Windows to get cycle-accurate branch tracing without
    modifying target code at all.
  - Integrate with a mutation engine: re-run with different inputs and
    measure new coverage to guide corpus selection.

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_coverage_tracker.cpp
  Usage:
    ex02.exe target.exe [arg]
    ex02.exe notepad.exe
*/

#include <windows.h>
#include <map>
#include <vector>
#include <string>
#include <cstdio>

struct Breakpoint {
    BYTE   originalByte;
    bool   hit;
};

static std::map<LPVOID, Breakpoint> g_breakpoints;

// ---------- TODO 1: spawnTarget ----------
bool spawnTarget(const std::string& exe, PROCESS_INFORMATION& pi) {
    STARTUPINFOA si = { sizeof(si) };
    // YOUR CODE HERE:
    // CreateProcessA(exe.c_str(), nullptr, nullptr, nullptr, FALSE,
    //                DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi)
    (void)exe; (void)si; (void)pi;
    return false; // replace
}

// ---------- TODO 2: setBreakpoint ----------
bool setBreakpoint(HANDLE hProcess, LPVOID addr) {
    if (g_breakpoints.count(addr)) return true;
    Breakpoint bp = {};
    SIZE_T bytesRead = 0;
    // YOUR CODE HERE:
    // ReadProcessMemory(hProcess, addr, &bp.originalByte, 1, &bytesRead)
    // BYTE int3 = 0xCC;
    // WriteProcessMemory(hProcess, addr, &int3, 1, &bytesRead)
    // FlushInstructionCache(hProcess, addr, 1)
    (void)hProcess; (void)bytesRead;
    g_breakpoints[addr] = bp;
    return false; // return true when implemented
}

// ---------- TODO 3: removeBreakpoint ----------
bool removeBreakpoint(HANDLE hProcess, LPVOID addr) {
    auto it = g_breakpoints.find(addr);
    if (it == g_breakpoints.end()) return false;
    SIZE_T w = 0;
    // YOUR CODE HERE:
    // WriteProcessMemory(hProcess, addr, &it->second.originalByte, 1, &w)
    // FlushInstructionCache(hProcess, addr, 1)
    // it->second.hit = true;
    (void)hProcess; (void)w;
    return false; // return true when implemented
}

// ---------- TODO 4: debugLoop ----------
void debugLoop(HANDLE hProcess, HANDLE hThread) {
    DEBUG_EVENT evt = {};
    while (WaitForDebugEvent(&evt, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;

        switch (evt.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            printf("[DBG] Process created, image base: %p\n",
                   evt.u.CreateProcessInfo.lpBaseOfImage);
            // TODO: enumerate exports and set breakpoints on each function entry
            CloseHandle(evt.u.CreateProcessInfo.hFile);
            break;

        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD& ex = evt.u.Exception.ExceptionRecord;
            if (ex.ExceptionCode == EXCEPTION_BREAKPOINT) {
                LPVOID addr = ex.ExceptionAddress;
                if (g_breakpoints.count(addr)) {
                    // TODO: removeBreakpoint, mark hit, rewind EIP by 1
                    // CONTEXT ctx = { CONTEXT_CONTROL };
                    // GetThreadContext(hThread, &ctx);
                    // ctx.Rip--;
                    // SetThreadContext(hThread, &ctx);
                    printf("[HIT] Breakpoint at %p\n", addr);
                }
                // else: first-chance system BP at process start, continue
            } else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[DBG] Process exited (code %lu)\n",
                   evt.u.ExitProcess.dwExitCode);
            goto done;

        default: break;
        }
        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueStatus);
    }
done:;
    (void)hThread;
}

// ---------- TODO 5: print coverage ----------
void printCoverage() {
    size_t total = g_breakpoints.size();
    size_t hit   = 0;
    for (auto& [addr, bp] : g_breakpoints)
        if (bp.hit) hit++;
    printf("\n[COV] Coverage: %zu / %zu (%.1f%%)\n",
           hit, total, total ? 100.0 * hit / total : 0.0);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target.exe> [args]\n", argv[0]);
        return 1;
    }
    PROCESS_INFORMATION pi = {};
    if (!spawnTarget(argv[1], pi)) {
        printf("[-] spawnTarget not implemented or failed\n");
        return 1;
    }
    debugLoop(pi.hProcess, pi.hThread);
    printCoverage();
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
