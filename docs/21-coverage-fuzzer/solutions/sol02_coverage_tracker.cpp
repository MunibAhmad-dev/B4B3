/*
  Solution 02 — Breakpoint-Based Coverage Tracker (Complete)
  -----------------------------------------------------------
  Uses INT3 software breakpoints + the Windows Debug API to track
  which addresses in the target process were executed.

  Compile:
    g++ -std=c++17 -Wall -o sol02.exe sol02_coverage_tracker.cpp

  Usage:
    sol02.exe target.exe
    sol02.exe notepad.exe
    sol02.exe my_parser.exe corpus/01_valid.txt

  NOTE: The breakpoints are set on hard-coded demo addresses in main()
  because export-table enumeration is highly PE-format-specific.
  For real usage, populate g_targetAddresses from the export table
  (see comments in setInitialBreakpoints).
*/

#include <windows.h>
#include <map>
#include <vector>
#include <string>
#include <cstdio>
#include <algorithm>

// =========================================================
// Global state
// =========================================================
struct Breakpoint {
    BYTE originalByte;
    bool hit;
};

static std::map<LPVOID, Breakpoint> g_breakpoints;

// Addresses to break on (populated from export table or caller)
static std::vector<LPVOID> g_targetAddresses;


// =========================================================
// 1. setBreakpoint — save original byte, write 0xCC (INT3)
// =========================================================
bool setBreakpoint(HANDLE hProcess, LPVOID addr) {
    if (g_breakpoints.count(addr)) return true;   // already set

    Breakpoint bp = {};
    SIZE_T bytesRW = 0;

    // Save the original byte
    if (!ReadProcessMemory(hProcess, addr, &bp.originalByte, 1, &bytesRW)
        || bytesRW != 1) {
        printf("[-] setBreakpoint: ReadProcessMemory(%p) failed: %lu\n",
               addr, GetLastError());
        return false;
    }

    // Write INT3
    BYTE int3 = 0xCC;
    if (!WriteProcessMemory(hProcess, addr, &int3, 1, &bytesRW) || bytesRW != 1) {
        printf("[-] setBreakpoint: WriteProcessMemory(%p) failed: %lu\n",
               addr, GetLastError());
        return false;
    }

    // Flush the instruction cache so the CPU sees the change
    FlushInstructionCache(hProcess, addr, 1);

    bp.hit              = false;
    g_breakpoints[addr] = bp;
    return true;
}


// =========================================================
// 2. removeBreakpoint — restore original byte and mark hit
// =========================================================
bool removeBreakpoint(HANDLE hProcess, LPVOID addr, HANDLE hThread) {
    auto it = g_breakpoints.find(addr);
    if (it == g_breakpoints.end()) return false;

    SIZE_T bytesRW = 0;

    // Restore original byte
    if (!WriteProcessMemory(hProcess, addr,
                            &it->second.originalByte, 1, &bytesRW)
        || bytesRW != 1) {
        printf("[-] removeBreakpoint: WriteProcessMemory(%p) failed: %lu\n",
               addr, GetLastError());
        return false;
    }
    FlushInstructionCache(hProcess, addr, 1);

    // Rewind instruction pointer by 1 (INT3 advanced it past the 0xCC)
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
        ctx.Rip--;
#else
        ctx.Eip--;
#endif
        SetThreadContext(hThread, &ctx);
    }

    it->second.hit = true;
    return true;
}


// =========================================================
// Helper: set breakpoints on target addresses at process start
// For a real tool: parse the PE export table here.
// =========================================================
static void setInitialBreakpoints(HANDLE hProcess,
                                   LPVOID imageBase) {
    /*
     * In a real coverage harness:
     *   1. Read the PE at imageBase (in-process memory).
     *   2. Walk IMAGE_EXPORT_DIRECTORY to find function RVAs.
     *   3. For each RVA: setBreakpoint(hProcess, (BYTE*)imageBase + rva)
     *
     * Here we use the caller-provided g_targetAddresses list instead.
     * Addresses in g_targetAddresses are relative to imageBase when
     * non-null, or absolute when imageBase is nullptr.
     */
    for (LPVOID rva : g_targetAddresses) {
        LPVOID absolute = imageBase
            ? (LPVOID)((BYTE*)imageBase + (uintptr_t)rva)
            : rva;
        if (setBreakpoint(hProcess, absolute))
            printf("[BP]  Set breakpoint at %p\n", absolute);
    }

    if (g_targetAddresses.empty())
        printf("[!]  No target addresses provided — coverage will be empty.\n"
               "     Populate g_targetAddresses with function RVAs before calling.\n");
}


// =========================================================
// 3. trackCoverage / debugLoop
//    Spawns the target with DEBUG_ONLY_THIS_PROCESS, drives
//    the debug event loop, removes hit BPs and records coverage.
// =========================================================
bool spawnTarget(const std::string& cmdLine, PROCESS_INFORMATION& pi) {
    STARTUPINFOA si = {};
    si.cb = sizeof(si);

    // Need a mutable copy of the command line
    std::string cmd = cmdLine;

    BOOL ok = CreateProcessA(
        nullptr,           // application name — use cmdLine
        &cmd[0],           // mutable command-line buffer
        nullptr, nullptr,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS,
        nullptr, nullptr,
        &si, &pi);

    if (!ok) {
        printf("[-] CreateProcess(\"%s\") failed: %lu\n",
               cmdLine.c_str(), GetLastError());
    }
    return ok == TRUE;
}

void trackCoverage(HANDLE hProcess, HANDLE hThread) {
    (void)hThread;  // used via per-event thread handle below

    DEBUG_EVENT evt = {};
    HANDLE      curThread = hThread;

    while (WaitForDebugEvent(&evt, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;

        switch (evt.dwDebugEventCode) {

        case CREATE_PROCESS_DEBUG_EVENT: {
            LPVOID base = evt.u.CreateProcessInfo.lpBaseOfImage;
            printf("[DBG] Process created.  ImageBase = %p\n", base);
            setInitialBreakpoints(hProcess, base);
            curThread = evt.u.CreateProcessInfo.hThread;
            CloseHandle(evt.u.CreateProcessInfo.hFile);
            break;
        }

        case CREATE_THREAD_DEBUG_EVENT:
            curThread = evt.u.CreateThread.hThread;
            break;

        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD& ex = evt.u.Exception.ExceptionRecord;

            if (ex.ExceptionCode == EXCEPTION_BREAKPOINT) {
                LPVOID addr = ex.ExceptionAddress;

                if (g_breakpoints.count(addr)) {
                    // Our breakpoint — restore, rewind RIP, record
                    removeBreakpoint(hProcess, addr, curThread);
                    printf("[HIT] Breakpoint hit at %p\n", addr);
                }
                // else: the very first system BP at process start — just continue
            } else {
                // Let the process handle any other exception
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[DBG] Process exited (code %lu)\n",
                   evt.u.ExitProcess.dwExitCode);
            ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueStatus);
            goto done;

        default:
            break;
        }

        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueStatus);
    }
done:;
}


// =========================================================
// 4. printReport — show each address as hit / miss with %
// =========================================================
void printReport() {
    size_t total = g_breakpoints.size();
    size_t hit   = 0;
    for (auto& [addr, bp] : g_breakpoints)
        if (bp.hit) hit++;

    printf("\n========== COVERAGE REPORT ==========\n");
    printf("  %-20s  %s\n", "Address", "Status");
    printf("  %s\n", std::string(35, '-').c_str());

    for (auto& [addr, bp] : g_breakpoints)
        printf("  %-20p  %s\n", addr, bp.hit ? "HIT" : "miss");

    printf("\n  Total breakpoints : %zu\n",  total);
    printf("  Hit               : %zu\n",  hit);
    printf("  Miss              : %zu\n",  total - hit);
    printf("  Coverage          : %.1f%%\n",
           total ? 100.0 * hit / total : 0.0);
    printf("=====================================\n");
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target.exe> [args...]\n", argv[0]);
        printf("  Optional: set g_targetAddresses with function RVAs\n");
        printf("  Example : %s notepad.exe\n", argv[0]);
        return 1;
    }

    // Build the full command line from all arguments
    std::string cmdLine;
    for (int i = 1; i < argc; i++) {
        if (i > 1) cmdLine += ' ';
        // Quote arguments that contain spaces
        bool hasSpace = (strchr(argv[i], ' ') != nullptr);
        if (hasSpace) cmdLine += '"';
        cmdLine += argv[i];
        if (hasSpace) cmdLine += '"';
    }

    /*
     * Demo: if you know the function entry-point RVAs of your target DLL,
     * add them here (as RVAs, not absolute addresses — they get rebased in
     * setInitialBreakpoints).  Example:
     *   g_targetAddresses.push_back((LPVOID)0x1A20);  // parseHttpHeader RVA
     *   g_targetAddresses.push_back((LPVOID)0x2B40);  // validateMethod RVA
     */

    PROCESS_INFORMATION pi = {};
    if (!spawnTarget(cmdLine, pi)) return 1;

    printf("[*] Debugging: %s\n", cmdLine.c_str());
    trackCoverage(pi.hProcess, pi.hThread);

    printReport();

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
