/*
  Exercise 04 — Crash Triage
  ---------------------------
  Fuzzers can generate thousands of crashes. Most are duplicates — the same
  bug triggered by different inputs. Triage groups crashes by root cause.

  This exercise builds a crash triage tool that:
    1. Reproduces crashes under a debugger (WER / SEH).
    2. Captures crash context: exception code, faulting address, registers.
    3. Deduplicates by "crash signature" = (exceptionCode, faultingAddress).
    4. Rates crashes by exploitability:
         EXPLOITABLE   — write AV, RIP control
         PROBABLY      — read AV near null / in stack, heap metadata
         UNKNOWN       — other exceptions
         NOT_EXPLOITABLE — STATUS_STACK_OVERFLOW (guard page), divzero

  Tasks:
  1. Implement runTarget(exe, inputFile) → runs the target in a new process,
     monitors for a crash, returns CrashInfo.
  2. Implement crashSignature(info) → returns a string like
     "ACCESS_VIOLATION_WRITE:0x00007FF650001234".
  3. Implement rateExploitability(info) → returns one of the 4 ratings.
  4. Implement triageCrashes(crashFiles[], targetExe) → for each input
     that supposedly crashed: reproduce, deduplicate, rate, print report.

  BONUS:
  - Use !exploitable (msec.dll) conventions for rating.
  - Compute a "hash stack" — hash of the first 5 return addresses on the
    stack to catch same-bug-different-input cases.
  - Emit a Markdown triage report.

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_crash_triage.cpp
  Usage:
    ex04.exe target.exe findings\crashes\
*/

#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include <string>
#include <vector>
#include <map>
#include <set>
#include <filesystem>
#include <cstdio>

namespace fs = std::filesystem;

struct CrashInfo {
    std::string inputFile;
    DWORD       exceptionCode;
    PVOID       faultingAddress;
    DWORD       accessType;    // 0=read, 1=write, 8=execute
    CONTEXT     context;
    bool        crashed;
};

enum Exploitability { EXPLOITABLE, PROBABLY_EXPLOITABLE, UNKNOWN, NOT_EXPLOITABLE };

// ---------- TODO 1: runTarget ----------
CrashInfo runTarget(const std::string& exe, const std::string& inputFile) {
    CrashInfo info = {};
    info.inputFile = inputFile;

    // YOUR CODE HERE:
    // 1. Build command: exe + " " + inputFile
    // 2. CreateProcess with DEBUG_ONLY_THIS_PROCESS
    // 3. DebugLoop:
    //    - WaitForDebugEvent
    //    - On EXCEPTION_DEBUG_EVENT (first chance):
    //        record ExceptionCode, ExceptionAddress, ExceptionInformation[0/1]
    //        GetThreadContext to capture registers
    //        info.crashed = true
    //        TerminateProcess
    //    - On EXIT: break
    // 4. CloseHandle, return info

    (void)exe;
    return info;
}

// ---------- TODO 2: crash signature ----------
std::string crashSignature(const CrashInfo& info) {
    // YOUR CODE HERE:
    // Map ExceptionCode to human name (STATUS_ACCESS_VIOLATION = 0xC0000005 etc.)
    // Format: "EXCEPTION_NAME_RWTYPE:0x<faultingAddress>"
    char sig[128];
    sprintf_s(sig, "0x%08X:0x%p", info.exceptionCode, info.faultingAddress);
    return sig; // replace with proper mapping
}

// ---------- TODO 3: rate exploitability ----------
Exploitability rateExploitability(const CrashInfo& info) {
    if (info.exceptionCode == 0xC0000005) { // ACCESS_VIOLATION
        // YOUR CODE HERE:
        // accessType 1 (write) → EXPLOITABLE
        // RIP in faulting module range → EXPLOITABLE
        // accessType 0 near null (<0x1000) → NOT_EXPLOITABLE
        // else → PROBABLY_EXPLOITABLE
        if (info.accessType == 1) return EXPLOITABLE;
        return PROBABLY_EXPLOITABLE;
    }
    if (info.exceptionCode == 0xC00000FD) // STACK_OVERFLOW
        return NOT_EXPLOITABLE;
    return UNKNOWN;
}

const char* exploitStr(Exploitability e) {
    switch (e) {
        case EXPLOITABLE:           return "EXPLOITABLE";
        case PROBABLY_EXPLOITABLE:  return "PROBABLY_EXPLOITABLE";
        case UNKNOWN:               return "UNKNOWN";
        case NOT_EXPLOITABLE:       return "NOT_EXPLOITABLE";
    }
    return "?";
}

// ---------- TODO 4: triage directory ----------
void triageCrashes(const std::string& targetExe, const std::string& crashDir) {
    std::set<std::string>    seen;
    std::map<std::string, int> dupCount;
    int total = 0, unique = 0;

    for (auto& entry : fs::directory_iterator(crashDir)) {
        if (!entry.is_regular_file()) continue;
        std::string path = entry.path().string();
        total++;

        CrashInfo info = runTarget(targetExe, path);
        if (!info.crashed) {
            printf("[MISS] %s — did not crash on replay\n", path.c_str());
            continue;
        }

        std::string sig = crashSignature(info);
        dupCount[sig]++;
        if (seen.count(sig)) {
            printf("[DUP]  %s — same as %s\n", path.c_str(), sig.c_str());
            continue;
        }
        seen.insert(sig);
        unique++;

        Exploitability exp = rateExploitability(info);
        printf("[NEW]  %s\n"
               "       sig=%s  rating=%s\n",
               path.c_str(), sig.c_str(), exploitStr(exp));
    }

    printf("\n[TRIAGE] Total: %d  Unique: %d  Deduped: %d\n",
           total, unique, total - unique);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target.exe> <crash_dir>\n", argv[0]);
        printf("  Example: %s parser.exe findings\\crashes\\\n", argv[0]);
        return 1;
    }
    triageCrashes(argv[1], argv[2]);
    return 0;
}
