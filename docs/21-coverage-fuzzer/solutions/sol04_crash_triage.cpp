/*
  Solution 04 — Crash Triage (Complete)
  ---------------------------------------
  Runs a target under a debugger, captures crash context, deduplicates
  by signature, and rates exploitability.

  Compile:
    g++ -std=c++17 -Wall -o sol04.exe sol04_crash_triage.cpp -ldbghelp
    cl  /std:c++17 /Zi sol04_crash_triage.cpp /link dbghelp.lib /OUT:sol04.exe

  Usage:
    sol04.exe target.exe findings\crashes\
    sol04.exe parser.exe crashes\
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

// =========================================================
// Data types
// =========================================================
struct CrashInfo {
    std::string inputFile;
    DWORD       exceptionCode     = 0;
    PVOID       faultingAddress   = nullptr;
    DWORD       accessType        = 0;   // 0=read, 1=write, 8=execute (ExInfo[0])
    PVOID       accessTarget      = nullptr;  // ExInfo[1]
    CONTEXT     context           = {};
    bool        crashed           = false;
};

enum Exploitability {
    EXPLOITABLE,
    PROBABLY_EXPLOITABLE,
    UNKNOWN_EXPLOITABILITY,
    NOT_EXPLOITABLE
};


// =========================================================
// 1. runTarget — spawn under debugger, wait for first real exception
// =========================================================
CrashInfo runTarget(const std::string& exe, const std::string& inputFile) {
    CrashInfo info;
    info.inputFile = inputFile;

    // Build command line: "exe inputFile"
    std::string cmd = "\"" + exe + "\" \"" + inputFile + "\"";

    STARTUPINFOA si  = {};
    si.cb            = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(nullptr, &cmd[0], nullptr, nullptr,
                        FALSE, DEBUG_ONLY_THIS_PROCESS,
                        nullptr, nullptr, &si, &pi)) {
        printf("[-] CreateProcess(\"%s\") failed: %lu\n",
               cmd.c_str(), GetLastError());
        return info;
    }

    DEBUG_EVENT evt    = {};
    bool        firstBP = true;  // The very first BP is the system one at startup
    HANDLE      hThread = pi.hThread;

    while (WaitForDebugEvent(&evt, 5000)) {  // 5-second timeout per event
        DWORD continueStatus = DBG_CONTINUE;

        switch (evt.dwDebugEventCode) {

        case CREATE_THREAD_DEBUG_EVENT:
            hThread = evt.u.CreateThread.hThread;
            break;

        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD& ex = evt.u.Exception.ExceptionRecord;

            if (ex.ExceptionCode == EXCEPTION_BREAKPOINT && firstBP) {
                // System-injected BP at process start — skip it
                firstBP = false;
                break;
            }

            // Real crash or unhandled exception — capture everything
            info.exceptionCode   = ex.ExceptionCode;
            info.faultingAddress = ex.ExceptionAddress;
            info.crashed         = true;

            if (ex.ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                ex.NumberParameters >= 2) {
                info.accessType   = (DWORD)ex.ExceptionInformation[0];
                info.accessTarget = (PVOID)ex.ExceptionInformation[1];
            }

            // Capture thread context (registers)
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_ALL;
            if (GetThreadContext(hThread, &ctx))
                info.context = ctx;

            // Terminate the process — we have what we need
            TerminateProcess(pi.hProcess, 0xDEAD);
            ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueStatus);
            goto done;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            goto done;

        default:
            break;
        }

        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueStatus);
    }

done:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return info;
}


// =========================================================
// 2. crashSignature — human-readable dedup key
//    Format: "EXCEPTION_NAME:0x<faultingAddress>"
// =========================================================
std::string crashSignature(const CrashInfo& info) {
    const char* name;
    switch (info.exceptionCode) {
        case 0xC0000005:  // STATUS_ACCESS_VIOLATION
            if (info.accessType == 1)       name = "ACCESS_VIOLATION_WRITE";
            else if (info.accessType == 8)  name = "ACCESS_VIOLATION_EXEC";
            else                            name = "ACCESS_VIOLATION_READ";
            break;
        case 0xC0000094:  name = "INT_DIVIDE_BY_ZERO";        break;
        case 0xC00000FD:  name = "STACK_OVERFLOW";            break;
        case 0xC0000409:  name = "STACK_BUFFER_OVERRUN";      break;
        case 0xC0000374:  name = "HEAP_CORRUPTION";           break;
        case 0xC0000025:  name = "NONCONTINUABLE_EXCEPTION";  break;
        case 0xC0000096:  name = "PRIVILEGED_INSTRUCTION";    break;
        case 0xC000001D:  name = "ILLEGAL_INSTRUCTION";       break;
        case 0x80000003:  name = "BREAKPOINT";                break;
        case 0x80000004:  name = "SINGLE_STEP";               break;
        default:          name = "UNKNOWN_EXCEPTION";         break;
    }

    char sig[256];
    snprintf(sig, sizeof(sig), "%s:0x%016llX",
             name, (unsigned long long)(uintptr_t)info.faultingAddress);
    return sig;
}


// =========================================================
// 3. rateExploitability
// =========================================================
Exploitability rateExploitability(const CrashInfo& info) {
    if (info.exceptionCode == 0xC0000005) {  // ACCESS_VIOLATION
        if (info.accessType == 1) {
            // Write AV — attacker may control what is written where
            return EXPLOITABLE;
        }
        if (info.accessType == 8) {
            // Execute AV — possibly jumped to attacker-controlled data
            return EXPLOITABLE;
        }
        // Read AV
        uintptr_t target = (uintptr_t)info.accessTarget;
        if (target < 0x1000) {
            // Near-null dereference — likely NOT exploitable (null-ptr crash)
            return NOT_EXPLOITABLE;
        }
        // Read AV at non-null address — possible information disclosure or
        // use-after-free; conservative "probably"
        return PROBABLY_EXPLOITABLE;
    }

    if (info.exceptionCode == 0xC00000FD ||  // STACK_OVERFLOW
        info.exceptionCode == 0xC0000094) {  // DIV_BY_ZERO
        return NOT_EXPLOITABLE;
    }

    if (info.exceptionCode == 0xC0000409 ||  // STACK_BUFFER_OVERRUN (GS cookie)
        info.exceptionCode == 0xC0000374) {  // HEAP_CORRUPTION
        return EXPLOITABLE;
    }

    if (info.exceptionCode == 0xC000001D ||  // ILLEGAL_INSTRUCTION
        info.exceptionCode == 0xC0000096) {  // PRIVILEGED_INSTRUCTION
        return PROBABLY_EXPLOITABLE;
    }

    return UNKNOWN_EXPLOITABILITY;
}

static const char* exploitStr(Exploitability e) {
    switch (e) {
        case EXPLOITABLE:           return "EXPLOITABLE";
        case PROBABLY_EXPLOITABLE:  return "PROBABLY_EXPLOITABLE";
        case UNKNOWN_EXPLOITABILITY: return "UNKNOWN";
        case NOT_EXPLOITABLE:       return "NOT_EXPLOITABLE";
    }
    return "?";
}


// =========================================================
// 4. triageCrash — triage all crashes in a directory
// =========================================================
void triageCrashes(const std::string& targetExe,
                   const std::string& crashDir) {
    std::set<std::string>     seen;
    std::map<std::string,int> dupCount;
    int total = 0, uniqueCrashes = 0, missed = 0;

    // Collect and sort crash files for deterministic order
    std::vector<std::string> paths;
    for (auto& entry : fs::directory_iterator(crashDir))
        if (entry.is_regular_file())
            paths.push_back(entry.path().string());
    std::sort(paths.begin(), paths.end());

    printf("[*] Found %zu candidate crash files in '%s'\n\n",
           paths.size(), crashDir.c_str());

    for (auto& path : paths) {
        total++;
        CrashInfo info = runTarget(targetExe, path);

        if (!info.crashed) {
            printf("[MISS]  %s — did not crash on replay\n",
                   fs::path(path).filename().string().c_str());
            missed++;
            continue;
        }

        std::string sig = crashSignature(info);
        dupCount[sig]++;

        if (seen.count(sig)) {
            printf("[DUP]   %s  →  %s  (dup #%d)\n",
                   fs::path(path).filename().string().c_str(),
                   sig.c_str(), dupCount[sig]);
            continue;
        }

        seen.insert(sig);
        uniqueCrashes++;

        Exploitability exp = rateExploitability(info);

        // Print register state for EXPLOITABLE crashes
        printf("[NEW]   %s\n"
               "        sig      = %s\n"
               "        rating   = %s\n",
               fs::path(path).filename().string().c_str(),
               sig.c_str(),
               exploitStr(exp));

        if (info.exceptionCode == 0xC0000005) {
            printf("        access   = %s  target=0x%016llX\n",
                   info.accessType == 1 ? "WRITE"
                   : info.accessType == 8 ? "EXEC" : "READ",
                   (unsigned long long)(uintptr_t)info.accessTarget);
        }

#ifdef _WIN64
        printf("        RIP=0x%016llX  RSP=0x%016llX\n",
               (unsigned long long)info.context.Rip,
               (unsigned long long)info.context.Rsp);
#else
        printf("        EIP=0x%08lX  ESP=0x%08lX\n",
               info.context.Eip, info.context.Esp);
#endif
        printf("\n");
    }

    // Summary
    printf("============== TRIAGE SUMMARY ==============\n");
    printf("  Total files     : %d\n", total);
    printf("  Unique crashes  : %d\n", uniqueCrashes);
    printf("  Duplicates      : %d\n", total - uniqueCrashes - missed);
    printf("  No-replay       : %d\n", missed);
    printf("\n  By rating:\n");

    // Count by exploitability across unique crashes
    // (re-run is expensive; in practice cache results)
    printf("  (ratings shown per [NEW] entry above)\n");
    printf("============================================\n");
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage:   %s <target.exe> <crash_dir>\n", argv[0]);
        printf("Example: %s parser.exe findings\\crashes\\\n", argv[0]);
        return 1;
    }

    if (!fs::is_directory(argv[2])) {
        printf("[-] '%s' is not a directory\n", argv[2]);
        return 1;
    }

    triageCrashes(argv[1], argv[2]);
    return 0;
}
