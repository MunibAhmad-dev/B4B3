// exercise_02_process_monitor.cpp
// Module 12 Exercise 02 — Process Monitor
// Compile: g++ -std=c++17 -Wall -o ex02.exe exercise_02_process_monitor.cpp
//
// Goal: Track running processes and report newly started or terminated ones.
// This is how EDR tools detect process injection, living-off-the-land binaries,
// and privilege escalation chains.
//
// What you will practice:
//   - Taking a Toolhelp32 snapshot (CreateToolhelp32Snapshot)
//   - Iterating processes with Process32First / Process32Next
//   - Diffing two snapshots stored in a std::map<DWORD, ProcInfo>
//   - Printing STARTED / TERMINATED events with PID, PPID, and process name

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <map>
#include <iostream>
#include <iomanip>

// =========================================================== Data types ======

struct ProcInfo {
    DWORD       pid;
    DWORD       ppid;
    std::string name;   // exe filename from PROCESSENTRY32
};

// Maps PID -> process information for a single snapshot.
using ProcMap = std::map<DWORD, ProcInfo>;

// ======================================================== Snapshot helper ====

// Returns a snapshot of every running process.
static ProcMap snapshot_processes() {
    ProcMap result;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "[ERROR] CreateToolhelp32Snapshot failed: "
                  << GetLastError() << "\n";
        return result;
    }

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof pe;      // mandatory before first call

    if (Process32First(hSnap, &pe)) {
        do {
            ProcInfo info;
            info.pid  = pe.th32ProcessID;
            info.ppid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            result[info.pid] = info;
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return result;
}

// ======================================================= Diff and report ====

// Compares two snapshots and prints what changed.
static void diff_procs(const ProcMap& prev, const ProcMap& curr) {
    // Processes in curr that are not in prev have just STARTED
    for (const auto& [pid, info] : curr) {
        if (prev.find(pid) == prev.end()) {
            std::cout << "  [STARTED]    PID="
                      << std::setw(6) << pid
                      << "  PPID=" << std::setw(6) << info.ppid
                      << "  " << info.name << "\n";
        }
    }

    // Processes in prev that are not in curr have TERMINATED
    for (const auto& [pid, info] : prev) {
        if (curr.find(pid) == curr.end()) {
            std::cout << "  [TERMINATED] PID="
                      << std::setw(6) << pid
                      << "  " << info.name << "\n";
        }
    }
}

// =========================================================== Timestamp ======

static std::string now_str() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d",
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    int interval_s = 2;
    if (argc >= 2) {
        try { interval_s = std::stoi(argv[1]); }
        catch (...) {}
    }

    std::cout << "[ProcMon] Monitoring process list every "
              << interval_s << "s. Ctrl+C to stop.\n\n";

    // Take initial snapshot (baseline)
    ProcMap prev = snapshot_processes();
    std::cout << "[ProcMon] Initial snapshot: " << prev.size() << " process(es).\n\n";

    for (;;) {
        Sleep(static_cast<DWORD>(interval_s) * 1000);

        ProcMap curr = snapshot_processes();

        std::cout << "[" << now_str() << "] Snapshot ("
                  << curr.size() << " processes)\n";

        diff_procs(prev, curr);

        // Roll forward
        prev = curr;
    }
}
