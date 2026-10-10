// exercise_04_memory_scanner.cpp
// Module 12 Exercise 04 — Memory Scanner
// Compile: g++ -std=c++17 -Wall -o ex04.exe exercise_04_memory_scanner.cpp
//
// Goal: Find private executable memory regions in running processes.
// Attackers who inject shellcode or reflectively load PEs create MEM_PRIVATE
// regions with execute permissions — a pattern normal code does not produce.
//
// What you will practice:
//   - Enumerating processes with Toolhelp32
//   - OpenProcess with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
//   - VirtualQueryEx to walk the virtual address space
//   - Filtering MEM_PRIVATE + executable pages
//   - ReadProcessMemory to peek at the first bytes (MZ header = PE inject)

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <vector>

// ============================================= Protection flag helpers =======

static bool is_executable(DWORD prot) {
    return (prot & (PAGE_EXECUTE |
                    PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE |
                    PAGE_EXECUTE_WRITECOPY)) != 0;
}

static const char* prot_str(DWORD prot) {
    switch (prot & 0xFF) {
        case PAGE_EXECUTE:            return "X";
        case PAGE_EXECUTE_READ:       return "RX";
        case PAGE_EXECUTE_READWRITE:  return "RWX";
        case PAGE_EXECUTE_WRITECOPY:  return "RWXC";
        case PAGE_READONLY:           return "R";
        case PAGE_READWRITE:          return "RW";
        case PAGE_WRITECOPY:          return "WC";
        case PAGE_NOACCESS:           return "NA";
        default:                       return "?";
    }
}

// ============================================= Scan one process =============

// Walks the virtual address space of `pid`.
// Flags every MEM_PRIVATE + executable committed region.
// Reads the first 2 bytes of each flagged region; if they are 'MZ'
// it likely contains an injected PE.
static int scan_process(DWORD pid, const std::string& name) {
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    MEMORY_BASIC_INFORMATION mbi{};
    ULONG_PTR addr = 0;
    int suspicious = 0;

    while (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr),
                          &mbi, sizeof mbi) == sizeof mbi) {
        if (mbi.State  == MEM_COMMIT  &&
            mbi.Type   == MEM_PRIVATE &&
            is_executable(mbi.Protect)) {

            // Try to read first two bytes for MZ signature check
            BYTE hdr[2] = {0, 0};
            SIZE_T got  = 0;
            bool   read_ok = ReadProcessMemory(
                hProc, mbi.BaseAddress, hdr, 2, &got) && (got >= 2);
            bool   is_mz   = read_ok && hdr[0] == 'M' && hdr[1] == 'Z';

            std::cout << "  PID=" << std::setw(6) << pid
                      << "  Name=" << std::left << std::setw(22) << name
                      << std::right
                      << "  Base=0x" << std::hex << std::setw(16)
                      << std::setfill('0')
                      << reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                      << std::dec << std::setfill(' ')
                      << "  Size=" << std::setw(8) << mbi.RegionSize
                      << "  Prot=" << prot_str(mbi.Protect)
                      << (is_mz ? "  [MZ/PE_INJECT]" : "  [EXEC_PRIVATE]")
                      << "\n";
            ++suspicious;
        }

        // Advance to next region; guard against pointer overflow
        ULONG_PTR next = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    if (suspicious)
        std::cout << "  >> " << name << " PID=" << pid
                  << " : " << suspicious << " suspicious region(s)\n\n";

    CloseHandle(hProc);
    return suspicious;
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    // Optional: pass a single PID to scan only that process
    DWORD target_pid = 0;
    if (argc >= 2) {
        try { target_pid = static_cast<DWORD>(std::stoul(argv[1])); }
        catch (...) {}
    }

    std::cout << "[MemScan] Scanning for private executable memory";
    if (target_pid)
        std::cout << " in PID " << target_pid;
    else
        std::cout << " in all processes";
    std::cout << "...\n\n";

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "[ERROR] Cannot create process snapshot: "
                  << GetLastError() << "\n";
        return 1;
    }

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof pe;

    int total_procs    = 0;
    int total_suspicious = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;

            // Skip Idle (0) and System (4)
            if (pid == 0 || pid == 4) continue;

            // If a specific PID was requested, skip everything else
            if (target_pid && pid != target_pid) continue;

            ++total_procs;
            total_suspicious += scan_process(pid, pe.szExeFile);

        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    std::cout << "[MemScan] Done. Scanned " << total_procs << " process(es), "
              << total_suspicious << " suspicious region(s) found.\n";
    return 0;
}
