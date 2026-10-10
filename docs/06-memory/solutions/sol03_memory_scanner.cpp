// sol03_memory_scanner.cpp
// Scans the entire virtual address space of a process using VirtualQueryEx.
// If a PID is passed, scans that process; otherwise scans the current process.
//
// Compile:
//   g++ -std=c++17 -Wall -o sol03.exe solutions/sol03_memory_scanner.cpp
//
// Usage:
//   sol03.exe          — scan self
//   sol03.exe <pid>    — scan another process (requires appropriate privileges)

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <string>

// -------------------------------------------------------------------------
// Decode helpers
// -------------------------------------------------------------------------

static const char* StateName(DWORD state)
{
    switch (state) {
        case MEM_FREE:    return "FREE   ";
        case MEM_RESERVE: return "RESERVE";
        case MEM_COMMIT:  return "COMMIT ";
        default:          return "UNKNOWN";
    }
}

static const char* TypeName(DWORD type)
{
    switch (type) {
        case MEM_IMAGE:   return "IMAGE  ";
        case MEM_MAPPED:  return "MAPPED ";
        case MEM_PRIVATE: return "PRIVATE";
        default:          return "       ";
    }
}

// Build a short protection string like "R--", "RW-", "RX-", "RWX"
static std::string ProtectStr(DWORD prot)
{
    DWORD base = prot & 0xFF;
    bool guard  = (prot & PAGE_GUARD) != 0;
    bool nocache= (prot & PAGE_NOCACHE) != 0;

    std::string s;
    switch (base) {
        case PAGE_NOACCESS:          s = "---"; break;
        case PAGE_READONLY:          s = "R--"; break;
        case PAGE_READWRITE:         s = "RW-"; break;
        case PAGE_WRITECOPY:         s = "RWC"; break;
        case PAGE_EXECUTE:           s = "--X"; break;
        case PAGE_EXECUTE_READ:      s = "R-X"; break;
        case PAGE_EXECUTE_READWRITE: s = "RWX"; break;
        case PAGE_EXECUTE_WRITECOPY: s = "RXC"; break;
        default:                     s = "???"; break;
    }
    if (guard)   s += " GUARD";
    if (nocache) s += " NOCACHE";
    return s;
}

static bool IsExecutable(DWORD prot)
{
    DWORD base = prot & 0xFF;
    return (base == PAGE_EXECUTE ||
            base == PAGE_EXECUTE_READ ||
            base == PAGE_EXECUTE_READWRITE ||
            base == PAGE_EXECUTE_WRITECOPY);
}

// -------------------------------------------------------------------------
// Scanner
// -------------------------------------------------------------------------

struct RegionInfo {
    LPVOID  base;
    SIZE_T  size;
    DWORD   state;
    DWORD   type;
    DWORD   protect;
};

static void ScanProcess(HANDLE hProc, DWORD pid)
{
    printf("\n=== Memory Map for PID %lu ===\n\n", pid);
    printf("%-18s  %-14s  %-7s  %-7s  %-10s  %s\n",
           "BaseAddress", "Size", "State", "Type", "Protect", "Flags");
    printf("%-18s  %-14s  %-7s  %-7s  %-10s  %s\n",
           "------------------", "--------------",
           "-------", "-------", "----------", "-----");

    LPVOID addr = 0;
    SIZE_T totalCommit  = 0;
    SIZE_T totalPrivExec = 0;

    std::vector<RegionInfo> execPrivate;

    while (true) {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T ret = VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi));
        if (ret == 0) break;  // end of accessible address space

        // Print one row per region
        printf("0x%016llX  %14llu  %s  %s  %-10s",
               (unsigned long long)(uintptr_t)mbi.BaseAddress,
               (unsigned long long)mbi.RegionSize,
               StateName(mbi.State),
               TypeName(mbi.Type),
               ProtectStr(mbi.Protect).c_str());

        // Annotations
        bool flagged = false;
        if (mbi.State == MEM_COMMIT) {
            totalCommit += mbi.RegionSize;
            if (mbi.Type == MEM_PRIVATE && IsExecutable(mbi.Protect)) {
                totalPrivExec += mbi.RegionSize;
                printf("  << EXEC PRIVATE");
                flagged = true;
                execPrivate.push_back({mbi.BaseAddress, mbi.RegionSize,
                                       mbi.State, mbi.Type, mbi.Protect});
            }
        }
        printf("\n");

        // Advance; avoid infinite loop at 0-size regions.
        if (mbi.RegionSize == 0)
            addr = (LPVOID)((uintptr_t)addr + 0x1000);
        else
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);

        // 64-bit: stop when we wrap around.
        if ((uintptr_t)addr < (uintptr_t)mbi.BaseAddress)
            break;
    }

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    printf("\n--- Summary ---\n");
    printf("  Total committed:            %llu bytes  (%.2f MB)\n",
           (unsigned long long)totalCommit,
           totalCommit / (1024.0 * 1024.0));
    printf("  Private executable regions: %llu bytes  (%.2f MB) — %zu region(s)\n",
           (unsigned long long)totalPrivExec,
           totalPrivExec / (1024.0 * 1024.0),
           execPrivate.size());

    if (!execPrivate.empty()) {
        printf("\n--- Flagged: PRIVATE + EXECUTABLE regions ---\n");
        for (auto& r : execPrivate) {
            printf("  0x%016llX  size=%-10llu  protect=%s\n",
                   (unsigned long long)(uintptr_t)r.base,
                   (unsigned long long)r.size,
                   ProtectStr(r.protect).c_str());
        }
        printf("\n[!] %zu private executable region(s) found — potential shellcode injection.\n",
               execPrivate.size());
    } else {
        printf("\n[OK] No private executable regions detected.\n");
    }
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    printf("=== Process Memory Scanner ===\n");

    DWORD  targetPid = GetCurrentProcessId();
    HANDLE hProc     = GetCurrentProcess();
    bool   ownProcess = true;

    if (argc >= 2) {
        targetPid = (DWORD)atoi(argv[1]);
        if (targetPid == 0) {
            printf("[!] Invalid PID: %s\n", argv[1]);
            return 1;
        }
        // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ are required for
        // VirtualQueryEx on a remote process.
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, targetPid);
        if (hProc == NULL) {
            printf("[!] OpenProcess(PID=%lu) failed: %lu\n",
                   targetPid, GetLastError());
            printf("    Tip: run as administrator for cross-process scanning.\n");
            return 1;
        }
        ownProcess = false;
        printf("Scanning remote process PID %lu\n", targetPid);
    } else {
        printf("Scanning own process (PID %lu)\n", targetPid);
    }

    ScanProcess(hProc, targetPid);

    if (!ownProcess)
        CloseHandle(hProc);

    printf("\n=== Done ===\n");
    return 0;
}
