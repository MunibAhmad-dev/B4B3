# Module 23 — Memory Forensics

## Why memory forensics

Malware lives in memory. Modern fileless malware:
- Never writes a file to disk
- Runs as shellcode in a legitimate process's memory
- Patches legitimate DLLs in memory
- Hides from the process list (DKOM)

Memory forensics lets you find it.

Tools like **Volatility** (Python) and **Rekall** do this from memory dumps.
This module builds the same capabilities in C++ so you understand every layer.

---

## 1. Process Memory Layout

Every process on x64 Windows has a private 128TB virtual address space.
The memory manager tracks regions using:
- **PTE (Page Table Entry)** — hardware mapping of virtual → physical
- **VAD (Virtual Address Descriptor)** — kernel tree of committed/reserved regions
- **EPROCESS** — kernel struct representing the process

```
Virtual address space for a typical process:
  0x00000000`00010000 → executable image (ntdll, kernel32, your code)
  0x00007FFF`FFFFFFFF → top of user-mode space
  0xFFFF8000`00000000 → kernel space (user mode can't read this)

Inside a process at runtime:
  .text section of EXE     → RX (read, execute)
  .rdata section           → R (read only)
  .data section            → RW (read, write)
  Stack(s)                 → RW + GUARD pages
  Heap(s)                  → RW, private
  Loaded DLL mappings      → MEM_MAPPED
  Injected shellcode       → Often MEM_PRIVATE + RWX (very suspicious)
```

---

## 2. Enumerating Memory Regions (VirtualQueryEx)

```cpp
#include <windows.h>
#include <psapi.h>
#include <iostream>

struct MemRegion {
    PVOID  base;
    SIZE_T size;
    DWORD  protect;   // PAGE_*
    DWORD  type;      // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
    DWORD  state;     // MEM_COMMIT, MEM_RESERVE, MEM_FREE
};

std::vector<MemRegion> enumMemory(HANDLE hProcess) {
    std::vector<MemRegion> regions;
    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID addr = nullptr;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            regions.push_back({mbi.BaseAddress, mbi.RegionSize,
                               mbi.Protect, mbi.Type, mbi.State});
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (addr >= (PVOID)0x7FFFFFFFFFFF) break;  // end of user space
    }
    return regions;
}

// Find suspicious regions: private, executable memory that is NOT an image
// (i.e. not part of a known loaded DLL/EXE — could be injected shellcode)
void findSuspiciousRegions(HANDLE hProcess) {
    for (const auto& r : enumMemory(hProcess)) {
        bool executable = (r.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        bool isPrivate   = (r.type == MEM_PRIVATE);
        bool notImage    = (r.type != MEM_IMAGE);

        if (executable && isPrivate && notImage) {
            printf("SUSPICIOUS: Base=%p  Size=0x%llX  Protect=0x%X\n",
                   r.base, (ULONGLONG)r.size, r.protect);
        }
    }
}
```

---

## 3. Dumping a Process (MiniDump)

`MiniDumpWriteDump` creates a `.dmp` file with process memory, thread stacks,
and module list. Used by crash reporters AND by security analysts.

```cpp
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

bool dumpProcess(DWORD pid, const char* outPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProcess); return false; }

    BOOL ok = MiniDumpWriteDump(
        hProcess,
        pid,
        hFile,
        (MINIDUMP_TYPE)(MiniDumpWithFullMemory |
                         MiniDumpWithHandleData |
                         MiniDumpWithThreadInfo),
        nullptr, nullptr, nullptr
    );

    CloseHandle(hFile);
    CloseHandle(hProcess);
    return ok != FALSE;
}
```

---

## 4. Scanning Process Memory for Patterns

Search the entire address space of a process for a byte pattern.
Used to find: shellcode signatures, credential strings, encryption keys.

```cpp
std::vector<PVOID> scanMemory(HANDLE hProcess, const BYTE* pattern, size_t patLen) {
    std::vector<PVOID> hits;
    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID addr = nullptr;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE)) != PAGE_NOACCESS) {

            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T read = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(), buf.size(), &read)) {
                for (SIZE_T i = 0; i + patLen <= read; i++) {
                    if (memcmp(buf.data() + i, pattern, patLen) == 0) {
                        hits.push_back((PBYTE)mbi.BaseAddress + i);
                    }
                }
            }
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (addr >= (PVOID)0x7FFFFFFFFFFF) break;
    }
    return hits;
}
```

---

## 5. Module List Discrepancy Detection (DKOM-hidden process detection)

If a process has been DKOM-hidden (removed from ActiveProcessLinks),
it no longer appears in `CreateToolhelp32Snapshot`. But it still:
- Has handles in the handle table
- Has an active VAD tree in kernel
- Can be found by scanning the PFN database (physical pages) — kernel-only

**User-mode partial detection:** compare two different process enumeration methods:
1. `CreateToolhelp32Snapshot` (walks ActiveProcessLinks — can be fooled by DKOM)
2. `NtQuerySystemInformation(SystemProcessInformation)` (similar, also foolable)
3. Scanning CSR (Client/Server Runtime) process list — harder to fake
4. Handle-based enumeration — open handles 0x4 to max, NtQueryObject each handle

```cpp
// Find processes that NtQuerySystemInformation sees but Toolhelp32 doesn't
void findHiddenProcesses() {
    // Method A: Toolhelp32
    std::set<DWORD> toolhelpPids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) do {
        toolhelpPids.insert(pe.th32ProcessID);
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);

    // Method B: open handle ranges (brute force valid PIDs)
    for (DWORD pid = 4; pid <= 65536; pid += 4) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {
            if (toolhelpPids.find(pid) == toolhelpPids.end())
                printf("[HIDDEN PROCESS?] PID=%lu not in Toolhelp32 snapshot\n", pid);
            CloseHandle(h);
        }
    }
}
```

---

## 6. Analysing a Live Memory Dump with WinDbg

```
Open WinDbg → File → Open Crash Dump → select .dmp

Useful commands:
  !analyze -v          → automatic analysis
  !process 0 0         → list all processes
  !process 0 7         → list processes with threads
  .process /r /p <eprocess addr>  → switch to a process context
  !dml_proc            → clickable process list
  dd <addr>            → dump DWORDs at address
  dt ntdll!_PEB <addr> → decode PEB structure
  !vad                 → print VAD tree for current process
  !address             → memory regions for current process
  s -b <start> <end> <pattern>  → search bytes in range
```

---

## Exercises

- `ex01_memory_scanner.cpp` — enumerate all regions of a target PID, find private RWX
- `ex02_string_hunter.cpp` — scan a process's memory for a given string pattern
- `ex03_mini_dumper.cpp` — dump LSASS (or any PID) to a .dmp file
- `ex04_hidden_process_detect.cpp` — compare enumeration methods, flag discrepancies
