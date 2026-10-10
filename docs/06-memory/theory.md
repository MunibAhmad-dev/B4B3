# Module 06 — Memory Management

## 1. Windows Virtual Memory

Every process on Windows has its own **virtual address space**. On 64-bit
Windows this is 0x0000000000000000 to 0x00007FFFFFFFFFFF for user space.

The OS uses a **page table** to map virtual addresses to physical RAM pages.
Each page is 4096 bytes (0x1000). A page can be:
- Committed — backed by RAM or pagefile, accessible
- Reserved — range claimed but no RAM allocated
- Free — not used

**Memory types:**
- `MEM_COMMIT`  — allocate RAM for the pages
- `MEM_RESERVE` — reserve address range (no RAM yet)
- `MEM_RELEASE` — free both reservation and commitment

**Protection flags:**
- `PAGE_READWRITE`         — normal data (read + write)
- `PAGE_EXECUTE_READ`      — code (execute + read)
- `PAGE_EXECUTE_READWRITE` — code + data (RWX — AV flags this)
- `PAGE_NOACCESS`          — trap any access

---

## 2. VirtualAlloc — Manual Memory Allocation

`VirtualAlloc` gives you direct control over pages, bypassing the heap.
This is what you use for shellcode buffers, encryption buffers, or any
allocation you want to control precisely.

```cpp
// Allocate 4096 bytes (one page), readable + writable
LPVOID mem = VirtualAlloc(
    nullptr,              // let OS choose address
    4096,                 // size in bytes (rounds up to page boundary)
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

if (!mem) {
    // GetLastError() for reason
    return;
}

// Use it
memset(mem, 0x90, 4096);  // fill with NOP instructions
char* ptr = (char*)mem;
ptr[0] = 0x48; ptr[1] = 0x31; ptr[2] = 0xC0;  // xor rax, rax

// Change protection to execute (after writing code)
DWORD oldProtect;
VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &oldProtect);

// Free when done
VirtualFree(mem, 0, MEM_RELEASE);
```

---

## 3. VirtualAllocEx — Allocate in Another Process

Used in process injection:

```cpp
HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);

LPVOID remote = VirtualAllocEx(
    hProc,
    nullptr,
    shellcodeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE   // RWX — AV red flag
);

WriteProcessMemory(hProc, remote, shellcode, shellcodeSize, nullptr);
```

**Improving evasion:** avoid `PAGE_EXECUTE_READWRITE`. Instead:
1. Allocate `PAGE_READWRITE`
2. Write the shellcode
3. Call `VirtualProtectEx` to change to `PAGE_EXECUTE_READ`

This splits the RW and RX phases, which is less suspicious to some EDRs.

---

## 4. HeapAlloc vs VirtualAlloc vs new

| Method | When to use |
|--------|-------------|
| `new` / `delete` | Normal objects, small allocations |
| `HeapAlloc` | Large buffers when you want Win32-level heap (interops with LocalFree etc.) |
| `VirtualAlloc` | Precise page-level control, shellcode buffers, RWX regions |
| `VirtualAllocEx` | Allocating in another process |

```cpp
// HeapAlloc — Win32 heap
HANDLE hHeap = GetProcessHeap();
BYTE* buf = (BYTE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 1024);
HeapFree(hHeap, 0, buf);
```

---

## 5. Memory Scanning — How AV Scans Your Process

When an AV engine scans a live process, it:
1. Opens the process with `PROCESS_VM_READ`
2. Calls `VirtualQueryEx` to enumerate all memory regions
3. For each committed, readable region: reads the bytes and scans for signatures

```cpp
// Enumerate memory regions in a process
MEMORY_BASIC_INFORMATION mbi = {};
LPVOID addr = nullptr;

while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READABLE)) {
        // Read and scan this region
        std::vector<BYTE> buf(mbi.RegionSize);
        SIZE_T read;
        ReadProcessMemory(hProcess, addr, buf.data(), mbi.RegionSize, &read);
        // ... scan buf for signatures
    }
    addr = (LPVOID)((ULONG_PTR)addr + mbi.RegionSize);
}
```

**Implication for evasion:**
- Encrypted payload decrypted at runtime into memory is visible to a live scan.
- Sleeping and decrypting only when needed reduces the window of exposure.
- Some advanced techniques overwrite the decrypted copy back to ciphertext after
  execution, but this is complex.

---

## 6. Stack vs Heap — Buffer Overflows (Conceptual)

```cpp
void vulnerable(const char* input) {
    char buf[64];    // 64 bytes on the stack
    strcpy(buf, input);  // no length check — copies until \0
    // If input is longer than 64 bytes, it overwrites:
    //   saved RBP (frame pointer)
    //   return address  ← attacker controls where this function returns
}
```

This is a **stack buffer overflow**. The return address is overwritten with
an attacker-controlled value, redirecting execution.

Modern mitigations:
- **ASLR** (Address Space Layout Randomization) — base addresses are random
- **Stack canaries** (`/GS` in MSVC, `-fstack-protector` in GCC) — detect overwrite
- **DEP/NX** (Data Execution Prevention) — stack memory not executable
- **CFG** (Control Flow Guard) — restricts valid call targets

Understanding these mitigations is why modern exploits need multiple bypass
techniques, not just a single overflow.

---

## 7. PEB Walking — Finding APIs Without GetProcAddress

The PEB (Process Environment Block) is reachable via the GS register on x64:

```
GS:[0x60] = PEB*
PEB.Ldr   = PEB_LDR_DATA*
PEB_LDR_DATA.InMemoryOrderModuleList = doubly-linked list of loaded modules
```

Each module entry has the DLL base address and export directory. By walking
the export directory you can find any exported function by hash (rather than
name), removing all API string references from your binary.

```
Module entry → DLL base
DLL base + e_lfanew → IMAGE_NT_HEADERS
OptionalHeader.DataDirectory[0] → IMAGE_EXPORT_DIRECTORY
ExportDir.AddressOfNames[] → function name strings
ExportDir.AddressOfFunctions[] → function RVAs
```

This technique (often called "shellcode API resolution") is used in advanced
implants to avoid any strings in the import table.

---

## Exercises

- `ex01_virtual_alloc.cpp` — allocate, write, read, free pages
- `ex02_memory_scan.cpp` — enumerate your own process's memory regions
- `ex03_heap_operations.cpp` — HeapAlloc/HeapFree, compare with new
