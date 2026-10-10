# Module 29 — Shellcode Development & BOF (Beacon Object Files)

## What shellcode is

Shellcode is position-independent machine code (PIC) that can be injected
anywhere in memory and executed without being loaded as a PE.

**Key constraint:** shellcode cannot use hardcoded addresses (the OS ASLR
randomizes them), can't use the import table (it hasn't been loaded by a PE
loader), and must resolve everything it needs at runtime.

**When you need it:**
- Injecting code into another process (write shellcode to remote heap, run it)
- Exploiting a buffer overflow (traditional use)
- BOF (Beacon Object File) — Cobalt Strike's way of running C code in-process
- Stageless payloads for red team tooling

---

## 2. Position-Independent Code Fundamentals

Three techniques to make code position-independent:

**A. Call + pop (x86):**
```asm
call next
next:
  pop eax     ; eax = address of "next" label
  ; now compute addresses as: eax + offset_from_next
```

**B. RIP-relative addressing (x64 — automatic in MASM/NASM):**
```asm
; Compiler generates this automatically for -fpic / /DYNAMIC_BASE
lea rax, [rip + my_string_offset]
```

**C. PEB walk (Windows-specific — resolve APIs at runtime):**
```cpp
// No imports needed — walk the PEB to find kernel32.dll base,
// then walk its export table to find LoadLibraryA, GetProcAddress
PPEB peb = (PPEB)__readgsqword(0x60);
PPEB_LDR_DATA ldr = peb->Ldr;
// walk InMemoryOrderModuleList...
```

---

## 3. PEB Walking (find kernel32 base at runtime)

```cpp
#include <windows.h>
#include <winternl.h>

HMODULE findKernel32() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;

    // InMemoryOrderModuleList: process, ntdll, kernel32 (usually 3rd)
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* cur  = head->Flink;

    while (cur != head) {
        auto* entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        WCHAR* name = entry->BaseDllName.Buffer;
        // Compare name to "KERNEL32.DLL" (case-insensitive)
        if (name && _wcsicmp(name, L"KERNEL32.DLL") == 0)
            return (HMODULE)entry->DllBase;
        cur = cur->Flink;
    }
    return nullptr;
}
```

---

## 4. Resolving Exports at Runtime (no GetProcAddress)

```cpp
FARPROC findExport(HMODULE base, const char* funcName) {
    PBYTE b = (PBYTE)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(b + ((PIMAGE_DOS_HEADER)b)->e_lfanew);
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(b + expRva);

    DWORD* names  = (DWORD*)(b + exp->AddressOfNames);
    WORD*  ords   = (WORD*)(b + exp->AddressOfNameOrdinals);
    DWORD* addrs  = (DWORD*)(b + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((char*)(b + names[i]), funcName) == 0) {
            return (FARPROC)(b + addrs[ords[i]]);
        }
    }
    return nullptr;
}
```

---

## 5. Writing a Hello World Shellcode in C

Compile to shellcode with MSVC or clang:

```cpp
// shellcode_hello.cpp — compile as /O2 /GS- /EHsc- /MT
// No CRT, no imports — resolve everything via PEB

typedef HANDLE  (WINAPI* pGetStdHandle)(DWORD);
typedef BOOL    (WINAPI* pWriteConsoleA)(HANDLE, const void*, DWORD, DWORD*, void*);

void shellcode_entry() {
    // 1. Find kernel32 via PEB walk
    HMODULE k32 = findKernel32();

    // 2. Resolve GetStdHandle + WriteConsoleA
    auto fnGetStdHandle  = (pGetStdHandle) findExport(k32, "GetStdHandle");
    auto fnWriteConsoleA = (pWriteConsoleA)findExport(k32, "WriteConsoleA");

    // 3. Call them
    HANDLE hOut = fnGetStdHandle((DWORD)-11); // STD_OUTPUT_HANDLE
    const char* msg = "Hello from shellcode!\n";
    DWORD written;
    fnWriteConsoleA(hOut, msg, 22, &written, nullptr);
}
```

---

## 6. Beacon Object Files (BOF)

A BOF is a COFF object file (.o) that Cobalt Strike's Beacon executes
in-process. No new process is spawned — the code runs inside the beacon.

```c
// Minimal BOF
#include <windows.h>
#include "beacon.h"   // provided by CS

// API calls use WINAPI macros that resolve at runtime
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);

void go(char* args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT, "BOF running in PID %d\n",
                 GetCurrentProcessId());
}
```

Compile:
```
x86_64-w64-mingw32-gcc -o hello.o -c hello.c -masm=intel
```

---

## 7. Shellcode to Executable (stager)

```cpp
// stager.cpp — allocates and runs shellcode bytes
unsigned char sc[] = { 0x48, 0x31, 0xC9, ... };  // your shellcode bytes

void runShellcode() {
    PVOID mem = VirtualAlloc(nullptr, sizeof(sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, sc, sizeof(sc));
    ((void(*)())mem)();
}
```

---

## Exercises

- `ex01_peb_walker.cpp` — find kernel32.dll base and resolve 3 functions without GetProcAddress
- `ex02_shellcode_runner.cpp` — allocate RWX memory, write shellcode, execute it
- `ex03_bof_skeleton.c` — minimal BOF that calls BeaconPrintf and lists processes
- `ex04_shellcode_encoder.cpp` — XOR-encode shellcode, write a decoder stub that decodes + executes
