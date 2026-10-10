# Module 05 — Processes and Threads

## 1. What is a Process?

A **process** is an isolated container that Windows creates when you run a
program. It has:
- Its own virtual address space (4GB on 32-bit, 128TB on 64-bit)
- One or more threads
- A handle table (list of open handles)
- A PEB (Process Environment Block) with environment variables, loaded modules

Processes are isolated: process A cannot read process B's memory directly
(unless A has a handle to B with appropriate access rights).

A **thread** is an execution context within a process. Every process starts
with one thread. You can create more. All threads in a process share the same
address space.

---

## 2. CreateProcess — Launching a Process

```cpp
#include <windows.h>

bool RunProcess(const char* exe, const char* args, bool hidden) {
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    if (hidden) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }

    PROCESS_INFORMATION pi = {};
    char cmdline[512];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", exe, args ? args : "");

    BOOL ok = CreateProcessA(
        nullptr,    // application name (null = parse from cmdline)
        cmdline,    // command line
        nullptr,    // process security attributes
        nullptr,    // thread security attributes
        FALSE,      // don't inherit handles
        0,          // creation flags (CREATE_NO_WINDOW, CREATE_SUSPENDED, etc.)
        nullptr,    // inherit environment
        nullptr,    // inherit working directory
        &si,        // startup info
        &pi         // receives process/thread handles and IDs
    );

    if (!ok) return false;

    // pi.hProcess = handle to new process
    // pi.hThread  = handle to new process's main thread
    // pi.dwProcessId = PID

    // Wait for it to finish (optional)
    // WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}
```

**Useful creation flags:**
- `CREATE_NO_WINDOW` — no console window
- `CREATE_SUSPENDED` — start paused (for injection — start, inject, resume)
- `DETACHED_PROCESS` — detach from parent's console
- `HIGH_PRIORITY_CLASS` — higher scheduling priority

---

## 3. OpenProcess — Getting a Handle to Another Process

```cpp
// Open with full access (requires admin for system processes)
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

// Open with just read access
HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, targetPid);

if (!h) {
    // GetLastError() == 5 → ERROR_ACCESS_DENIED (need elevation)
}

CloseHandle(h);
```

**Access rights matrix:**

| Purpose | Access right needed |
|---------|-------------------|
| Read process memory | `PROCESS_VM_READ` |
| Write process memory | `PROCESS_VM_WRITE` + `PROCESS_VM_OPERATION` |
| Create remote thread | `PROCESS_CREATE_THREAD` |
| Query info / path | `PROCESS_QUERY_INFORMATION` |
| Terminate | `PROCESS_TERMINATE` |
| All of the above | `PROCESS_ALL_ACCESS` |

---

## 4. Enumerating Processes (Toolhelp32)

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

void listProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            printf("PID: %6lu  Name: %s\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
}
```

**Also enumerate modules loaded in a process:**
```cpp
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
MODULEENTRY32 me = {};
me.dwSize = sizeof(me);
if (Module32First(hSnap, &me)) {
    do {
        printf("  Module: %s  Base: 0x%p\n", me.szModule, me.modBaseAddr);
    } while (Module32Next(hSnap, &me));
}
CloseHandle(hSnap);
```

---

## 5. Threads

**Creating a thread in your own process:**
```cpp
DWORD WINAPI MyThread(LPVOID param) {
    // param = whatever you passed as the 4th arg to CreateThread
    int* val = (int*)param;
    printf("Thread got: %d\n", *val);
    return 0;
}

int value = 42;
HANDLE hThread = CreateThread(
    nullptr,    // security attributes
    0,          // default stack size
    MyThread,   // thread function
    &value,     // parameter
    0,          // creation flags (0 = run immediately, CREATE_SUSPENDED = pause)
    nullptr     // receives thread ID (optional)
);

WaitForSingleObject(hThread, INFINITE);  // wait for it to finish
CloseHandle(hThread);
```

**With std::thread (C++11):**
```cpp
std::thread t([&value]() {
    printf("Thread got: %d\n", value);
});
t.join();
```

`CreateThread` is the Win32 way. `std::thread` wraps it. Use `std::thread`
for your own code, `CreateThread` when you need to pass a function to Win32
APIs that expect a `LPTHREAD_START_ROUTINE`.

---

## 6. Remote Thread Injection (Classic DLL Injection)

This is **the** fundamental code injection technique. Understanding it is
essential for both red team and blue team.

```
Steps:
1. OpenProcess(PROCESS_ALL_ACCESS, target_pid)
2. VirtualAllocEx(hProcess, ...) — allocate memory IN the target process
3. WriteProcessMemory(hProcess, allocated_addr, dll_path, len, ...) — write DLL path there
4. Get address of LoadLibraryA from kernel32.dll (same address in all processes)
5. CreateRemoteThread(hProcess, ..., LoadLibraryA, dll_path_addr, ...) — run LoadLibrary in target
→ target process loads your DLL
```

```cpp
void injectDll(DWORD pid, const char* dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;

    size_t pathLen = strlen(dllPath) + 1;

    // Allocate memory in target process
    LPVOID remote = VirtualAllocEx(hProc, nullptr, pathLen,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Write DLL path into target
    WriteProcessMemory(hProc, remote, dllPath, pathLen, nullptr);

    // Get LoadLibraryA address (same in all processes due to how Windows loads kernel32)
    LPTHREAD_START_ROUTINE loadLib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // Execute LoadLibraryA in target, passing our DLL path
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, loadLib, remote, 0, nullptr);
    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
}
```

**Why AV flags this:** `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
appearing together in the import table is the "injection triad" — a classic
detection signature.

**Blue team defence:** EDRs hook `NtCreateThreadEx` in ntdll to intercept
remote thread creation. Tools like Windows Defender ATP alert on this in real time.

---

## 7. Synchronization Objects

When multiple threads access shared data, you need synchronization.

**CRITICAL_SECTION (fastest, same process only):**
```cpp
CRITICAL_SECTION cs;
InitializeCriticalSection(&cs);

// Thread 1:
EnterCriticalSection(&cs);
sharedData += "key";
LeaveCriticalSection(&cs);

DeleteCriticalSection(&cs);  // cleanup
```

**MUTEX (cross-process, e.g. single-instance check):**
```cpp
// Create or open a named mutex
HANDLE hMutex = CreateMutexA(nullptr, FALSE, "Global\\MyRATInstance");
if (GetLastError() == ERROR_ALREADY_EXISTS) {
    // Another instance is already running
    CloseHandle(hMutex);
    ExitProcess(0);
}
// We are the first instance
```

Single-instance check via named mutex is how a RAT avoids running twice:
if the mutex already exists, a second copy silently exits.

---

## Exercises

- `ex01_create_process.cpp` — spawn cmd.exe hidden, capture its output
- `ex02_enumerate_processes.cpp` — list processes, find a target by name
- `ex03_threads_sync.cpp` — producer/consumer using CRITICAL_SECTION
- `ex04_single_instance.cpp` — single-instance check via named mutex
