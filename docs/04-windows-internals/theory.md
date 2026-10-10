# Module 04 — Windows Internals

## 1. The Windows API (Win32 API)

Everything a program does on Windows that involves the OS goes through the
**Win32 API** — a set of C functions in system DLLs.

Key DLLs and what they contain:

| DLL | What it provides |
|-----|-----------------|
| `kernel32.dll` | Processes, threads, memory, file I/O, synchronization |
| `advapi32.dll` | Registry, services, security tokens, cryptography |
| `user32.dll` | Windows, messages, input, GUI |
| `ntdll.dll` | Native API — lowest level before the kernel. Most Win32 calls eventually call into ntdll. |
| `wininet.dll` | HTTP/HTTPS client (InternetOpen, HttpSendRequest) |
| `ws2_32.dll` | Winsock sockets |

**Calling convention:** Win32 functions use `__stdcall` (also written `WINAPI`).
On x64 Windows this is the same as the default calling convention, so you
rarely need to specify it explicitly with MinGW.

---

## 2. HANDLE — The Universal Object Reference

A `HANDLE` is an opaque 64-bit value (pointer-sized) that identifies a kernel
object: a process, thread, file, registry key, event, mutex, etc.

```cpp
HANDLE hFile = CreateFileA("log.txt", GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
if (hFile == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    // err tells you what went wrong
}

// Use the handle
DWORD written;
WriteFile(hFile, "hello", 5, &written, nullptr);

// Always close when done — leaking handles wastes kernel resources
CloseHandle(hFile);
hFile = nullptr;
```

**INVALID_HANDLE_VALUE** vs **NULL:**
- File functions: failure = `INVALID_HANDLE_VALUE`
- Process/thread functions: failure = `NULL`
- Always check the docs for which a given function returns.

---

## 3. GetLastError() — Error Handling

Win32 functions signal failure by returning `FALSE`, `NULL`, or
`INVALID_HANDLE_VALUE`. The actual error code is stored per-thread and
retrieved with `GetLastError()`.

```cpp
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);
if (!h) {
    DWORD err = GetLastError();
    // Common error codes:
    // 5   = ERROR_ACCESS_DENIED
    // 87  = ERROR_INVALID_PARAMETER
    // 6   = ERROR_INVALID_HANDLE
    // 2   = ERROR_FILE_NOT_FOUND
    // 740 = ERROR_ELEVATION_REQUIRED
    printf("OpenProcess failed: %lu\n", err);
}
```

**`FormatMessageA`** converts an error code to a human-readable string:

```cpp
char msg[256];
FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, GetLastError(),
               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
               msg, sizeof(msg), nullptr);
printf("Error: %s\n", msg);
```

---

## 4. The Registry

The registry is a hierarchical key-value database. Every RAT uses it for
persistence. The most important key is:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

Any value under this key runs when the current user logs in. No admin
required.

```cpp
#include <windows.h>

// Write a persistence key
void SetRunKey(const char* name, const char* exePath) {
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);

    RegSetValueExA(hKey, name, 0, REG_SZ,
                   (const BYTE*)exePath, (DWORD)strlen(exePath) + 1);

    RegCloseKey(hKey);
}

// Delete it (cleanup / uninstall)
void DeleteRunKey(const char* name) {
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);
    RegDeleteValueA(hKey, name);
    RegCloseKey(hKey);
}

// Check if it exists
bool RunKeyExists(const char* name) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD type, size = 0;
    bool exists = RegQueryValueExA(hKey, name, nullptr, &type, nullptr, &size) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return exists;
}
```

**Other persistence locations (all HKCU, no admin needed):**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
Startup folder: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

---

## 5. The PE File Format

Every `.exe` and `.dll` is a PE (Portable Executable) file. Understanding
its structure is essential for AV evasion and malware analysis.

```
PE File Layout:
┌─────────────────────┐
│  DOS Header         │  64 bytes — starts with "MZ" (0x4D 0x5A)
│  e_lfanew: offset   │  → offset to PE header
├─────────────────────┤
│  DOS Stub           │  "This program cannot be run in DOS mode"
├─────────────────────┤
│  PE Signature       │  "PE\0\0" (0x50 0x45 0x00 0x00)
├─────────────────────┤
│  File Header        │  Machine type, section count, timestamp
│  (IMAGE_FILE_HEADER)│
├─────────────────────┤
│  Optional Header    │  Subsystem (GUI vs Console), entry point,
│(IMAGE_OPTIONAL_HEADER) image base, section alignment
├─────────────────────┤
│  Section Table      │  Array of section descriptors
│  .text .rdata .data │  (name, virtual address, raw offset, size)
│  .rsrc .idata ...   │
├─────────────────────┤
│  Section Data       │
│  .text  — code      │
│  .rdata — read-only │
│  .data  — globals   │
│  .idata — imports   │  ← AV reads this for API names
│  .rsrc  — resources │
└─────────────────────┘
```

**Key fields in the Optional Header:**

| Field | Meaning |
|-------|---------|
| `Subsystem` | 2 = GUI (no console), 3 = Console |
| `AddressOfEntryPoint` | RVA of the first instruction executed |
| `ImageBase` | Preferred load address (typically 0x140000000 on x64) |
| `SizeOfImage` | Total virtual size when loaded |

**Reading a PE header in C++:**

```cpp
#include <windows.h>
#include <fstream>

int main() {
    std::ifstream f("Stub.exe", std::ios::binary);
    std::vector<char> data((std::istreambuf_iterator<char>(f)), {});

    // DOS header starts at offset 0
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data.data();
    // dos->e_magic should be 0x5A4D ('MZ')
    // dos->e_lfanew = offset to PE header

    // PE header
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data.data() + dos->e_lfanew);
    // nt->Signature should be 0x00004550 ('PE\0\0')
    // nt->FileHeader.NumberOfSections
    // nt->OptionalHeader.Subsystem (2 = GUI, 3 = console)
    // nt->OptionalHeader.AddressOfEntryPoint

    printf("Subsystem: %d\n", nt->OptionalHeader.Subsystem);
    printf("Entry point RVA: 0x%X\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("Sections: %d\n", nt->FileHeader.NumberOfSections);
}
```

---

## 6. Import Table — How DLL Calls Work

When Windows loads a PE, it looks at the import table and:
1. Loads each required DLL into the process's address space
2. Resolves each function address
3. Writes the address into the **Import Address Table (IAT)**

Your call to `CreateProcessA` in C++ compiles to:
```
call [IAT + offset_of_CreateProcessA]
```
Which at runtime resolves to the actual `CreateProcessA` in `kernel32.dll`.

**AV implication:** every function in the import table is visible to static
analysis before the binary runs. If `VirtualAllocEx`, `WriteProcessMemory`,
and `CreateRemoteThread` all appear together → flagged.

**Resolution:** don't import them statically. Resolve at runtime:
```cpp
auto fn = (LPVOID(WINAPI*)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD))
          GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx");
```

---

## 7. WinMain — The Silent Entry Point

Console programs use `main()`. GUI programs use `WinMain()`:

```cpp
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nShowCmd) {
    // No console window — runs completely silently
    MessageBoxA(nullptr, "Hello from a silent EXE", "Test", MB_OK);
    return 0;
}
```

Compiled with `-mwindows`: no console ever opens.
The process appears in Task Manager but shows no window.

---

## Exercises

- `ex01_handles_winapi.cpp` — file read/write via Win32 (CreateFile, ReadFile, WriteFile)
- `ex02_registry.cpp` — read, write, delete registry keys
- `ex03_pe_parser.cpp` — parse PE header, print section names and subsystem
- `ex04_error_handling.cpp` — GetLastError + FormatMessage wrapper

All exercises require Windows to compile. Compile with:
```
g++ -std=c++17 -Wall -mwindows -o out.exe exercise.cpp -ladvapi32 -lkernel32
```
