/*
  Exercise 01 — PEB Walker (No GetProcAddress)
  ---------------------------------------------
  Resolve Windows API functions at runtime without using GetProcAddress.
  This is the foundation of shellcode: we can't rely on the PE import table,
  so we must find everything ourselves.

  Strategy:
    1. Read the PEB (Process Environment Block) via gs:[0x60] (x64).
    2. Walk PEB.Ldr.InMemoryOrderModuleList to find kernel32.dll.
    3. Walk kernel32's export table to find GetStdHandle, WriteConsoleA,
       VirtualAlloc, etc.
    4. Call them without ever using GetProcAddress or LoadLibrary.

  Tasks:
  1. Implement findModuleBase(name) — return the base address of a loaded
     DLL by walking PEB.Ldr.InMemoryOrderModuleList.
  2. Implement findExport(base, funcName) — walk the PE export directory
     of the given module to find the function address.
  3. Implement findExportByHash(base, hash) — for stealth, compare a
     hash of each export name instead of the plain string.
     Use DJB2: hash = hash * 33 + c for each char (tolower).
  4. Use your functions to resolve and call:
       GetStdHandle  → STD_OUTPUT_HANDLE
       WriteConsoleA → print "PEB walk success!"
       GetProcessId  → print current PID

  BONUS:
  - Implement a case-insensitive unicode module name comparison (the
    module name in PEB is wide-char, uppercase-normalized on some Windows versions).
  - Write the entire exercise as a self-contained function with no global state,
    suitable for embedding in an allocated buffer as shellcode.

  Compile:
    cl /std:c++17 /GS- /O2 ex01_peb_walker.cpp /link /OUT:ex01.exe
  Compile with ASLR (verify PEB walk still works):
    cl /std:c++17 /GS- /O2 /DYNAMICBASE ex01_peb_walker.cpp /link /OUT:ex01.exe
*/

#include <windows.h>
#include <winternl.h>
#include <cstdio>

// Typedefs for the functions we'll resolve
typedef HANDLE (WINAPI* pGetStdHandle)(DWORD);
typedef BOOL   (WINAPI* pWriteConsoleA)(HANDLE, const void*, DWORD, DWORD*, void*);
typedef DWORD  (WINAPI* pGetCurrentProcessId)(void);

// DJB2 hash for export name matching (avoids plain string comparison in shellcode)
DWORD djb2(const char* s) {
    DWORD h = 5381;
    while (*s) h = h * 33 + (unsigned char)tolower(*s++);
    return h;
}

static const DWORD HASH_GetStdHandle         = 0; // TODO: compute and fill in
static const DWORD HASH_WriteConsoleA        = 0;
static const DWORD HASH_GetCurrentProcessId  = 0;

// ---------- TODO 1: findModuleBase ----------
HMODULE findModuleBase(const wchar_t* moduleName) {
    // YOUR CODE HERE:
    // PPEB peb = (PPEB)__readgsqword(0x60);
    // PPEB_LDR_DATA ldr = peb->Ldr;
    // Walk InMemoryOrderModuleList:
    //   LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    //   LIST_ENTRY* cur  = head->Flink;
    //   while (cur != head) {
    //       LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY,
    //                                                         InMemoryOrderLinks);
    //       if (entry->BaseDllName.Buffer &&
    //           _wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0)
    //           return (HMODULE)entry->DllBase;
    //       cur = cur->Flink;
    //   }
    (void)moduleName;
    return nullptr;
}

// ---------- TODO 2: findExport ----------
FARPROC findExport(HMODULE base, const char* funcName) {
    // YOUR CODE HERE (see theory.md section 4)
    (void)base; (void)funcName;
    return nullptr;
}

// ---------- TODO 3: findExportByHash ----------
FARPROC findExportByHash(HMODULE base, DWORD targetHash) {
    // YOUR CODE HERE: same as findExport but compare djb2(name) == targetHash
    (void)base; (void)targetHash;
    return nullptr;
}

int main() {
    printf("[*] Testing PEB walk...\n");
    printf("[*] Our GetProcAddress baseline:\n");
    HMODULE k32_real = GetModuleHandleA("kernel32.dll");
    printf("    GetModuleHandle(kernel32) = %p\n", (void*)k32_real);

    HMODULE k32 = findModuleBase(L"KERNEL32.DLL");
    if (!k32) {
        printf("[-] findModuleBase not implemented\n"); return 1;
    }
    printf("[+] Found kernel32 @ %p  (match: %s)\n",
           (void*)k32, k32 == k32_real ? "YES" : "NO");

    auto fnGetStdHandle = (pGetStdHandle)findExport(k32, "GetStdHandle");
    if (!fnGetStdHandle) {
        printf("[-] findExport not implemented\n"); return 1;
    }
    printf("[+] GetStdHandle @ %p  (real: %p)\n",
           (void*)fnGetStdHandle,
           (void*)GetProcAddress(k32_real, "GetStdHandle"));

    auto fnWriteConsole = (pWriteConsoleA)findExport(k32, "WriteConsoleA");
    auto fnGetPid       = (pGetCurrentProcessId)findExport(k32, "GetCurrentProcessId");

    if (fnWriteConsole && fnGetStdHandle) {
        HANDLE hOut = fnGetStdHandle((DWORD)-11);
        const char* msg = "PEB walk success! No GetProcAddress used.\r\n";
        DWORD written = 0;
        fnWriteConsole(hOut, msg, (DWORD)strlen(msg), &written, nullptr);
    }
    if (fnGetPid) printf("[+] PID via resolved func: %lu\n", fnGetPid());

    // Hash-based test
    printf("\n[*] Testing hash-based resolution...\n");
    // TODO: compute HASH_GetStdHandle = djb2("getstdhandle") and set the const above
    // Then: auto fn = findExportByHash(k32, HASH_GetStdHandle);

    return 0;
}
