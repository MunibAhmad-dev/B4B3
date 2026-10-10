/*
  Solution 01 — Detect Inline Hooks (complete)
*/
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

bool isHooked(PVOID funcPtr) {
    PBYTE b = (PBYTE)funcPtr;
    return (b[0] == 0xE9)                          // relative JMP
        || (b[0] == 0xFF && b[1] == 0x25)          // absolute indirect JMP
        || (b[0] == 0xE8);                          // CALL
}

PVOID getHookTarget(PVOID funcPtr) {
    PBYTE b = (PBYTE)funcPtr;
    if (b[0] == 0xE9) {
        INT32 rel = *(INT32*)(b + 1);
        return (PVOID)(b + 5 + rel);
    }
    if (b[0] == 0xFF && b[1] == 0x25) {
        DWORD rel = *(DWORD*)(b + 2);
        PBYTE abs = b + 6 + rel;
        return *(PVOID*)abs;
    }
    return nullptr;
}

void checkNtdllFunction(const char* funcName) {
    PVOID addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName);
    if (!addr) {
        printf("%-35s NOT FOUND\n", funcName);
        return;
    }
    PBYTE b = (PBYTE)addr;
    printf("%-35s ", funcName);
    for (int i = 0; i < 8; i++) printf("%02X ", b[i]);
    if (isHooked(addr)) {
        PVOID target = getHookTarget(addr);
        printf(" HOOKED → %p\n", target);
    } else {
        printf(" CLEAN\n");
    }
}

void compareWithDisk() {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { printf("[-] Can't open ntdll from disk\n"); return; }

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    LPVOID clean = hMap ? MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0) : nullptr;
    CloseHandle(hMap); CloseHandle(hFile);
    if (!clean) { printf("[-] Can't map ntdll from disk\n"); return; }

    HMODULE live = GetModuleHandleA("ntdll.dll");
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)clean;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((PBYTE)clean + dos->e_lfanew);
    IMAGE_SECTION_HEADER* secs = IMAGE_FIRST_SECTION(nt);

    int diffs = 0;
    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++) {
        if (memcmp(secs[s].Name, ".text", 5) != 0) continue;
        PBYTE diskText = (PBYTE)clean + secs[s].VirtualAddress;
        PBYTE liveText = (PBYTE)live  + secs[s].VirtualAddress;
        DWORD sz       = secs[s].Misc.VirtualSize;
        for (DWORD i = 0; i < sz; i++) {
            if (diskText[i] != liveText[i]) {
                if (diffs < 20)
                    printf("  Offset +0x%05X: disk=%02X live=%02X\n",
                           secs[s].VirtualAddress + i, diskText[i], liveText[i]);
                diffs++;
            }
        }
        break;
    }

    if (diffs == 0) printf("[*] .text section matches disk — no patches detected\n");
    else            printf("[!] %d byte(s) differ in .text\n", diffs);

    UnmapViewOfFile(clean);
}

int main() {
    printf("=== NTDLL Hook Detector ===\n\n");

    const char* funcs[] = {
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx",
        "NtOpenProcess", "NtReadVirtualMemory", "NtQueueApcThread",
        "NtProtectVirtualMemory", "NtMapViewOfSection", "NtUnmapViewOfSection", nullptr
    };

    printf("%-35s %-25s %s\n", "Function", "First 8 bytes", "Status");
    printf("%s\n", std::string(75, '-').c_str());
    for (int i = 0; funcs[i]; i++) checkNtdllFunction(funcs[i]);

    printf("\n--- Disk Comparison ---\n");
    compareWithDisk();
    return 0;
}
