// sol02_peb_flags.cpp — solution for ex02
// Compile: g++ -std=c++17 -o sol02.exe sol02_peb_flags.cpp

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

typedef struct _UNICODE_STRING2 { USHORT Len, Max; PWSTR Buf; } USTR2;
typedef struct _LDR_ENTRY {
    LIST_ENTRY Load, Mem, Init;
    PVOID Base; PVOID EP; ULONG Size;
    USTR2 Full, Base2;
} LDR_ENTRY;

int main() {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    printf("PEB @ 0x%p\n", peb);
    printf("  BeingDebugged:  %d\n", peb->BeingDebugged);

    // NtGlobalFlag: offset 0xBC on x64
#ifdef _WIN64
    DWORD ntgf = *(DWORD*)((BYTE*)peb + 0xBC);
#else
    DWORD ntgf = *(DWORD*)((BYTE*)peb + 0x68);
#endif
    printf("  NtGlobalFlag:   0x%08X%s\n", ntgf,
           ntgf & 0x70 ? "  <-- debugger!" : "");

    printf("  ImageBase:      0x%p\n", peb->Reserved3[1]);

    printf("\nLoaded modules:\n");
    auto* ldr  = peb->Ldr;
    auto* head = &ldr->InMemoryOrderModuleList;
    auto* cur  = head->Flink;
    while (cur != head) {
        auto* entry = (LDR_ENTRY*)CONTAINING_RECORD(cur, LDR_ENTRY, Mem);
        if (entry->Full.Buf) {
            char path[512]{};
            WideCharToMultiByte(CP_ACP,0,entry->Full.Buf,entry->Full.Len/2,
                                path,sizeof(path),nullptr,nullptr);
            printf("  0x%p  %s\n", entry->Base, path);
        }
        cur = cur->Flink;
    }

    printf("\nPatching BeingDebugged...\n");
    peb->BeingDebugged = 0;
    printf("  IsDebuggerPresent() now returns: %d\n", IsDebuggerPresent());
    return 0;
}
