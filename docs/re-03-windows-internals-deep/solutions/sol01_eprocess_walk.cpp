// sol01_eprocess_walk.cpp — solution for ex01
// Compile: g++ -std=c++17 -o sol01.exe sol01_eprocess_walk.cpp

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <vector>
#include <string>

typedef NTSTATUS (WINAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

int main() {
    auto NtQSI = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");

    ULONG sz = 0x10000;
    std::vector<BYTE> buf;
    NTSTATUS st;
    do {
        buf.resize(sz);
        st = NtQSI(5 /*SystemProcessInformation*/, buf.data(), sz, &sz);
        sz *= 2;
    } while (st == (NTSTATUS)0xC0000004L); // STATUS_INFO_LENGTH_MISMATCH

    if (st != 0) { fprintf(stderr, "NtQSI failed: 0x%08X\n", st); return 1; }

    printf("%-8s  %-8s  %-4s  %-7s  %s\n","PID","PPID","SESS","THREADS","Name");
    printf("%s\n", std::string(60,'-').c_str());

    auto* p = (SYSTEM_PROCESS_INFORMATION*)buf.data();
    while (true) {
        char name[256] = "<System>";
        if (p->ImageName.Buffer && p->ImageName.Length > 0)
            WideCharToMultiByte(CP_ACP,0,p->ImageName.Buffer,p->ImageName.Length/2,
                                name,sizeof(name),nullptr,nullptr);

        printf("%-8llu  %-8llu  %-4u  %-7u  %s\n",
               (unsigned long long)(uintptr_t)p->UniqueProcessId,
               (unsigned long long)(uintptr_t)p->InheritedFromUniqueProcessId,
               p->SessionId,
               p->NumberOfThreads,
               name);

        if (!p->NextEntryOffset) break;
        p = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
    }
    return 0;
}
