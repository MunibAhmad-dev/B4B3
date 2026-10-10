// winternals_inspector.cpp — Windows internals inspection tool
// Compile: g++ -std=c++17 -o winternals_inspector.exe winternals_inspector.cpp
// Usage: winternals_inspector.exe processes | peb <pid> | handles <pid> | modules <pid> | teb

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>

typedef NTSTATUS (WINAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static NtQSI_t NtQSI = nullptr;
static NtQIP_t NtQIP = nullptr;

static void init_nt() {
    HMODULE nt = GetModuleHandleA("ntdll");
    NtQSI = (NtQSI_t)GetProcAddress(nt, "NtQuerySystemInformation");
    NtQIP = (NtQIP_t)GetProcAddress(nt, "NtQueryInformationProcess");
}

static std::vector<BYTE> qsi(ULONG cls) {
    ULONG sz = 0x20000;
    std::vector<BYTE> buf;
    NTSTATUS st;
    do {
        buf.resize(sz);
        st = NtQSI(cls, buf.data(), sz, &sz);
        sz *= 2;
    } while (st == (NTSTATUS)0xC0000004L);
    if (st != 0) buf.clear();
    return buf;
}

// ─── processes ────────────────────────────────────────────────────────────────

static void cmd_processes() {
    auto buf = qsi(5);
    if (buf.empty()) { fprintf(stderr, "NtQuerySystemInformation failed\n"); return; }
    printf("%-8s  %-8s  %-5s  %-8s  %s\n","PID","PPID","SESS","THREADS","Name");
    printf("%s\n", std::string(60,'-').c_str());
    auto* p = (SYSTEM_PROCESS_INFORMATION*)buf.data();
    while (true) {
        char name[256] = "<Idle>";
        if (p->ImageName.Buffer && p->ImageName.Length)
            WideCharToMultiByte(CP_ACP,0,p->ImageName.Buffer,p->ImageName.Length/2,
                                name,sizeof(name),nullptr,nullptr);
        printf("%-8llu  %-8llu  %-5u  %-8u  %s\n",
               (unsigned long long)(uintptr_t)p->UniqueProcessId,
               (unsigned long long)(uintptr_t)p->InheritedFromUniqueProcessId,
               p->SessionId, p->NumberOfThreads, name);
        if (!p->NextEntryOffset) break;
        p = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
    }
}

// ─── peb <pid> ────────────────────────────────────────────────────────────────

static void cmd_peb(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) { fprintf(stderr, "Cannot open PID %lu: %lu\n", pid, GetLastError()); return; }

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG ret = 0;
    NtQIP(hProc, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &ret);

    printf("PEB @ 0x%p\n", pbi.PebBaseAddress);

    // Read PEB header (first 256 bytes)
    BYTE peb_raw[256]{};
    SIZE_T rd = 0;
    ReadProcessMemory(hProc, pbi.PebBaseAddress, peb_raw, sizeof(peb_raw), &rd);

    BYTE being_dbg = peb_raw[2];
    DWORD ntgf;
#ifdef _WIN64
    memcpy(&ntgf, peb_raw + 0xBC, 4);
    PVOID imgbase; memcpy(&imgbase, peb_raw + 0x10, 8);
#else
    memcpy(&ntgf, peb_raw + 0x68, 4);
    PVOID imgbase; memcpy(&imgbase, peb_raw + 0x08, 4);
#endif
    printf("  BeingDebugged:  %d\n", being_dbg);
    printf("  NtGlobalFlag:   0x%08X%s\n", ntgf, (ntgf & 0x70) ? "  <-- debug flags!" : "");
    printf("  ImageBase:      0x%p\n", imgbase);

    CloseHandle(hProc);
}

// ─── handles <pid> ────────────────────────────────────────────────────────────

#pragma pack(push,1)
struct SHE {
    ULONG  OwnerPid;
    BYTE   ObjectType;
    BYTE   HandleFlags;
    USHORT HandleValue;
    PVOID  ObjectPointer;
    ULONG  AccessMask;
};
#pragma pack(pop)

static void cmd_handles(DWORD pid) {
    auto buf = qsi(16 /*SystemHandleInformation*/);
    if (buf.empty()) { fprintf(stderr, "SystemHandleInformation failed\n"); return; }
    ULONG count = *(ULONG*)buf.data();
    auto* entries = (SHE*)(buf.data() + sizeof(ULONG));
    printf("Handles for PID %lu:\n", pid);
    printf("%-8s  %-5s  %-4s  %s\n","Handle","Type","Flags","ObjectPtr");
    int found = 0;
    for (ULONG i = 0; i < count; ++i) {
        if (entries[i].OwnerPid != pid) continue;
        printf("  0x%04X    %-5u  0x%02X  0x%p\n",
               entries[i].HandleValue, entries[i].ObjectType,
               entries[i].HandleFlags, entries[i].ObjectPointer);
        ++found;
    }
    printf("Total: %d handles\n", found);
}

// ─── modules <pid> ────────────────────────────────────────────────────────────

static void cmd_modules(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Snapshot failed: %lu\n", GetLastError()); return;
    }
    MODULEENTRY32 me{ sizeof(me) };
    printf("%-18s  %-10s  %s\n","Base","Size","Path");
    printf("%s\n", std::string(80,'-').c_str());
    if (Module32First(snap, &me)) {
        do {
            printf("0x%-16p  0x%-8X  %s\n",
                   me.modBaseAddr, me.modBaseSize, me.szExePath);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

// ─── teb: dump own TEB ────────────────────────────────────────────────────────

static void cmd_teb() {
#ifdef _WIN64
    BYTE* teb = (BYTE*)__readgsqword(0);
    // TEB: NT_TIB at offset 0
    // StackBase  +0x008, StackLimit +0x010, PEB +0x060
    PVOID stack_base;  memcpy(&stack_base,  teb + 0x008, 8);
    PVOID stack_limit; memcpy(&stack_limit, teb + 0x010, 8);
    PVOID peb_ptr;     memcpy(&peb_ptr,     teb + 0x060, 8);
    DWORD tid;         memcpy(&tid,         teb + 0x048, 4);
    DWORD pid;         memcpy(&pid,         teb + 0x040, 4);
    printf("Own TEB (x64):\n");
    printf("  TEB address:   0x%p\n", teb);
    printf("  PID:           %lu\n",  pid);
    printf("  TID:           %lu\n",  tid);
    printf("  StackBase:     0x%p\n", stack_base);
    printf("  StackLimit:    0x%p\n", stack_limit);
    printf("  PEB:           0x%p\n", peb_ptr);
#else
    printf("TEB (x86): FS:[0]\n");
    BYTE* teb = (BYTE*)__readfsdword(0x18);
    printf("  TEB @ 0x%p\n", teb);
#endif
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    init_nt();
    if (argc < 2) {
        printf("Usage:\n"
               "  winternals_inspector.exe processes\n"
               "  winternals_inspector.exe peb     <pid>\n"
               "  winternals_inspector.exe handles <pid>\n"
               "  winternals_inspector.exe modules <pid>\n"
               "  winternals_inspector.exe teb\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "processes")             cmd_processes();
    else if (cmd == "peb"     && argc >= 3)  cmd_peb((DWORD)strtoul(argv[2],nullptr,10));
    else if (cmd == "handles" && argc >= 3)  cmd_handles((DWORD)strtoul(argv[2],nullptr,10));
    else if (cmd == "modules" && argc >= 3)  cmd_modules((DWORD)strtoul(argv[2],nullptr,10));
    else if (cmd == "teb")                   cmd_teb();
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
