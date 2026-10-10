/*
  Exercise 03 — YARA Process Memory Scanner
  -------------------------------------------
  Scan the memory of running processes with YARA rules.
  This is more powerful than file scanning because:
    - Detects unpacked/decrypted payloads (not visible on disk)
    - Can match shellcode or reflective DLLs that have no file
    - Used by IR tools (Volatility, pe-sieve, hollows_hunter)

  yr_rules_scan_mem() lets you scan a raw byte buffer — so you can:
    1. Enumerate all committed memory regions of a process.
    2. ReadProcessMemory to copy each region.
    3. yr_rules_scan_mem() each region.

  Tasks:
  1. Implement scanProcessMemory(rules, pid) — enumerate regions,
     read each one, scan with YARA.
  2. Implement scanAllProcesses(rules) — iterate all PIDs via Toolhelp32,
     call scanProcessMemory for each.
  3. Skip inaccessible processes gracefully (system/protected).
  4. Print matches with: PID, process name, region base, matched rule.

  BONUS:
  - Only scan MEM_PRIVATE regions (skip MEM_IMAGE) for efficiency.
  - Add a whitelist of trusted process names to skip.
  - Export results to a JSON file for import into a SIEM.

  Compile: same as ex02 — requires libyara.
  Usage:
    ex03.exe rules.yar            → scan all processes
    ex03.exe rules.yar 1234       → scan specific PID
*/

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdio>

#ifdef YARA_AVAILABLE
#include <yara.h>

struct ProcScanCtx {
    DWORD       pid;
    std::string procName;
    LPVOID      regionBase;
};

int procScanCallback(YR_SCAN_CONTEXT* context, int message,
                      void* messageData, void* userData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE*    rule = (YR_RULE*)messageData;
        ProcScanCtx* ctx = (ProcScanCtx*)userData;
        printf("[MATCH] PID=%-6lu  %-30s  @%p  Rule: %s\n",
               ctx->pid, ctx->procName.c_str(), ctx->regionBase, rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// ---------- TODO 1: scan one process ----------
void scanProcessMemory(YR_RULES* rules, DWORD pid, const std::string& name) {
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = nullptr;
    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS))
        {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress,
                                   buf.data(), mbi.RegionSize, &bytesRead) && bytesRead) {
                ProcScanCtx ctx{ pid, name, mbi.BaseAddress };
                yr_rules_scan_mem(rules, buf.data(), bytesRead, 0,
                                   procScanCallback, &ctx, 5);
            }
        }
        addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(hProcess);
}

// ---------- TODO 2: scan all processes ----------
void scanAllProcesses(YR_RULES* rules) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnap, &pe)) {
        do {
            // Skip system processes
            if (pe.th32ProcessID <= 4) continue;
            printf("[*] Scanning PID=%-6lu  %s\n", pe.th32ProcessID, pe.szExeFile);
            scanProcessMemory(rules, pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

YR_RULES* compileRules(const char* path) {
    yr_initialize();
    YR_COMPILER* c = nullptr; YR_RULES* r = nullptr;
    yr_compiler_create(&c);
    FILE* f = nullptr; fopen_s(&f, path, "r");
    if (!f) { yr_compiler_destroy(c); yr_finalize(); return nullptr; }
    yr_compiler_add_file(c, f, nullptr, path);
    fclose(f);
    yr_compiler_get_rules(c, &r);
    yr_compiler_destroy(c);
    return r;
}

#endif

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <rules.yar> [pid]\n", argv[0]);
        return 1;
    }
#ifdef YARA_AVAILABLE
    YR_RULES* rules = compileRules(argv[1]);
    if (!rules) return 1;

    if (argc > 2) {
        DWORD pid = (DWORD)atoi(argv[2]);
        scanProcessMemory(rules, pid, "target");
    } else {
        scanAllProcesses(rules);
    }

    yr_rules_destroy(rules);
    yr_finalize();
#else
    printf("[-] YARA not compiled in (define YARA_AVAILABLE)\n");
    (void)argc; (void)argv;
#endif
    return 0;
}
