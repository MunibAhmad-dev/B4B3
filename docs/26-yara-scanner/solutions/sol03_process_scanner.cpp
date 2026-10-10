/*
  Solution 03 — YARA Live Process Scanner
  ------------------------------------------
  Scans the memory regions of running processes using yr_rules_scan_mem.

  Compile (with YARA):
    g++ -std=c++17 -Wall -DYARA_AVAILABLE -I<yara>/include -o sol03.exe sol03_process_scanner.cpp -lyara -lpsapi
  Usage:
    sol03.exe rules.yar [pid]          # scan one process or all processes
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef YARA_AVAILABLE
#include <yara.h>

// ── compileRules (same as sol02) ──────────────────────────────────────────────
YR_RULES* compileRules(const char* ruleFile) {
    yr_initialize();
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return nullptr;
    FILE* f = fopen(ruleFile, "r");
    if (!f) { yr_compiler_destroy(compiler); return nullptr; }
    int err = yr_compiler_add_file(compiler, f, nullptr, ruleFile);
    fclose(f);
    if (err > 0) { yr_compiler_destroy(compiler); return nullptr; }
    YR_RULES* rules = nullptr;
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    return rules;
}

struct ScanCtx {
    std::vector<std::string>* matches;
    DWORD pid;
    LPVOID regionBase;
};

int matchCallback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    (void)context;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = (YR_RULE*)messageData;
        auto* ctx  = (ScanCtx*)userData;
        char hit[256];
        snprintf(hit, sizeof(hit), "PID=%lu @%p rule=%s",
                 ctx->pid, ctx->regionBase, rule->identifier);
        ctx->matches->push_back(hit);
    }
    return CALLBACK_CONTINUE;
}

// ── scanProcessMemory ─────────────────────────────────────────────────────────
// Enumerate all committed, readable memory regions and scan each with YARA.
std::vector<std::string> scanProcessMemory(YR_RULES* rules, DWORD pid) {
    std::vector<std::string> allMatches;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return allMatches;  // no access — normal for system processes

    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = nullptr;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT)                        { continue; }
        if (mbi.Protect & PAGE_GUARD)                       { continue; }
        if (mbi.Protect == PAGE_NOACCESS)                   { continue; }
        if (mbi.RegionSize < 16 || mbi.RegionSize > 64*1024*1024) { continue; }

        std::vector<BYTE> buf(mbi.RegionSize);
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &read)) continue;
        if (read == 0) continue;

        ScanCtx ctx{ &allMatches, pid, mbi.BaseAddress };
        yr_rules_scan_mem(rules, buf.data(), read,
                          SCAN_FLAGS_FAST_MODE, matchCallback, &ctx,
                          5 /* timeout */);
    }

    CloseHandle(hProc);
    return allMatches;
}

// ── scanAllProcesses ──────────────────────────────────────────────────────────
void scanAllProcesses(YR_RULES* rules) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { printf("[-] Snapshot failed\n"); return; }

    PROCESSENTRY32 pe = {}; pe.dwSize = sizeof(pe);
    size_t scanned = 0, total_hits = 0;

    if (Process32First(snap, &pe)) {
        do {
            scanned++;
            auto hits = scanProcessMemory(rules, pe.th32ProcessID);
            if (!hits.empty()) {
                total_hits += hits.size();
                printf("[!] PID %lu (%s): %zu match(es)\n",
                       pe.th32ProcessID, pe.szExeFile, hits.size());
                for (auto& h : hits) printf("    %s\n", h.c_str());
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    printf("\n[*] Scanned %zu processes, %zu total matches\n", scanned, total_hits);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <rules.yar> [pid]\n", argv[0]);
        return 1;
    }

    YR_RULES* rules = compileRules(argv[1]);
    if (!rules) { printf("[-] Failed to compile rules\n"); return 1; }

    if (argc >= 3) {
        DWORD pid = (DWORD)atoi(argv[2]);
        printf("[*] Scanning PID %lu\n", pid);
        auto hits = scanProcessMemory(rules, pid);
        if (hits.empty()) printf("[=] No matches in PID %lu\n", pid);
        else for (auto& h : hits) printf("[MATCH] %s\n", h.c_str());
    } else {
        printf("[*] Scanning all processes...\n\n");
        scanAllProcesses(rules);
    }

    yr_rules_destroy(rules);
    yr_finalize();
    return 0;
}

#else
int main(int argc, char* argv[]) {
    printf("[-] YARA not linked. Compile with -DYARA_AVAILABLE -lyara\n");
    (void)argc; (void)argv;
    return 1;
}
#endif
