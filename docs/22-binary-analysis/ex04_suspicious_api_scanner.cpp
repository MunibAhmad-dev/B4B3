/*
  Exercise 04 — Suspicious API Scanner
  --------------------------------------
  Many malware families are detectable by which Windows APIs they import.
  Security tools (VirusTotal, SandBoxie, AV engines) flag binaries that
  import certain combinations of APIs — especially the "injection triad".

  This exercise scans a PE's Import Address Table (IAT) and:
    1. Lists all imported DLLs and functions.
    2. Scores the binary against a set of "suspicious API" rules.
    3. Reports a verdict: CLEAN / SUSPICIOUS / MALICIOUS.

  Rule categories:
    INJECTION  — VirtualAllocEx, WriteProcessMemory, CreateRemoteThread,
                 NtAllocateVirtualMemory, QueueUserAPC
    EVASION    — IsDebuggerPresent, CheckRemoteDebuggerPresent,
                 NtQueryInformationProcess, GetTickCount
    CREDENTIAL — CryptProtectData, CredEnumerate, VaultEnumerateItems
    NETWORK    — InternetOpenA, HttpSendRequestA, WinHttpOpen, socket
    KEYLOG     — SetWindowsHookExA/W (WH_KEYBOARD_LL)
    RANSOM     — CryptEncrypt, FindFirstFileA (directory walk)
    DEFENSE    — LoadLibraryA + GetProcAddress (dynamic resolution)
    DROPPER    — WinExec, ShellExecuteA, CreateProcessA

  Tasks:
  1. Parse the import table (from ex01_pe_analyzer.cpp approach).
  2. For each imported function, check against the rule categories above.
  3. Count how many rules trigger; compute a score.
  4. Print a report with verdict, triggered rules, and the specific imports.

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_suspicious_api_scanner.cpp
  Usage:
    ex04.exe target.exe
    ex04.exe C:\Windows\System32\notepad.exe   (should be CLEAN)
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <cstdio>
#include <algorithm>

struct ImportEntry {
    std::string dll;
    std::string function;
};

// ---------- API rule table ----------
static const std::map<std::string, std::vector<std::string>> RULES = {
    { "INJECTION",   { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                       "NtAllocateVirtualMemory", "QueueUserAPC", "NtCreateSection",
                       "NtMapViewOfSection", "SetThreadContext", "ResumeThread" } },
    { "EVASION",     { "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                       "NtQueryInformationProcess", "GetTickCount", "GetTickCount64",
                       "QueryPerformanceCounter" } },
    { "CREDENTIAL",  { "CryptProtectData", "CryptUnprotectData",
                       "CredEnumerate", "VaultEnumerateItems" } },
    { "NETWORK",     { "InternetOpenA", "InternetOpenW", "HttpSendRequestA",
                       "HttpSendRequestW", "WinHttpOpen", "socket", "connect",
                       "send", "recv", "WSAConnect" } },
    { "KEYLOG",      { "SetWindowsHookExA", "SetWindowsHookExW" } },
    { "RANSOM",      { "CryptEncrypt", "CryptGenKey", "FindFirstFileA",
                       "FindFirstFileW", "MoveFileExA", "DeleteFileA" } },
    { "DEFENSE_EVA", { "LoadLibraryA", "LoadLibraryW", "GetProcAddress" } },
    { "DROPPER",     { "WinExec", "ShellExecuteA", "ShellExecuteW",
                       "CreateProcessA", "CreateProcessW" } },
};

static const int SCORE_INJECTION  = 40;
static const int SCORE_EVASION    = 15;
static const int SCORE_CREDENTIAL = 30;
static const int SCORE_NETWORK    = 10;
static const int SCORE_KEYLOG     = 35;
static const int SCORE_RANSOM     = 30;
static const int SCORE_DEFENSE    = 5;
static const int SCORE_DROPPER    = 20;

static const std::map<std::string, int> RULE_SCORES = {
    {"INJECTION", SCORE_INJECTION}, {"EVASION", SCORE_EVASION},
    {"CREDENTIAL", SCORE_CREDENTIAL}, {"NETWORK", SCORE_NETWORK},
    {"KEYLOG", SCORE_KEYLOG}, {"RANSOM", SCORE_RANSOM},
    {"DEFENSE_EVA", SCORE_DEFENSE}, {"DROPPER", SCORE_DROPPER}
};

// ---------- TODO: parse import table ----------
std::vector<ImportEntry> parseImports(const char* filename) {
    std::vector<ImportEntry> result;

    // YOUR CODE HERE (same approach as ex01_pe_analyzer):
    // 1. Read file into buffer
    // 2. Locate IMAGE_NT_HEADERS64
    // 3. Find IMAGE_DIRECTORY_ENTRY_IMPORT (index 1) in DataDirectory
    // 4. Map RVA to file offset: offset = rva - section.VirtualAddress + section.PointerToRawData
    // 5. Walk IMAGE_IMPORT_DESCRIPTOR until Name == 0
    //    For each descriptor:
    //      dll_name = buf + rvaToOffset(descriptor->Name)
    //      Walk IMAGE_THUNK_DATA (OriginalFirstThunk / FirstThunk):
    //        if not ordinal import: IMAGE_IMPORT_BY_NAME at the thunk's offset
    //          result.push_back({ dll_name, func_name })

    (void)filename;
    return result;
}

// ---------- score and report ----------
void scanBinary(const char* filename) {
    printf("[*] Scanning: %s\n\n", filename);

    auto imports = parseImports(filename);
    if (imports.empty()) {
        printf("[-] No imports found (parseImports not implemented?)\n");
        return;
    }

    printf("[*] Total imports: %zu\n\n", imports.size());

    // Build a flat set for quick lookup
    std::set<std::string> funcSet;
    for (auto& i : imports) funcSet.insert(i.function);

    // Check each rule
    struct Hit { std::string rule; std::vector<std::string> matched; };
    std::vector<Hit> hits;
    int totalScore = 0;

    for (auto& [rule, funcs] : RULES) {
        Hit h{ rule, {} };
        for (auto& f : funcs)
            if (funcSet.count(f)) h.matched.push_back(f);
        if (!h.matched.empty()) {
            totalScore += RULE_SCORES.at(rule);
            hits.push_back(h);
        }
    }

    // Print triggered rules
    if (!hits.empty()) {
        printf("[RULES TRIGGERED]\n");
        for (auto& h : hits) {
            printf("  %-15s (+%2d pts)  →  ", h.rule.c_str(), RULE_SCORES.at(h.rule));
            for (size_t i = 0; i < h.matched.size(); i++) {
                if (i) printf(", ");
                printf("%s", h.matched[i].c_str());
            }
            printf("\n");
        }
    }

    // Verdict
    const char* verdict = totalScore == 0   ? "CLEAN"
                        : totalScore < 40   ? "LOW RISK"
                        : totalScore < 80   ? "SUSPICIOUS"
                        : totalScore < 120  ? "HIGH RISK"
                                            : "LIKELY MALICIOUS";
    printf("\n[VERDICT]  Score: %d  →  %s\n", totalScore, verdict);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.exe>\n", argv[0]);
        return 1;
    }
    scanBinary(argv[1]);
    return 0;
}
