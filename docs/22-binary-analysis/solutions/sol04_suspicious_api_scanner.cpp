/*
  Solution 04 — Suspicious API Scanner (Complete)
  --------------------------------------------------
  Parses the PE Import Address Table and scores a binary against
  rule sets for common malware capabilities.

  Compile:
    g++ -std=c++17 -Wall -o sol04.exe sol04_suspicious_api_scanner.cpp
    cl  /std=c++17 sol04_suspicious_api_scanner.cpp /Fe:sol04.exe

  Usage:
    sol04.exe target.exe
    sol04.exe C:\Windows\System32\notepad.exe   (should be CLEAN / LOW RISK)
    sol04.exe malware_sample.exe
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <cstdio>
#include <algorithm>
#include <cstring>

struct ImportEntry {
    std::string dll;
    std::string function;
};

// =========================================================
// Rule table and scoring
// =========================================================
static const std::map<std::string, std::vector<std::string>> RULES = {
    { "INJECTION",   { "VirtualAllocEx", "WriteProcessMemory",
                       "CreateRemoteThread", "NtCreateThreadEx",
                       "NtAllocateVirtualMemory", "QueueUserAPC",
                       "NtCreateSection", "NtMapViewOfSection",
                       "SetThreadContext", "ResumeThread" } },
    { "EVASION",     { "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                       "NtQueryInformationProcess", "GetTickCount",
                       "GetTickCount64", "QueryPerformanceCounter" } },
    { "CREDENTIAL",  { "CryptUnprotectData", "CryptProtectData",
                       "LsaRetrievePrivateData", "SamOpenDatabase",
                       "CredEnumerate", "VaultEnumerateItems" } },
    { "KEYLOG",      { "SetWindowsHookExA", "SetWindowsHookExW",
                       "GetAsyncKeyState", "GetKeyState",
                       "RegisterHotKey" } },
    { "RANSOM",      { "CryptEncrypt", "CryptAcquireContext",
                       "CryptGenKey", "FindFirstFileA", "FindFirstFileW",
                       "MoveFileExA", "MoveFileExW", "DeleteFileA",
                       "DeleteFileW" } },
    { "NETWORK",     { "InternetOpenA", "InternetOpenW",
                       "HttpSendRequestA", "HttpSendRequestW",
                       "WinHttpOpen", "socket", "connect",
                       "send", "recv", "WSAConnect" } },
    { "DEFENSE_EVA", { "LoadLibraryA", "LoadLibraryW", "GetProcAddress" } },
    { "DROPPER",     { "WinExec", "ShellExecuteA", "ShellExecuteW",
                       "CreateProcessA", "CreateProcessW" } },
};

static const std::map<std::string, int> RULE_SCORES = {
    { "INJECTION",   40 },
    { "EVASION",     15 },
    { "CREDENTIAL",  30 },
    { "KEYLOG",      35 },
    { "RANSOM",      30 },
    { "NETWORK",     10 },
    { "DEFENSE_EVA",  5 },
    { "DROPPER",     20 },
};


// =========================================================
// PE helper: RVA → file offset
// =========================================================
static DWORD rvaToFileOffset(const BYTE* base,
                              IMAGE_SECTION_HEADER* sects,
                              WORD numSects,
                              DWORD rva) {
    for (WORD i = 0; i < numSects; i++) {
        DWORD vStart = sects[i].VirtualAddress;
        DWORD vEnd   = vStart + sects[i].Misc.VirtualSize;
        if (rva >= vStart && rva < vEnd)
            return sects[i].PointerToRawData + (rva - vStart);
    }
    return 0;
}


// =========================================================
// scanImports — parse the PE import directory
// =========================================================
std::vector<ImportEntry> scanImports(const char* filename) {
    std::vector<ImportEntry> result;

    std::ifstream f(filename, std::ios::binary);
    if (!f) { printf("[-] Cannot open '%s'\n", filename); return result; }

    std::vector<BYTE> data(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    f.close();

    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return result;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    DWORD ntOff = dos->e_lfanew;
    if (ntOff + 4 > data.size()) return result;

    // Check machine type
    auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(data.data() + ntOff);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) return result;

    bool  is64    = (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    WORD  numSects;
    DWORD importRva, importSize;
    DWORD sectOff;

    if (is64) {
        auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(data.data() + ntOff);
        numSects   = nt64->FileHeader.NumberOfSections;
        importRva  = nt64->OptionalHeader.DataDirectory
                         [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt64->OptionalHeader.DataDirectory
                         [IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        sectOff    = ntOff + sizeof(IMAGE_NT_HEADERS64);
    } else {
        numSects   = nt32->FileHeader.NumberOfSections;
        importRva  = nt32->OptionalHeader.DataDirectory
                         [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt32->OptionalHeader.DataDirectory
                         [IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        sectOff    = ntOff + sizeof(IMAGE_NT_HEADERS32);
    }

    if (importRva == 0 || importSize == 0) return result;
    if (sectOff + numSects * sizeof(IMAGE_SECTION_HEADER) > data.size())
        return result;

    auto* sects = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                      data.data() + sectOff);

    DWORD importOff = rvaToFileOffset(data.data(), sects, numSects, importRva);
    if (importOff == 0 || importOff >= data.size()) return result;

    // Walk IMAGE_IMPORT_DESCRIPTOR array (ends with all-zero entry)
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                     data.data() + importOff);

    while (importOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= data.size()
           && desc->Name != 0) {

        // DLL name
        DWORD nameOff = rvaToFileOffset(data.data(), sects, numSects, desc->Name);
        const char* dllName = (nameOff && nameOff < data.size())
                              ? (const char*)data.data() + nameOff
                              : "<unknown>";

        // Walk the INT (OriginalFirstThunk) or IAT (FirstThunk)
        DWORD thunkRva = desc->OriginalFirstThunk
                         ? desc->OriginalFirstThunk
                         : desc->FirstThunk;
        DWORD thunkOff = rvaToFileOffset(data.data(), sects, numSects, thunkRva);

        if (thunkOff && thunkOff < data.size()) {
            if (is64) {
                auto* thunk64 = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                                    data.data() + thunkOff);
                while (thunkOff + sizeof(IMAGE_THUNK_DATA64) <= data.size()
                       && thunk64->u1.AddressOfData != 0) {
                    if (!(thunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                        DWORD ibnOff = rvaToFileOffset(
                            data.data(), sects, numSects,
                            (DWORD)thunk64->u1.AddressOfData);
                        if (ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= data.size()) {
                            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                                            data.data() + ibnOff);
                            result.push_back({ dllName, (char*)ibn->Name });
                        }
                    }
                    thunk64++;
                    thunkOff += sizeof(IMAGE_THUNK_DATA64);
                }
            } else {
                auto* thunk32 = reinterpret_cast<IMAGE_THUNK_DATA32*>(
                                    data.data() + thunkOff);
                while (thunkOff + sizeof(IMAGE_THUNK_DATA32) <= data.size()
                       && thunk32->u1.AddressOfData != 0) {
                    if (!(thunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                        DWORD ibnOff = rvaToFileOffset(
                            data.data(), sects, numSects,
                            (DWORD)thunk32->u1.AddressOfData);
                        if (ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= data.size()) {
                            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                                            data.data() + ibnOff);
                            result.push_back({ dllName, (char*)ibn->Name });
                        }
                    }
                    thunk32++;
                    thunkOff += sizeof(IMAGE_THUNK_DATA32);
                }
            }
        }

        desc++;
        importOff += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    return result;
}


// =========================================================
// score — map imports to rule scores
// =========================================================
struct HitInfo {
    std::string              rule;
    std::vector<std::string> matched;
    int                      score;
};

static int score(const std::vector<ImportEntry>& imports,
                 std::vector<HitInfo>& hits) {
    // Build a flat name set for O(log n) lookups
    std::set<std::string> funcSet;
    for (auto& imp : imports)
        funcSet.insert(imp.function);

    int total = 0;
    for (auto& [rule, funcs] : RULES) {
        HitInfo h;
        h.rule  = rule;
        h.score = RULE_SCORES.at(rule);
        for (auto& fn : funcs)
            if (funcSet.count(fn)) h.matched.push_back(fn);

        if (!h.matched.empty()) {
            // Score scales with how many functions in the rule matched
            int ruleScore = h.score + (int)(h.matched.size() - 1) * (h.score / 4);
            h.score = ruleScore;
            total  += ruleScore;
            hits.push_back(std::move(h));
        }
    }
    return total;
}


// =========================================================
// scanBinary — full scan + report
// =========================================================
void scanBinary(const char* filename) {
    printf("[*] Scanning: %s\n\n", filename);

    auto imports = scanImports(filename);
    if (imports.empty()) {
        printf("[-] No imports found — either not a PE, no import table, "
               "or all imports are ordinal.\n");
        return;
    }

    printf("[*] Total imports: %zu\n\n", imports.size());

    // Print all imports grouped by DLL
    {
        std::map<std::string, std::vector<std::string>> byDll;
        for (auto& i : imports) byDll[i.dll].push_back(i.function);

        printf("[IMPORT TABLE]\n");
        for (auto& [dll, fns] : byDll) {
            printf("  %s\n", dll.c_str());
            for (auto& fn : fns)
                printf("    - %s\n", fn.c_str());
        }
        printf("\n");
    }

    // Score
    std::vector<HitInfo> hits;
    int totalScore = score(imports, hits);

    if (!hits.empty()) {
        printf("[RULES TRIGGERED]\n");
        // Sort by score descending
        std::sort(hits.begin(), hits.end(),
                  [](const HitInfo& a, const HitInfo& b){
                      return a.score > b.score;
                  });
        for (auto& h : hits) {
            printf("  %-15s (+%3d pts)  imports: ", h.rule.c_str(), h.score);
            for (size_t i = 0; i < h.matched.size(); i++) {
                if (i) printf(", ");
                printf("%s", h.matched[i].c_str());
            }
            printf("\n");
        }
        printf("\n");
    }

    // Verdict thresholds:
    //   0         → CLEAN
    //   1–39      → LOW RISK
    //   40–79     → SUSPICIOUS
    //   80–119    → HIGH RISK
    //   >= 120    → LIKELY MALICIOUS
    const char* verdict =
        totalScore == 0   ? "CLEAN"
      : totalScore < 40   ? "LOW RISK"
      : totalScore < 80   ? "SUSPICIOUS"
      : totalScore < 120  ? "HIGH RISK"
                          : "LIKELY MALICIOUS";

    printf("[VERDICT]  Score: %d  →  %s\n", totalScore, verdict);
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.exe>\n", argv[0]);
        printf("  Example: %s C:\\Windows\\System32\\notepad.exe\n", argv[0]);
        return 1;
    }
    scanBinary(argv[1]);
    return 0;
}
