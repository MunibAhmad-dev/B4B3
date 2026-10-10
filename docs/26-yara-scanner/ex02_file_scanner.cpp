/*
  Exercise 02 — YARA File Scanner
  ---------------------------------
  Use the libyara C API to scan a file or directory against a ruleset.

  libyara setup:
    - Windows: download prebuilt from https://github.com/VirusTotal/yara/releases
      or build with MSVC from source.
    - vcpkg: vcpkg install yara:x64-windows
    - Include: <yara.h>  Link: libyara.lib

  Tasks:
  1. Implement compileRules(rulesPath) — compile a .yar file into YR_RULES*.
  2. Implement scanFile(rules, filePath) — scan one file, print each match.
  3. Implement scanDirectory(rules, dirPath) — recursively scan all files
     in a directory, skip directories and inaccessible files.
  4. Print a summary: files scanned, files matched, rules that hit most.

  BONUS:
  - Accept multiple rule files: compile them all into one rule set.
  - Implement timeout: use the yr_rules_scan_file timeout parameter (10 seconds).
  - Save matches to a JSON report file.

  Compile (MSVC):
    cl /std:c++17 ex02_file_scanner.cpp /I<yara_include>
       /link <yara_lib_dir>\libyara.lib /OUT:ex02.exe
  Usage:
    ex02.exe rules.yar target.exe
    ex02.exe rules.yar C:\Users\ --recurse
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <cstdio>

#ifdef YARA_AVAILABLE
#include <yara.h>
#endif

namespace fs = std::filesystem;

struct ScanResult {
    std::string file;
    std::string rule;
    size_t      matchCount;
};

static std::vector<ScanResult> g_results;
static int g_filesScanned = 0;

#ifdef YARA_AVAILABLE

int scanCallback(YR_SCAN_CONTEXT* context, int message,
                  void* messageData, void* userData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)messageData;
        const char* filePath = (const char*)userData;
        printf("[MATCH]  %-40s  Rule: %s\n", filePath, rule->identifier);

        // Print matching strings
        YR_STRING* str;
        yr_rule_strings_foreach(rule, str) {
            YR_MATCH* match;
            yr_string_matches_foreach(context, str, match) {
                printf("         String %-15s at offset 0x%08llX\n",
                       str->identifier, (ULONGLONG)match->offset);
            }
        }
        g_results.push_back({ filePath, rule->identifier, 1 });
    }
    return CALLBACK_CONTINUE;
}

// ---------- TODO 1: compileRules ----------
YR_RULES* compileRules(const std::string& rulesPath) {
    YR_COMPILER* compiler = nullptr;
    YR_RULES*    rules    = nullptr;

    yr_initialize();
    yr_compiler_create(&compiler);

    FILE* f = nullptr;
    fopen_s(&f, rulesPath.c_str(), "r");
    if (!f) {
        printf("[-] Cannot open rules: %s\n", rulesPath.c_str());
        yr_compiler_destroy(compiler); yr_finalize();
        return nullptr;
    }

    int errors = yr_compiler_add_file(compiler, f, nullptr, rulesPath.c_str());
    fclose(f);

    if (errors > 0) {
        printf("[-] Rule compilation errors: %d\n", errors);
        yr_compiler_destroy(compiler); yr_finalize();
        return nullptr;
    }
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    return rules;
}

// ---------- TODO 2: scanFile ----------
void scanFile(YR_RULES* rules, const std::string& filePath) {
    g_filesScanned++;
    int result = yr_rules_scan_file(rules, filePath.c_str(), 0,
                                     scanCallback, (void*)filePath.c_str(), 10);
    if (result != ERROR_SUCCESS && result != ERROR_CALLBACK_ERROR) {
        printf("[-] Scan error on %s: %d\n", filePath.c_str(), result);
    }
}

// ---------- TODO 3: scanDirectory ----------
void scanDirectory(YR_RULES* rules, const std::string& dirPath) {
    for (auto& entry : fs::recursive_directory_iterator(
             dirPath, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        scanFile(rules, entry.path().string());
    }
}

#else
// Stub when libyara not available
void* compileRules(const std::string&) { printf("[-] YARA not compiled in\n"); return nullptr; }
void scanFile(void*, const std::string& p) { printf("[STUB] Would scan: %s\n", p.c_str()); }
void scanDirectory(void*, const std::string& d) { printf("[STUB] Would scan dir: %s\n", d.c_str()); }
#endif

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <rules.yar> <target> [--recurse]\n", argv[0]);
        return 1;
    }
    bool recurse = (argc > 3 && strcmp(argv[3], "--recurse") == 0);

    printf("[*] Loading rules: %s\n", argv[1]);
#ifdef YARA_AVAILABLE
    YR_RULES* rules = compileRules(argv[1]);
    if (!rules) return 1;

    printf("[*] Scanning: %s\n", argv[2]);
    if (recurse || fs::is_directory(argv[2]))
        scanDirectory(rules, argv[2]);
    else
        scanFile(rules, argv[2]);

    yr_rules_destroy(rules);
    yr_finalize();
#else
    printf("[*] (YARA not available — would scan %s with %s)\n", argv[2], argv[1]);
#endif

    printf("\n[*] Summary: %d files scanned, %zu matches\n",
           g_filesScanned, g_results.size());
    return 0;
}
