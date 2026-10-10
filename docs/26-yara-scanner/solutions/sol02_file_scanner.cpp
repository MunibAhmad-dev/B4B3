/*
  Solution 02 — YARA File Scanner
  ----------------------------------
  Implements compileRules, scanFile, and scanDirectory using the libyara C API.

  Compile (with YARA):
    g++ -std=c++17 -Wall -DYARA_AVAILABLE -I<yara>/include -o sol02.exe sol02_file_scanner.cpp -lyara
  Compile (stub only):
    g++ -std=c++17 -Wall -o sol02.exe sol02_file_scanner.cpp
  Usage:
    sol02.exe rules.yar <target_file_or_directory>
*/

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>

#ifdef YARA_AVAILABLE
#include <yara.h>

// ── compileRules ──────────────────────────────────────────────────────────────
// Two-step: add rule files to a compiler, then get the compiled rule object.
YR_RULES* compileRules(const char* ruleFile) {
    yr_initialize();

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        printf("[-] yr_compiler_create failed\n");
        return nullptr;
    }

    // Report compilation errors
    yr_compiler_set_callback(compiler, [](int errorLevel, const char* fileName,
                                          int lineNumber, const YR_RULE* rule,
                                          const char* message, void* userData) {
        (void)rule; (void)userData;
        printf("[YARA %s] %s:%d — %s\n",
               errorLevel == YARA_ERROR_LEVEL_ERROR ? "ERROR" : "WARN",
               fileName, lineNumber, message);
    }, nullptr);

    FILE* f = fopen(ruleFile, "r");
    if (!f) { printf("[-] Cannot open rule file: %s\n", ruleFile); yr_compiler_destroy(compiler); return nullptr; }
    int errors = yr_compiler_add_file(compiler, f, nullptr, ruleFile);
    fclose(f);

    if (errors > 0) {
        printf("[-] %d compilation error(s) in %s\n", errors, ruleFile);
        yr_compiler_destroy(compiler);
        return nullptr;
    }

    YR_RULES* rules = nullptr;
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    return rules;
}

// ── matchCallback ─────────────────────────────────────────────────────────────
// Called once per matched rule; adds the rule name to the output vector.
struct ScanCtx { std::vector<std::string>* matches; };

int matchCallback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    (void)context;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = (YR_RULE*)messageData;
        auto* ctx  = (ScanCtx*)userData;
        ctx->matches->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// ── scanFile ─────────────────────────────────────────────────────────────────
std::vector<std::string> scanFile(YR_RULES* rules, const std::string& path) {
    std::vector<std::string> matches;
    ScanCtx ctx{ &matches };

    int ret = yr_rules_scan_file(rules, path.c_str(),
                                  SCAN_FLAGS_FAST_MODE,
                                  matchCallback, &ctx,
                                  10 /* timeout seconds */);
    if (ret != ERROR_SUCCESS && ret != ERROR_TOO_MANY_MATCHES)
        printf("  [!] Scan error %d on: %s\n", ret, path.c_str());

    return matches;
}

// ── scanDirectory ─────────────────────────────────────────────────────────────
void scanDirectory(YR_RULES* rules, const std::string& dir) {
    namespace fs = std::filesystem;
    size_t scanned = 0, hits = 0;

    for (auto& entry : fs::recursive_directory_iterator(dir,
             fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        scanned++;
        auto matches = scanFile(rules, entry.path().string());
        if (!matches.empty()) {
            hits++;
            printf("[MATCH] %s\n", entry.path().string().c_str());
            for (auto& m : matches) printf("  → %s\n", m.c_str());
        }
    }
    printf("\n[*] Scanned %zu files, %zu matched\n", scanned, hits);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <rules.yar> <file_or_directory>\n", argv[0]);
        return 1;
    }

    YR_RULES* rules = compileRules(argv[1]);
    if (!rules) return 1;

    namespace fs = std::filesystem;
    std::string target = argv[2];

    if (fs::is_directory(target)) {
        printf("[*] Scanning directory: %s\n\n", target.c_str());
        scanDirectory(rules, target);
    } else {
        printf("[*] Scanning file: %s\n", target.c_str());
        auto matches = scanFile(rules, target);
        if (matches.empty()) printf("[=] No matches\n");
        else for (auto& m : matches) printf("[MATCH] %s\n", m.c_str());
    }

    yr_rules_destroy(rules);
    yr_finalize();
    return 0;
}

#else  // ── stub when YARA not available ──────────────────────────────────────
int main(int argc, char* argv[]) {
    printf("[-] YARA not linked. Compile with -DYARA_AVAILABLE -lyara\n");
    printf("    Install YARA: https://github.com/VirusTotal/yara/releases\n");
    (void)argc; (void)argv;
    return 1;
}
#endif
