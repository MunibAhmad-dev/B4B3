/*
  Solution 04 — YARA Rule Optimizer (TP/FP Analysis)
  ---------------------------------------------------
  Tests a rule set against a malicious corpus and a clean corpus to compute
  per-rule TP% and FP%, then flags poorly performing rules.

  Compile (with YARA):
    g++ -std=c++17 -Wall -DYARA_AVAILABLE -I<yara>/include -o sol04.exe sol04_rule_optimizer.cpp -lyara
  Usage:
    sol04.exe rules.yar <malicious_dir> <clean_dir>
*/

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <filesystem>

#ifdef YARA_AVAILABLE
#include <yara.h>

YR_RULES* compileRules(const char* ruleFile) {
    yr_initialize();
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return nullptr;
    FILE* f = fopen(ruleFile, "r");
    if (!f) { yr_compiler_destroy(compiler); return nullptr; }
    yr_compiler_add_file(compiler, f, nullptr, ruleFile);
    fclose(f);
    YR_RULES* rules = nullptr;
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    return rules;
}

// Collect matched rule names for one file
struct MatchCtx { std::set<std::string>* matched; };

int matchCallback(YR_SCAN_CONTEXT* ctx, int msg, void* data, void* user) {
    (void)ctx;
    if (msg == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = (YR_RULE*)data;
        ((MatchCtx*)user)->matched->insert(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// ── testCorpus ────────────────────────────────────────────────────────────────
// Scan all files in `dir` and return: map<ruleName, matchCount>, totalFiles
struct CorpusStats {
    std::map<std::string, size_t> matchCounts;
    size_t totalFiles = 0;
};

CorpusStats testCorpus(YR_RULES* rules, const std::string& dir) {
    namespace fs = std::filesystem;
    CorpusStats stats;

    for (auto& entry : fs::recursive_directory_iterator(dir,
             fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        stats.totalFiles++;

        std::set<std::string> matched;
        MatchCtx ctx{ &matched };
        yr_rules_scan_file(rules, entry.path().string().c_str(),
                           SCAN_FLAGS_FAST_MODE, matchCallback, &ctx, 10);
        for (auto& m : matched) stats.matchCounts[m]++;
    }
    return stats;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <rules.yar> <malicious_dir> <clean_dir>\n", argv[0]);
        return 1;
    }

    YR_RULES* rules = compileRules(argv[1]);
    if (!rules) { printf("[-] Failed to compile rules\n"); return 1; }

    printf("[*] Testing against malicious corpus: %s\n", argv[2]);
    auto malStats  = testCorpus(rules, argv[2]);

    printf("[*] Testing against clean corpus:     %s\n", argv[3]);
    auto cleanStats = testCorpus(rules, argv[3]);

    printf("\n[*] Malicious files: %zu  Clean files: %zu\n\n",
           malStats.totalFiles, cleanStats.totalFiles);

    // Collect all rule names
    std::set<std::string> allRules;
    for (auto& [k,_] : malStats.matchCounts)  allRules.insert(k);
    for (auto& [k,_] : cleanStats.matchCounts) allRules.insert(k);

    // Also add rules that matched zero files
    yr_rules_foreach(rules, rule) {
        allRules.insert(rule->identifier);
    }

    printf("%-35s  %7s  %7s  %s\n", "Rule", "TP%", "FP%", "Verdict");
    printf("%s\n", std::string(65, '-').c_str());

    for (auto& name : allRules) {
        double tp = 0, fp = 0;
        if (malStats.totalFiles > 0)
            tp = 100.0 * malStats.matchCounts[name] / malStats.totalFiles;
        if (cleanStats.totalFiles > 0)
            fp = 100.0 * cleanStats.matchCounts[name] / cleanStats.totalFiles;

        const char* verdict;
        if (fp > 5.0)              verdict = "POOR (FP too high)";
        else if (tp < 50.0)        verdict = "POOR (TP too low)";
        else                       verdict = "GOOD";

        printf("%-35s  %6.1f%%  %6.1f%%  %s\n", name.c_str(), tp, fp, verdict);
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
