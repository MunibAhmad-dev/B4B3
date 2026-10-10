/*
  Exercise 04 — YARA Rule Optimizer / False Positive Tester
  -----------------------------------------------------------
  A YARA rule is only useful if it has a low false positive (FP) rate.
  A rule that fires on every binary is useless.

  This tool tests a ruleset against:
    a) A "malicious" corpus (samples you WANT to match)
    b) A "clean" corpus   (known-good binaries you DON'T want to match)

  And computes:
    - True Positive  rate (TP%)  — malicious files matched
    - False Positive rate (FP%)  — clean files matched
    - Per-rule statistics
    - Suggestions: rules with high FP% should be tightened

  Tasks:
  1. Implement testCorpus(rules, dir) — scan all files, return {filename → [rules hit]}.
  2. Compute TP% = matched_malicious / total_malicious.
  3. Compute FP% = matched_clean / total_clean.
  4. Per rule: compute its own TP% and FP%, flag rules with FP% > 1%.
  5. Print a table: Rule | TP (N/M) | FP (N/M) | Status.

  Usage:
    ex04.exe rules.yar C:\malware_samples\ C:\clean_binaries\
    ex04.exe rules.yar samples\malware\ C:\Windows\System32\

  BONUS:
  - Compute a "score" per rule: TP% - (5 * FP%) — penalize false positives heavily.
  - Suggest which strings to remove to reduce FP% (remove the most common-FP strings).
  - Export results as a Markdown table.

  Compile: same as ex02 — requires libyara.
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <filesystem>
#include <cstdio>

namespace fs = std::filesystem;

#ifdef YARA_AVAILABLE
#include <yara.h>

struct CorpusResult {
    std::string file;
    std::set<std::string> matchedRules;
};

struct ScanCtx { std::string filePath; CorpusResult* result; };

int optCallback(YR_SCAN_CONTEXT* context, int message,
                 void* messageData, void* userData) {
    UNREFERENCED_PARAMETER(context);
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE*   rule = (YR_RULE*)messageData;
        ScanCtx*   ctx  = (ScanCtx*)userData;
        ctx->result->matchedRules.insert(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// ---------- TODO 1: testCorpus ----------
std::vector<CorpusResult> testCorpus(YR_RULES* rules, const std::string& dir) {
    std::vector<CorpusResult> results;
    for (auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        CorpusResult r{ entry.path().string(), {} };
        ScanCtx ctx{ r.file, &r };
        yr_rules_scan_file(rules, r.file.c_str(), 0, optCallback, &ctx, 10);
        results.push_back(r);
    }
    return results;
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

void printReport(const std::vector<CorpusResult>& malicious,
                  const std::vector<CorpusResult>& clean) {
    // Collect all rule names
    std::set<std::string> allRules;
    for (auto& r : malicious) for (auto& rule : r.matchedRules) allRules.insert(rule);
    for (auto& r : clean)     for (auto& rule : r.matchedRules) allRules.insert(rule);

    int totalMal   = (int)malicious.size();
    int totalClean = (int)clean.size();

    int malHit   = 0; for (auto& r : malicious) if (!r.matchedRules.empty()) malHit++;
    int cleanHit = 0; for (auto& r : clean)     if (!r.matchedRules.empty()) cleanHit++;

    printf("\n=== OVERALL ===\n");
    printf("  Malicious: %d/%d (%.1f%% TP)\n",
           malHit, totalMal, totalMal ? 100.0*malHit/totalMal : 0.0);
    printf("  Clean:     %d/%d (%.1f%% FP)\n",
           cleanHit, totalClean, totalClean ? 100.0*cleanHit/totalClean : 0.0);

    printf("\n=== PER-RULE ===\n");
    printf("%-35s  %8s  %8s  %s\n", "Rule", "TP%", "FP%", "Status");
    printf("%s\n", std::string(65, '-').c_str());

    for (auto& rule : allRules) {
        int tp = 0, fp = 0;
        for (auto& r : malicious) if (r.matchedRules.count(rule)) tp++;
        for (auto& r : clean)     if (r.matchedRules.count(rule)) fp++;

        double tpPct = totalMal   ? 100.0*tp/totalMal   : 0.0;
        double fpPct = totalClean ? 100.0*fp/totalClean : 0.0;
        const char* status = fpPct > 5.0  ? "POOR  (high FP)"
                           : fpPct > 1.0  ? "WARN  (check FP)"
                           : tpPct < 10.0 ? "WEAK  (low TP)"
                                          : "OK";
        printf("%-35s  %7.1f%%  %7.1f%%  %s\n",
               rule.c_str(), tpPct, fpPct, status);
    }
}

#endif

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <rules.yar> <malicious_dir> <clean_dir>\n", argv[0]);
        return 1;
    }
#ifdef YARA_AVAILABLE
    YR_RULES* rules = compileRules(argv[1]);
    if (!rules) return 1;

    printf("[*] Scanning malicious corpus: %s\n", argv[2]);
    auto malResults = testCorpus(rules, argv[2]);
    printf("[*] Scanning clean corpus:     %s\n", argv[3]);
    auto cleanResults = testCorpus(rules, argv[3]);

    printReport(malResults, cleanResults);

    yr_rules_destroy(rules);
    yr_finalize();
#else
    printf("[-] YARA not compiled in\n");
    (void)argc; (void)argv;
#endif
    return 0;
}
