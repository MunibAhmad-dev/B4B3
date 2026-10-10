// solutions/sol04_test_harness.cpp
// Module 36 — SAST Tool, Solution 4
//
// Complete test harness: embeds 8 vulnerable C snippets, runs sol01_pattern_scanner
// on each, and measures TP/FP/FN detection rates.
//
// Compile: g++ -std=c++17 -Wall -o sol04.exe sol04_test_harness.cpp
// Run:     sol04.exe <path_to_sol01.exe>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

struct Snippet {
    std::string name;
    std::string code;
    std::vector<std::string> expectedCWEs;    // should be in scanner output
    std::vector<std::string> notExpectedCWEs; // common false positives to check for
};

// =====================================================================
// Eight intentionally-vulnerable C snippets
// =====================================================================

static std::vector<Snippet> makeSnippets() {
    return {
        {
            "01_buffer_overflow_gets",
            "#include <stdio.h>\n"
            "int main() {\n"
            "    char buf[64];\n"
            "    gets(buf);       /* CWE-120: no bounds check */\n"
            "    printf(\"%s\", buf);\n"
            "    return 0;\n"
            "}\n",
            {"CWE-120"}, {}
        },
        {
            "02_format_string",
            "#include <stdio.h>\n"
            "void logMessage(char* msg) {\n"
            "    printf(msg);    /* CWE-134: format string */\n"
            "}\n"
            "int main(int argc, char** argv) {\n"
            "    logMessage(argv[1]);\n"
            "    return 0;\n"
            "}\n",
            {"CWE-134"}, {}
        },
        {
            "03_command_injection",
            "#include <stdlib.h>\n"
            "int main(int argc, char** argv) {\n"
            "    system(argv[1]);  /* CWE-78: command injection */\n"
            "    return 0;\n"
            "}\n",
            {"CWE-78"}, {}
        },
        {
            "04_sql_injection",
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "void query(char* name) {\n"
            "    char sql[256];\n"
            "    sprintf(sql, \"SELECT * FROM users WHERE name='%s'\", name);\n"
            "    /* CWE-89: SQL injection via sprintf */\n"
            "}\n",
            {"CWE-89", "CWE-120"}, {}  // sprintf also triggers CWE-120
        },
        {
            "05_hardcoded_password",
            "#include <string.h>\n"
            "int check(char* pass) {\n"
            "    const char* password = \"admin123\";  /* CWE-798 */\n"
            "    return strcmp(pass, password) == 0;\n"
            "}\n",
            {"CWE-798"}, {}
        },
        {
            "06_use_after_free",
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "void process(char* data) {\n"
            "    char* p = (char*)malloc(64);\n"
            "    strcpy(p, data);   /* CWE-120 */\n"
            "    free(p);\n"
            "    /* UAF: accessing p after free */\n"
            "    p[0] = 0;          /* CWE-416 */\n"
            "}\n",
            {"CWE-120", "CWE-416"}, {}
        },
        {
            "07_null_deref_malloc",
            "#include <stdlib.h>\n"
            "void alloc(int n) {\n"
            "    char* buf = (char*)malloc(n);  /* CWE-476: no NULL check */\n"
            "    buf[0] = 0;\n"
            "}\n",
            {"CWE-476"}, {}
        },
        {
            "08_path_traversal",
            "#include <stdio.h>\n"
            "void readFile(char* path) {\n"
            "    FILE* f = fopen(path, \"r\");  /* CWE-22: path traversal */\n"
            "    if (f) fclose(f);\n"
            "}\n",
            {"CWE-22"}, {}
        },
    };
}

// =====================================================================
// Write a snippet to a temp file
// =====================================================================

static std::string writeSnippet(const Snippet& s) {
    std::string path = "tmp_harness_" + s.name + ".c";
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return "";
    fwrite(s.code.c_str(), 1, s.code.size(), f);
    fclose(f);
    return path;
}

// =====================================================================
// Run scanner and capture stdout
// =====================================================================

static std::string runScanner(const std::string& scannerPath,
                               const std::string& snippetFile) {
    std::string cmd = "\"" + scannerPath + "\" \"" + snippetFile + "\" 2>&1";
    std::string output;

#ifdef _WIN32
    FILE* p = _popen(cmd.c_str(), "r");
#else
    FILE* p = popen(cmd.c_str(), "r");
#endif
    if (!p) return "";

    char buf[512];
    while (fgets(buf, sizeof(buf), p))
        output += buf;

#ifdef _WIN32
    _pclose(p);
#else
    pclose(p);
#endif
    return output;
}

// =====================================================================
// Score a test case
// =====================================================================

struct Score { int tp, fn, fp; };

static Score evaluate(const Snippet& s, const std::string& output, bool verbose) {
    Score sc{0,0,0};

    for (const auto& cwe : s.expectedCWEs) {
        bool found = output.find(cwe) != std::string::npos;
        if (found) {
            sc.tp++;
            if (verbose) printf("  [PASS] Expected %s — FOUND\n", cwe.c_str());
        } else {
            sc.fn++;
            if (verbose) printf("  [MISS] Expected %s — NOT FOUND (false negative)\n", cwe.c_str());
        }
    }

    // Approximate FP: count CWE strings in output that aren't in expectedCWEs
    // Scan for "CWE-" occurrences
    size_t pos = 0;
    while ((pos = output.find("CWE-", pos)) != std::string::npos) {
        // Extract "CWE-NNN"
        size_t end = pos + 4;
        while (end < output.size() && isdigit(output[end])) end++;
        std::string cwe = output.substr(pos, end-pos);
        pos = end;

        bool expected = false;
        for (auto& e : s.expectedCWEs)
            if (e == cwe) { expected=true; break; }

        if (!expected) {
            sc.fp++;
            if (verbose) printf("  [FP?]  Unexpected %s in output\n", cwe.c_str());
        }
    }

    return sc;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_sol01_or_ex01.exe>\n", argv[0]);
        return 1;
    }

    const char* scannerPath = argv[1];
    bool verbose = (argc >= 3 && strcmp(argv[2], "-v") == 0);

    auto snippets = makeSnippets();
    int totalTP=0, totalFN=0, totalFP=0;
    int passed=0, total=(int)snippets.size();

    printf("=== SAST Scanner Test Harness ===\n");
    printf("Scanner: %s\n", scannerPath);
    printf("Snippets: %d\n\n", total);

    for (auto& s : snippets) {
        printf("[%s]\n", s.name.c_str());
        printf("  Expected CWEs: ");
        for (auto& c : s.expectedCWEs) printf("%s ", c.c_str());
        printf("\n");

        std::string tmpFile = writeSnippet(s);
        if (tmpFile.empty()) {
            printf("  ERROR: could not write temp file\n\n");
            totalFN += (int)s.expectedCWEs.size();
            continue;
        }

        std::string output = runScanner(scannerPath, tmpFile);
        remove(tmpFile.c_str());

        if (verbose) {
            printf("  --- Scanner output ---\n");
            // Print first 400 chars
            std::string trimmed = output.substr(0, 400);
            printf("%s%s\n", trimmed.c_str(), output.size()>400?"...":"");
            printf("  ---\n");
        }

        Score sc = evaluate(s, output, verbose);

        printf("  TP=%d  FN=%d  FP(approx)=%d\n", sc.tp, sc.fn, sc.fp);

        if (sc.fn == 0) passed++;
        totalTP += sc.tp;
        totalFN += sc.fn;
        totalFP += sc.fp;
        printf("\n");
    }

    int allExpected = totalTP + totalFN;
    printf("===========================================\n");
    printf("=== Summary ===\n");
    printf("  Snippets fully detected   : %d / %d\n", passed, total);
    printf("  True Positives            : %d\n", totalTP);
    printf("  False Negatives (missed)  : %d\n", totalFN);
    printf("  False Positives (approx)  : %d\n", totalFP);
    if (allExpected > 0)
        printf("  Detection Rate            : %.1f%%\n", 100.0 * totalTP / allExpected);

    printf("\nPatterns the scanner likely misses:\n");
    if (totalFN > 0) {
        printf("  - Use-after-free (requires multi-line flow)\n");
        printf("  - Format string only when format arg is a variable (not literal)\n");
        printf("  - NULL dereference (requires knowing malloc was called on prior line)\n");
    } else {
        printf("  (All expected patterns were detected)\n");
    }

    return (totalFN > 0) ? 1 : 0;
}
