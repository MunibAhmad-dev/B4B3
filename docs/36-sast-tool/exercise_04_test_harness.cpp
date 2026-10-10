// exercise_04_test_harness.cpp
// Module 36 — SAST Tool, Exercise 4
//
// Goal: Embed intentionally-vulnerable C snippets, write them to temp files,
//       run exercise_01's pattern scanner on each, and measure TP/FP/FN.
//
// Compile: g++ -std=c++17 -Wall -o ex04.exe exercise_04_test_harness.cpp
// Run:     ex04.exe <path_to_ex01.exe>
//
// The harness:
//   1. Writes each snippet to a temp .c file
//   2. Runs: ex01.exe <tempfile>  (capture stdout via popen)
//   3. Checks if expected CWE IDs appear in the output
//   4. Prints TP/FP/FN for each snippet, and overall detection rate

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

struct Snippet {
    std::string name;
    std::string code;
    std::vector<std::string> expectedCWEs; // CWE IDs that should be reported
};

// -------------------------------------------------------------------
// Five vulnerable C snippets to test the scanner
// -------------------------------------------------------------------
static std::vector<Snippet> makeSnippets() {
    return {
        {
            "buffer_overflow_gets",
            "#include <stdio.h>\n"
            "int main() {\n"
            "    char buf[64];\n"
            "    gets(buf);  // vulnerable\n"
            "    return 0;\n"
            "}\n",
            {"CWE-120"}
        },
        {
            "format_string_printf",
            "#include <stdio.h>\n"
            "int main(int argc, char** argv) {\n"
            "    // print user input directly as format string\n"
            "    printf(argv[1]);  // vulnerable\n"
            "    return 0;\n"
            "}\n",
            {"CWE-134"}
        },
        {
            "command_injection_system",
            "#include <stdlib.h>\n"
            "int main(int argc, char** argv) {\n"
            "    system(argv[1]);  // vulnerable\n"
            "    return 0;\n"
            "}\n",
            {"CWE-78"}
        },
        {
            "strcpy_overflow",
            "#include <string.h>\n"
            "void copy(char* src) {\n"
            "    char dest[32];\n"
            "    strcpy(dest, src);  // vulnerable\n"
            "}\n",
            {"CWE-120"}
        },
        {
            "hardcoded_password",
            "#include <string.h>\n"
            "int authenticate(char* pass) {\n"
            "    const char* password = \"s3cr3t\";  // hardcoded\n"
            "    return strcmp(pass, password) == 0;\n"
            "}\n",
            {"CWE-798"}
        },
    };
}

// -------------------------------------------------------------------
// TODO: Implement writeSnippet()
//
// Write snippet.code to a temporary file.
// Return the file path (e.g., "tmp_snippet_<name>.c").
// Use fopen/fwrite/fclose.
// Return empty string on failure.
// -------------------------------------------------------------------
static std::string writeSnippet(const Snippet& s) {
    // TODO: implement
    (void)s;
    return "";
}

// -------------------------------------------------------------------
// TODO: Implement runScanner()
//
// Run: <scannerPath> <snippetFile>
// Capture all stdout output.
// Return the output as a string.
//
// Hint: use popen() / _popen() on Windows
// -------------------------------------------------------------------
static std::string runScanner(const std::string& scannerPath,
                               const std::string& snippetFile) {
    // TODO: implement
    (void)scannerPath; (void)snippetFile;
    return "";
}

// -------------------------------------------------------------------
// TODO: Implement evaluate()
//
// For a given snippet and scanner output:
//   TP = count of expectedCWEs that appear in output
//   FN = count of expectedCWEs that do NOT appear in output
//   FP = rough count of CWE strings in output that are NOT in expectedCWEs
//
// Print per-snippet results and return {tp, fn, fp}.
// -------------------------------------------------------------------
struct Score { int tp, fn, fp; };

static Score evaluate(const Snippet& s, const std::string& output) {
    // TODO: implement
    (void)s; (void)output;
    Score sc{0,0,0};
    return sc;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_ex01.exe>\n", argv[0]);
        return 1;
    }

    auto snippets = makeSnippets();
    int totalTP=0, totalFN=0, totalFP=0;

    for (auto& s : snippets) {
        printf("=== Snippet: %s ===\n", s.name.c_str());

        std::string tmpFile = writeSnippet(s);
        if (tmpFile.empty()) {
            printf("  ERROR: failed to write snippet\n\n");
            continue;
        }

        std::string output = runScanner(argv[1], tmpFile);
        if (output.empty()) {
            printf("  ERROR: scanner produced no output\n\n");
            remove(tmpFile.c_str());
            continue;
        }

        Score sc = evaluate(s, output);
        totalTP += sc.tp;
        totalFN += sc.fn;
        totalFP += sc.fp;

        printf("  TP=%d  FN=%d  FP=%d\n\n", sc.tp, sc.fn, sc.fp);
        remove(tmpFile.c_str());
    }

    int total = totalTP + totalFN;
    printf("=== Overall Results ===\n");
    printf("  True Positives : %d\n", totalTP);
    printf("  False Negatives: %d\n", totalFN);
    printf("  False Positives: %d (approximate)\n", totalFP);
    if (total > 0)
        printf("  Detection Rate : %.0f%%\n", 100.0 * totalTP / total);

    return 0;
}
