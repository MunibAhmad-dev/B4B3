// exercise_01_pattern_scanner.cpp
// Module 36 — SAST Tool, Exercise 1
//
// Goal: Read a C/C++ source file line by line, scan for dangerous function calls,
//       and report findings in the format: filename:line:[SEVERITY] CWE-XXX: description
//
// Compile: g++ -std=c++17 -Wall -o ex01.exe exercise_01_pattern_scanner.cpp
// Run:     ex01.exe <source_file.c>
//
// Functions to detect (minimum set):
//   gets(          HIGH    CWE-120  no bounds checking at all
//   strcpy(        MEDIUM  CWE-120  no bounds checking
//   strcat(        MEDIUM  CWE-120  no bounds checking
//   sprintf(       MEDIUM  CWE-120  no bounds checking on format output
//   strncpy(       LOW     CWE-120  common off-by-one; does not null-terminate if truncated
//   system(        HIGH    CWE-78   command injection if argument is user-controlled
//
// Output example:
//   test.c:14:[HIGH] CWE-120: gets() has no bounds checking — use fgets() instead
//   test.c:22:[MEDIUM] CWE-120: strcpy() has no bounds checking — use strncpy() or strlcpy()

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

struct Finding {
    std::string filename;
    int         line;
    std::string severity;   // "HIGH", "MEDIUM", "LOW"
    std::string cwe;        // e.g. "CWE-120"
    std::string message;
    std::string snippet;    // the offending line (trimmed)
};

// -------------------------------------------------------------------
// TODO: Implement checkLine()
//
// Parameters:
//   filename  — source file path (for output)
//   lineNum   — 1-based line number
//   line      — the raw source line
//   findings  — append any new Finding objects here
//
// Checks to implement (use strstr() or std::string::find()):
//   1. "gets("        HIGH   CWE-120  "gets() has no bounds checking — use fgets() instead"
//   2. "strcpy("      MEDIUM CWE-120  "strcpy() has no bounds checking — use strncpy() or strlcpy()"
//   3. "strcat("      MEDIUM CWE-120  "strcat() has no bounds checking — use strncat()"
//   4. "sprintf("     MEDIUM CWE-120  "sprintf() can overflow destination buffer — use snprintf()"
//   5. "vsprintf("    MEDIUM CWE-120  "vsprintf() can overflow destination buffer — use vsnprintf()"
//   6. "strncpy("     LOW    CWE-120  "strncpy() may not null-terminate if truncated"
//   7. "system("      HIGH   CWE-78   "system() executes shell command — command injection risk"
//   8. "popen("       HIGH   CWE-78   "popen() executes shell command — command injection risk"
//
// Tips:
//   - A very basic approach: just use line.find("gets(") != std::string::npos
//   - Skip lines that start with "//" (single-line comments) — reduces false positives
//   - Do NOT skip a line just because it contains "//"; only skip if "//" comes before
//     the pattern on the same line
//   - A line might trigger multiple patterns
// -------------------------------------------------------------------
static void checkLine(const std::string& filename, int lineNum,
                      const std::string& line, std::vector<Finding>& findings) {
    // TODO: implement
    (void)filename; (void)lineNum; (void)line; (void)findings;
}

// Helper: trim leading whitespace
static std::string trimLeft(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && (s[i]==' '||s[i]=='\t')) i++;
    return s.substr(i);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <source_file.c>\n", argv[0]);
        return 1;
    }

    std::ifstream in(argv[1]);
    if (!in) {
        fprintf(stderr, "Cannot open: %s\n", argv[1]);
        return 1;
    }

    std::vector<Finding> findings;
    std::string line;
    int lineNum = 0;

    while (std::getline(in, line)) {
        lineNum++;
        checkLine(argv[1], lineNum, line, findings);
    }

    // Print findings
    if (findings.empty()) {
        printf("No issues found in: %s\n", argv[1]);
        return 0;
    }

    for (const auto& f : findings) {
        printf("%s:%d:[%s] %s: %s\n",
               f.filename.c_str(), f.line,
               f.severity.c_str(), f.cwe.c_str(),
               f.message.c_str());
        if (!f.snippet.empty())
            printf("  > %s\n", f.snippet.c_str());
    }

    printf("\n%zu finding(s) in %s\n", findings.size(), argv[1]);
    return 0;
}
