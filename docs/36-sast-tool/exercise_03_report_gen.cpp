// exercise_03_report_gen.cpp
// Module 36 — SAST Tool, Exercise 3
//
// Goal: Given a list of findings, produce formatted output:
//       (1) a text table summary
//       (2) a JSON array
//
// Compile: g++ -std=c++17 -Wall -o ex03.exe exercise_03_report_gen.cpp
// Run:     ex03.exe
//          (uses hard-coded sample findings for testing)
//
// A finding has: file, line, cwe, severity, message, snippet (1-line context)

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

struct Finding {
    std::string file;
    int         line;
    std::string cwe;         // e.g. "CWE-120"
    std::string severity;    // "HIGH", "MEDIUM", "LOW"
    std::string message;
    std::string snippet;     // source line context
    std::string remediation; // how to fix
};

// Sample findings for testing — do not modify
static std::vector<Finding> sampleFindings() {
    return {
        {"src/main.c",   14, "CWE-120", "HIGH",   "gets() has no bounds checking",
         "    gets(inputBuffer);",
         "Replace gets() with fgets(inputBuffer, sizeof(inputBuffer), stdin)"},

        {"src/main.c",   27, "CWE-78",  "HIGH",   "system() with user-controlled argument",
         "    system(userCmd);",
         "Validate and sanitize command before passing to system(); prefer execv() with arg array"},

        {"src/parser.c", 88, "CWE-120", "MEDIUM", "strcpy() has no bounds checking",
         "    strcpy(dest, src);",
         "Use strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1]=0; or strlcpy()"},

        {"src/auth.c",  112, "CWE-798", "HIGH",   "Hardcoded password literal",
         "    if (strcmp(pass, \"admin123\") == 0)",
         "Load credentials from environment variable or encrypted config file"},

        {"src/net.c",    55, "CWE-134", "MEDIUM", "printf with non-literal format argument",
         "    printf(userMsg);",
         "Always use printf(\"%s\", userMsg) — never printf(userMsg)"},

        {"src/db.c",     73, "CWE-89",  "HIGH",   "SQL injection risk in query construction",
         "    sprintf(query, \"SELECT * FROM users WHERE name='%s'\", input);",
         "Use parameterized queries / prepared statements"},

        {"src/file.c",   31, "CWE-22",  "MEDIUM", "fopen with user-supplied path",
         "    fopen(filePath, \"r\");",
         "Validate path: reject '..' components, restrict to allowed directory"},
    };
}

// -------------------------------------------------------------------
// TODO: Implement printTextTable()
//
// Print a human-readable summary table with:
//   - A header row
//   - One row per finding: File:Line | Severity | CWE | Message (truncated to 40 chars)
//   - Horizontal separator lines
//   - Footer: count per severity (HIGH: N, MEDIUM: N, LOW: N)
//
// Example:
//   +-----------------+--------+---------+------------------------------------------+
//   | File:Line       | SEVER  | CWE     | Message                                  |
//   +-----------------+--------+---------+------------------------------------------+
//   | src/main.c:14   | HIGH   | CWE-120 | gets() has no bounds checking            |
//   ...
// -------------------------------------------------------------------
static void printTextTable(const std::vector<Finding>& findings) {
    // TODO: implement
    (void)findings;
    printf("TODO: implement printTextTable\n");
}

// -------------------------------------------------------------------
// TODO: Implement printJSON()
//
// Produce a JSON array of finding objects:
// [
//   {
//     "file": "src/main.c",
//     "line": 14,
//     "cwe": "CWE-120",
//     "severity": "HIGH",
//     "message": "gets() has no bounds checking",
//     "snippet": "    gets(inputBuffer);",
//     "remediation": "Replace gets() with fgets(...)"
//   },
//   ...
// ]
//
// Hint: escape backslashes and double-quotes in string values.
// A helper function escapeJSON(s) is useful:
//   for each char: if '"' output '\"', if '\\' output '\\\\', else output as-is
// -------------------------------------------------------------------
static void printJSON(const std::vector<Finding>& findings) {
    // TODO: implement
    (void)findings;
    printf("TODO: implement printJSON\n");
}

// -------------------------------------------------------------------
// TODO (BONUS): Implement printRemediation()
//
// For each HIGH severity finding, print:
//   [HIGH] File:Line — Message
//   Remediation: ...
// Sort by severity (HIGH first), then by file+line.
// -------------------------------------------------------------------
static void printRemediation(const std::vector<Finding>& findings) {
    // TODO: implement (bonus)
    (void)findings;
}

int main(int argc, char* argv[]) {
    auto findings = sampleFindings();

    const char* format = "table";  // default
    if (argc >= 2) format = argv[1];

    if (strcmp(format, "table") == 0) {
        printTextTable(findings);
    } else if (strcmp(format, "json") == 0) {
        printJSON(findings);
    } else if (strcmp(format, "remediation") == 0) {
        printRemediation(findings);
    } else {
        fprintf(stderr, "Usage: %s [table|json|remediation]\n", argv[0]);
        return 1;
    }

    return 0;
}
