// exercise_02_taint_tracker.cpp
// Module 36 — SAST Tool, Exercise 2
//
// Goal: Two-pass taint tracker.
//       Pass 1: find variables that receive tainted (user-controlled) input.
//       Pass 2: flag when those variables appear in dangerous sinks.
//
// Compile: g++ -std=c++17 -Wall -o ex02.exe exercise_02_taint_tracker.cpp
// Run:     ex02.exe <source_file.c>
//
// Example:
//   char* cmd = argv[1];          // Pass 1: mark "cmd" as tainted
//   system(cmd);                  // Pass 2: tainted variable in sink → report
//
// Taint sources to detect:
//   argv[           -- char* var = argv[N]
//   getenv(         -- char* var = getenv(...)
//   fgets(          -- fgets(var, ...) — first argument is tainted
//   recv(           -- recv(sock, var, ...) — second argument is tainted
//   scanf(          -- scanf(fmt, &var) — arguments after fmt are tainted
//
// Sinks to check:
//   system(         -- OS command execution
//   popen(          -- OS command execution
//   execve/execl/execlp/execvp  -- process creation
//   mysql_query(    -- SQL injection
//   sqlite3_exec(   -- SQL injection
//   fopen(          -- path traversal

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <iostream>
#include <regex>

struct TaintFinding {
    int         line;
    std::string variable;
    std::string sink;
    std::string snippet;
};

// -------------------------------------------------------------------
// TODO: Implement pass1_findTaintedVars()
//
// Read all lines and return a set of variable names that receive tainted input.
//
// Heuristic patterns (regex or strstr-based):
//
//   Pattern A — assignment from argv:
//     char* VAR = argv[
//     const char* VAR = argv[
//     Extract VAR as the variable name.
//
//   Pattern B — assignment from getenv:
//     char* VAR = getenv(
//     Extract VAR.
//
//   Pattern C — fgets into a buffer:
//     fgets(VAR,
//     Extract VAR as the first argument.
//
//   Pattern D — recv into a buffer:
//     recv(sock, VAR,
//     Extract second argument as VAR.
//
//   Pattern E — scanf result:
//     scanf(fmt, &VAR)  or  scanf(fmt, VAR)
//     Extract arguments after the format string.
//
// For this exercise, implement at least Pattern A and B using std::regex or
// simple string operations. Patterns C-E are optional extras.
//
// Returns: set of variable name strings found to be tainted.
// -------------------------------------------------------------------
static std::set<std::string> pass1_findTaintedVars(
        const std::vector<std::string>& lines) {
    std::set<std::string> tainted;
    // TODO: implement
    (void)lines;
    return tainted;
}

// -------------------------------------------------------------------
// TODO: Implement pass2_findSinks()
//
// For each line, check if any tainted variable name appears within a
// dangerous sink call. A simple approach:
//
//   For each line:
//     For each taintedVar in the tainted set:
//       If line contains taintedVar AND line contains a sink keyword:
//         Record a finding.
//
// Sinks to check (as substrings):
//   "system(", "popen(", "execve(", "execl(", "execvp(", "execlp(",
//   "mysql_query(", "sqlite3_exec(", "fopen("
//
// Output format:
//   "line N: tainted variable 'VAR' flows into sink 'SINK' — CWE-78\n"
//   (use CWE-78 for command injection, CWE-89 for SQL, CWE-22 for fopen)
// -------------------------------------------------------------------
static std::vector<TaintFinding> pass2_findSinks(
        const std::vector<std::string>& lines,
        const std::set<std::string>& tainted) {
    std::vector<TaintFinding> findings;
    // TODO: implement
    (void)lines; (void)tainted;
    return findings;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <source_file.c>\n", argv[0]);
        return 1;
    }

    std::ifstream in(argv[1]);
    if (!in) { fprintf(stderr, "Cannot open: %s\n", argv[1]); return 1; }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);

    // Pass 1: find tainted variables
    auto tainted = pass1_findTaintedVars(lines);

    if (tainted.empty()) {
        printf("Pass 1: No tainted variables detected.\n");
    } else {
        printf("Pass 1: Tainted variables detected:\n");
        for (auto& v : tainted)
            printf("  '%s'\n", v.c_str());
    }

    // Pass 2: find sinks
    auto findings = pass2_findSinks(lines, tainted);

    printf("\nPass 2: %zu taint flow(s) found:\n", findings.size());
    for (auto& f : findings) {
        printf("  line %d: tainted variable '%s' flows into sink '%s'\n",
               f.line, f.variable.c_str(), f.sink.c_str());
        if (!f.snippet.empty())
            printf("    > %s\n", f.snippet.c_str());
    }

    if (findings.empty()) printf("  (none)\n");
    return 0;
}
