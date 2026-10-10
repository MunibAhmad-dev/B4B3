// sast_scanner.cpp — Self-contained SAST Scanner
// Module 36 — SAST Tool
//
// Detects 28 vulnerability patterns in 8 categories across C/C++ source.
// No external dependencies.
//
// Usage:
//   sast_scanner.exe <file.c>                  -- scan one file
//   sast_scanner.exe --dir <src_dir>           -- scan all .c/.cpp/.h recursively
//   sast_scanner.exe --format json             -- output JSON
//   sast_scanner.exe --format html -o out.html -- HTML report
//   sast_scanner.exe --severity HIGH           -- only show HIGH findings
//
// Compile: g++ -std=c++17 -Wall -o sast_scanner.exe sast_scanner.cpp

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>
#include <windows.h>

// =====================================================================
// Data types
// =====================================================================

struct Finding {
    std::string file;
    int         line;
    int         col;        // 1-based column (approximate)
    std::string cwe;
    std::string severity;   // HIGH / MEDIUM / LOW
    std::string category;   // "Buffer Overflow", "Format String", ...
    std::string message;
    std::string snippet;    // offending source line (trimmed)
};

// =====================================================================
// Utility
// =====================================================================

static std::string trim(const std::string& s) {
    size_t i = s.find_first_not_of(" \t\r\n");
    if (i == std::string::npos) return "";
    size_t j = s.find_last_not_of(" \t\r\n");
    return s.substr(i, j-i+1);
}

// JSON-escape a string
static std::string jsonEsc(const std::string& s) {
    std::string r;
    for (char c : s) {
        if      (c=='"')  r += "\\\"";
        else if (c=='\\') r += "\\\\";
        else if (c=='\n') r += "\\n";
        else if (c=='\r') r += "\\r";
        else if (c=='\t') r += "\\t";
        else              r += c;
    }
    return r;
}

static std::string htmlEsc(const std::string& s) {
    std::string r;
    for (char c : s) {
        if      (c=='<') r += "&lt;";
        else if (c=='>') r += "&gt;";
        else if (c=='&') r += "&amp;";
        else if (c=='"') r += "&quot;";
        else             r += c;
    }
    return r;
}

// Return the part of the line before any // comment that is not inside a string
static std::string codeOnly(const std::string& line) {
    bool inStr = false;
    for (size_t i=0; i+1<line.size(); i++) {
        if (line[i]=='\\' && inStr) { i++; continue; }
        if (line[i]=='"') { inStr = !inStr; continue; }
        if (!inStr && line[i]=='/' && line[i+1]=='/') return line.substr(0,i);
    }
    return line;
}

// Check if pattern appears in code (not inside string literal or comment)
static bool inCode(const std::string& line, const std::string& pat) {
    std::string code = codeOnly(line);
    size_t pos = code.find(pat);
    if (pos == std::string::npos) return false;
    int q = 0;
    for (size_t i=0; i<pos; i++) {
        if (code[i]=='\\') { i++; continue; }
        if (code[i]=='"') q++;
    }
    return (q % 2 == 0);
}

// Approximate column: find first occurrence in raw line
static int findCol(const std::string& line, const std::string& pat) {
    size_t p = line.find(pat);
    return (p == std::string::npos) ? 1 : (int)(p+1);
}

// =====================================================================
// Pattern definitions
// =====================================================================

struct Pattern {
    const char* category;
    const char* cwe;
    const char* severity;
    const char* keyword;       // simple substring to match
    const char* regexStr;      // regex (used if keyword is nullptr)
    const char* message;
};

// 28 patterns across 8 categories
static const Pattern PATTERNS[] = {
    // --- 1. Buffer Overflow (CWE-120) ---
    {"Buffer Overflow", "CWE-120", "HIGH",
     "gets(",   nullptr,
     "gets() has no bounds checking — replace with fgets(buf, sizeof(buf), stdin)"},

    {"Buffer Overflow", "CWE-120", "MEDIUM",
     "strcpy(", nullptr,
     "strcpy() has no bounds checking — use strncpy() or strlcpy()"},

    {"Buffer Overflow", "CWE-120", "MEDIUM",
     "strcat(", nullptr,
     "strcat() has no bounds checking — use strncat(dst, src, sizeof(dst)-strlen(dst)-1)"},

    {"Buffer Overflow", "CWE-120", "MEDIUM",
     "sprintf(", nullptr,
     "sprintf() can overflow destination buffer — use snprintf()"},

    {"Buffer Overflow", "CWE-120", "MEDIUM",
     "vsprintf(", nullptr,
     "vsprintf() can overflow destination buffer — use vsnprintf()"},

    {"Buffer Overflow", "CWE-120", "LOW",
     "strncpy(", nullptr,
     "strncpy() does not null-terminate if src length >= n — add manual null termination"},

    {"Buffer Overflow", "CWE-120", "MEDIUM",
     nullptr,
     R"(\bscanf\s*\([^)]*%[^0-9"'n][^)]*s[^)]*\))",
     "scanf with unbound %s — specify field width (e.g., %63s)"},

    // --- 2. Format String (CWE-134) ---
    {"Format String", "CWE-134", "HIGH",
     nullptr,
     R"(\b(printf|fprintf|dprintf|syslog|err|errx|warn|warnx)\s*\(\s*(?!\"))",
     "printf-family function with non-literal first format argument — format string injection"},

    {"Format String", "CWE-134", "HIGH",
     nullptr,
     R"(\bvprintf\s*\(\s*(?!\"))",
     "vprintf with non-literal format argument — format string injection"},

    // --- 3. Command Injection (CWE-78) ---
    {"Command Injection", "CWE-78", "HIGH",
     "system(", nullptr,
     "system() passes argument to shell — use execv() with explicit argument array"},

    {"Command Injection", "CWE-78", "HIGH",
     "popen(", nullptr,
     "popen() executes shell command — validate and sanitize argument"},

    {"Command Injection", "CWE-78", "MEDIUM",
     "execve(", nullptr,
     "execve() process creation — ensure no user-controlled arguments without validation"},

    {"Command Injection", "CWE-78", "MEDIUM",
     "execl(", nullptr,
     "execl() process creation — ensure no user-controlled path or arguments"},

    {"Command Injection", "CWE-78", "MEDIUM",
     "execlp(", nullptr,
     "execlp() searches PATH — use execve() with absolute path"},

    {"Command Injection", "CWE-78", "MEDIUM",
     "execvp(", nullptr,
     "execvp() searches PATH — use execve() with absolute path"},

    // --- 4. SQL Injection (CWE-89) ---
    {"SQL Injection", "CWE-89", "HIGH",
     nullptr,
     R"(\b(sprintf|snprintf|strcat|strcpy)\s*\([^;]*SELECT\s)",
     "SQL query constructed with string function — use parameterized queries"},

    {"SQL Injection", "CWE-89", "MEDIUM",
     "mysql_query(", nullptr,
     "mysql_query() — verify query is not built from user input"},

    {"SQL Injection", "CWE-89", "MEDIUM",
     "sqlite3_exec(", nullptr,
     "sqlite3_exec() — verify query is not built from user input"},

    // --- 5. Path Traversal (CWE-22) ---
    {"Path Traversal", "CWE-22", "MEDIUM",
     "fopen(", nullptr,
     "fopen() with user-supplied path — validate path, reject '..' components"},

    {"Path Traversal", "CWE-22", "MEDIUM",
     "CreateFileA(", nullptr,
     "CreateFileA() with user-supplied path — validate path before use"},

    {"Path Traversal", "CWE-22", "MEDIUM",
     "CreateFileW(", nullptr,
     "CreateFileW() with user-supplied path — validate path before use"},

    // --- 6. Hardcoded Credentials (CWE-798) ---
    {"Hardcoded Credentials", "CWE-798", "HIGH",
     nullptr,
     R"(\b(password|passwd|secret|api_key|apikey|token|auth_token|private_key)\s*=\s*\"[^\"]+\")",
     "Hardcoded credential — store in environment variable or secure vault"},

    {"Hardcoded Credentials", "CWE-798", "MEDIUM",
     nullptr,
     R"(\b(password|passwd|secret)\s*\[\s*\]\s*=\s*\")",
     "Hardcoded credential in array literal — use secure credential storage"},

    // --- 7. Use After Free (CWE-416) ---
    {"Use After Free", "CWE-416", "MEDIUM",
     "free(", nullptr,
     "free() call — ensure pointer is set to NULL and not used or freed again"},

    // --- 8. NULL Pointer Dereference (CWE-476) ---
    {"Null Dereference", "CWE-476", "LOW",
     "malloc(", nullptr,
     "malloc() return value — check for NULL before dereferencing"},

    {"Null Dereference", "CWE-476", "LOW",
     "calloc(", nullptr,
     "calloc() return value — check for NULL before dereferencing"},

    // --- Integer Issues (CWE-190/195) ---
    {"Integer Issue", "CWE-190", "MEDIUM",
     nullptr,
     R"(\(size_t\)\s*-|\(unsigned\)\s*-|\(uint\d+_t\)\s*-)",
     "Negative value cast to unsigned type — may produce unexpectedly large value"},

    {"Integer Issue", "CWE-195", "LOW",
     nullptr,
     R"(\(int\)\s*strlen\(|\(int\)\s*sizeof\()",
     "Narrowing cast from size_t to int — may truncate on large values"},

    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr} // terminator
};

// =====================================================================
// Scan one file
// =====================================================================

static std::vector<Finding> scanFile(const std::string& filePath,
                                      const std::string& minSeverity) {
    std::vector<Finding> findings;

    std::ifstream in(filePath);
    if (!in) return findings;

    // Build regex objects for regex patterns (only once per scan call)
    struct CompiledPattern {
        const Pattern* pat;
        std::regex re;
        bool hasRegex;
    };
    std::vector<CompiledPattern> compiled;
    for (int i=0; PATTERNS[i].category; i++) {
        CompiledPattern cp;
        cp.pat = &PATTERNS[i];
        cp.hasRegex = (PATTERNS[i].regexStr != nullptr);
        if (cp.hasRegex) {
            try {
                cp.re = std::regex(PATTERNS[i].regexStr,
                                   std::regex::icase | std::regex::optimize);
            } catch (...) {
                cp.hasRegex = false;
            }
        }
        compiled.push_back(std::move(cp));
    }

    auto sevRank = [](const std::string& s) {
        if (s=="HIGH") return 2; if (s=="MEDIUM") return 1; return 0;
    };
    int minRank = sevRank(minSeverity);

    std::string line;
    int lineNum = 0;

    // Track free() positions for UAF heuristic
    std::set<int> freeLines;

    while (std::getline(in, line)) {
        lineNum++;
        std::string code = codeOnly(line);
        std::string snip = trim(line);

        for (auto& cp : compiled) {
            const Pattern* p = cp.pat;

            // Severity filter
            std::string sev(p->severity);
            if (sevRank(sev) < minRank) continue;

            bool matched = false;

            if (!cp.hasRegex) {
                // Simple keyword match
                if (p->keyword && inCode(line, p->keyword)) matched = true;
            } else {
                // Regex match on code portion
                std::smatch m;
                if (std::regex_search(code, m, cp.re)) matched = true;
            }

            if (matched) {
                // Avoid exact duplicates (same file+line+cwe+message)
                bool dup = false;
                for (auto& f : findings)
                    if (f.line==lineNum && f.cwe==p->cwe && f.message==p->message) {
                        dup=true; break;
                    }
                if (dup) continue;

                int col = p->keyword ? findCol(line, p->keyword) : 1;
                findings.push_back({
                    filePath, lineNum, col,
                    std::string(p->cwe), sev,
                    std::string(p->category),
                    std::string(p->message),
                    snip
                });
            }
        }
    }

    return findings;
}

// =====================================================================
// Recursive directory scan (Windows)
// =====================================================================

static void scanDirRecursive(const std::string& dir,
                              const std::string& minSeverity,
                              std::vector<Finding>& allFindings) {
    std::string pattern = dir + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        std::string fullPath = dir + "\\" + name;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scanDirRecursive(fullPath, minSeverity, allFindings);
        } else {
            // Check extension
            size_t dot = name.rfind('.');
            if (dot != std::string::npos) {
                std::string ext = name.substr(dot+1);
                for (auto& c : ext) c = (char)tolower((unsigned char)c);
                if (ext=="c"||ext=="cpp"||ext=="cc"||ext=="cxx"||ext=="h"||ext=="hpp") {
                    auto f = scanFile(fullPath, minSeverity);
                    for (auto& fi : f) allFindings.push_back(fi);
                }
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

// =====================================================================
// Output: Text
// =====================================================================

static void outputText(const std::vector<Finding>& findings, FILE* out) {
    for (auto& f : findings) {
        fprintf(out, "%s:%d:%d: [%s] %s: %s\n",
                f.file.c_str(), f.line, f.col,
                f.severity.c_str(), f.cwe.c_str(), f.message.c_str());
        if (!f.snippet.empty())
            fprintf(out, "  > %s\n", f.snippet.c_str());
    }

    // Summary
    int h=0,m=0,l=0;
    for (auto& f : findings) {
        if (f.severity=="HIGH") h++;
        else if (f.severity=="MEDIUM") m++;
        else l++;
    }
    std::set<std::string> files;
    for (auto& f : findings) files.insert(f.file);

    fprintf(out, "\n--- SAST Summary ---\n");
    fprintf(out, "  Files scanned  : %zu\n", files.size());
    fprintf(out, "  Total findings : %zu\n", findings.size());
    fprintf(out, "  HIGH           : %d\n", h);
    fprintf(out, "  MEDIUM         : %d\n", m);
    fprintf(out, "  LOW            : %d\n", l);

    // Top categories
    struct CatCount { std::string cat; int count; };
    std::vector<CatCount> cats;
    for (auto& f : findings) {
        bool found=false;
        for (auto& c : cats) if (c.cat==f.category) { c.count++; found=true; break; }
        if (!found) cats.push_back({f.category,1});
    }
    std::sort(cats.begin(),cats.end(),[](auto& a,auto& b){return a.count>b.count;});
    if (!cats.empty()) {
        fprintf(out, "\nTop Categories:\n");
        for (auto& c : cats) fprintf(out, "  %-30s : %d\n", c.cat.c_str(), c.count);
    }
}

// =====================================================================
// Output: JSON
// =====================================================================

static void outputJSON(const std::vector<Finding>& findings, FILE* out) {
    fprintf(out, "{\n");
    fprintf(out, "  \"tool\": \"sast_scanner\",\n");
    fprintf(out, "  \"version\": \"1.0\",\n");
    fprintf(out, "  \"total\": %zu,\n", findings.size());
    fprintf(out, "  \"findings\": [\n");
    for (size_t i=0;i<findings.size();i++) {
        auto& f = findings[i];
        fprintf(out,
            "    {\n"
            "      \"file\"     : \"%s\",\n"
            "      \"line\"     : %d,\n"
            "      \"col\"      : %d,\n"
            "      \"cwe\"      : \"%s\",\n"
            "      \"severity\" : \"%s\",\n"
            "      \"category\" : \"%s\",\n"
            "      \"message\"  : \"%s\",\n"
            "      \"snippet\"  : \"%s\"\n"
            "    }%s\n",
            jsonEsc(f.file).c_str(), f.line, f.col,
            jsonEsc(f.cwe).c_str(),
            jsonEsc(f.severity).c_str(),
            jsonEsc(f.category).c_str(),
            jsonEsc(f.message).c_str(),
            jsonEsc(f.snippet).c_str(),
            (i+1<findings.size()) ? "," : "");
    }
    fprintf(out, "  ]\n}\n");
}

// =====================================================================
// Output: HTML
// =====================================================================

static void outputHTML(const std::vector<Finding>& findings, FILE* out) {
    int h=0,m=0,l=0;
    for (auto& f : findings) {
        if (f.severity=="HIGH") h++;
        else if (f.severity=="MEDIUM") m++;
        else l++;
    }

    fprintf(out, R"(<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>SAST Scanner Report</title>
<style>
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 2em; background: #f5f7f9; color: #1a1a2e; }
h1 { color: #16213e; margin-bottom: .3em; }
.meta { color: #555; font-size: .9em; margin-bottom: 1.5em; }
.stats { display: flex; gap: 1em; flex-wrap: wrap; margin-bottom: 1.5em; }
.stat { padding: .6em 1.4em; border-radius: 6px; font-size: 1.1em; font-weight: 700; color: #fff; }
.stat-H { background: #c0392b; } .stat-M { background: #d68910; }
.stat-L { background: #1a5276; } .stat-T { background: #2c3e50; }
table { width: 100%%; border-collapse: collapse; font-size: .88em; }
th { background: #2c3e50; color: #fff; padding: .5em .6em; text-align: left; }
tr:nth-child(even) { background: #eaf0fb; }
td { padding: .38em .6em; vertical-align: top; }
.sH { color: #c0392b; font-weight: 700; } .sM { color: #d68910; font-weight: 700; }
.sL { color: #1a5276; font-weight: 700; }
code { background: #e8e8e8; padding: .1em .3em; border-radius: 3px; font-size: .85em; font-family: monospace; }
.snip { font-family: monospace; background: #1e1e1e; color: #9cdcfe; padding: .15em .4em; border-radius: 4px; }
.cwe { font-family: monospace; font-size: .88em; color: #7b2fbe; }
</style></head><body>
<h1>SAST Scanner Report</h1>
)");

    fprintf(out, "<div class=\"meta\">Generated by sast_scanner | Total findings: %zu</div>\n",
            findings.size());
    fprintf(out,
        "<div class=\"stats\">\n"
        "  <div class=\"stat stat-H\">HIGH: %d</div>\n"
        "  <div class=\"stat stat-M\">MEDIUM: %d</div>\n"
        "  <div class=\"stat stat-L\">LOW: %d</div>\n"
        "  <div class=\"stat stat-T\">TOTAL: %zu</div>\n"
        "</div>\n", h, m, l, findings.size());

    fprintf(out,
        "<table>\n<tr>"
        "<th>#</th><th>File:Line</th><th>Severity</th><th>CWE</th>"
        "<th>Category</th><th>Message</th><th>Snippet</th>"
        "</tr>\n");

    int n=1;
    for (auto& f : findings) {
        std::string sc = f.severity=="HIGH" ? "sH" : f.severity=="MEDIUM" ? "sM" : "sL";
        fprintf(out,
            "<tr><td>%d</td>"
            "<td><code>%s:%d</code></td>"
            "<td class=\"%s\">%s</td>"
            "<td class=\"cwe\">%s</td>"
            "<td>%s</td>"
            "<td>%s</td>"
            "<td><span class=\"snip\">%s</span></td></tr>\n",
            n++,
            htmlEsc(f.file).c_str(), f.line,
            sc.c_str(), htmlEsc(f.severity).c_str(),
            htmlEsc(f.cwe).c_str(),
            htmlEsc(f.category).c_str(),
            htmlEsc(f.message).c_str(),
            htmlEsc(f.snippet).c_str());
    }
    fprintf(out, "</table>\n</body></html>\n");
}

// =====================================================================
// Entry point
// =====================================================================

static void usage(const char* prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s <file.c>                     -- scan one file\n"
        "  %s --dir <directory>            -- scan directory recursively\n"
        "  %s --format [text|json|html]    -- output format (default: text)\n"
        "  %s -o <output_file>             -- write to file\n"
        "  %s --severity [HIGH|MEDIUM|LOW] -- minimum severity filter\n"
        "  %s -v                           -- verbose (print each file scanned)\n",
        prog,prog,prog,prog,prog,prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char* format       = "text";
    const char* outPath      = nullptr;
    const char* dirPath      = nullptr;
    const char* singleFile   = nullptr;
    const char* minSeverity  = "LOW";
    bool verbose             = false;

    for (int i=1; i<argc; i++) {
        if      (strcmp(argv[i],"--format")==0 && i+1<argc)   format      = argv[++i];
        else if (strcmp(argv[i],"-o")==0 && i+1<argc)         outPath     = argv[++i];
        else if (strcmp(argv[i],"--dir")==0 && i+1<argc)      dirPath     = argv[++i];
        else if (strcmp(argv[i],"--severity")==0 && i+1<argc) minSeverity = argv[++i];
        else if (strcmp(argv[i],"-v")==0)                      verbose     = true;
        else if (argv[i][0] != '-')                            singleFile  = argv[i];
    }

    if (!singleFile && !dirPath) {
        fprintf(stderr, "ERROR: specify a file or --dir <directory>\n");
        usage(argv[0]); return 1;
    }

    std::vector<Finding> allFindings;

    if (singleFile) {
        if (verbose) fprintf(stderr, "Scanning: %s\n", singleFile);
        auto f = scanFile(singleFile, minSeverity);
        for (auto& fi : f) allFindings.push_back(fi);
    } else {
        if (verbose) fprintf(stderr, "Scanning directory: %s\n", dirPath);
        scanDirRecursive(dirPath, minSeverity, allFindings);
    }

    // Sort: severity DESC, then file, then line
    std::sort(allFindings.begin(), allFindings.end(), [](const Finding& a, const Finding& b) {
        auto r = [](const std::string& s) { return s=="HIGH"?2:s=="MEDIUM"?1:0; };
        if (r(a.severity) != r(b.severity)) return r(a.severity) > r(b.severity);
        if (a.file != b.file) return a.file < b.file;
        return a.line < b.line;
    });

    FILE* out = stdout;
    if (outPath) {
        out = fopen(outPath, "w");
        if (!out) { perror("fopen output"); return 1; }
    }

    if      (strcmp(format,"json")==0) outputJSON(allFindings, out);
    else if (strcmp(format,"html")==0) outputHTML(allFindings, out);
    else                               outputText(allFindings, out);

    if (outPath) {
        fclose(out);
        fprintf(stderr, "Report written to: %s\n", outPath);
    }

    // Exit code: 1 if any HIGH findings
    for (auto& f : allFindings) if (f.severity=="HIGH") return 1;
    return 0;
}
