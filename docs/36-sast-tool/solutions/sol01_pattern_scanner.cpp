// solutions/sol01_pattern_scanner.cpp
// Module 36 — SAST Tool, Solution 1
//
// Complete regex-based pattern scanner. Detects 20+ vulnerability patterns.
// Output: filename:line: [SEVERITY] CWE-XXX: description — snippet
//
// Compile: g++ -std=c++17 -Wall -o sol01.exe sol01_pattern_scanner.cpp
// Run:     sol01.exe <source.c>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <regex>
#include <fstream>
#include <algorithm>
#include <cctype>

struct Finding {
    std::string filename;
    int         line;
    std::string severity;
    std::string cwe;
    std::string message;
    std::string snippet;
};

// Trim leading whitespace
static std::string trim(const std::string& s) {
    size_t i = s.find_first_not_of(" \t\r\n");
    return (i == std::string::npos) ? "" : s.substr(i);
}

// Return the position of // that is not inside a string literal
// Returns npos if no such comment start found
static size_t findLineComment(const std::string& s) {
    bool inStr = false;
    for (size_t i = 0; i + 1 < s.size(); i++) {
        if (s[i] == '\\' && inStr) { i++; continue; }
        if (s[i] == '"') { inStr = !inStr; continue; }
        if (!inStr && s[i] == '/' && s[i+1] == '/') return i;
    }
    return std::string::npos;
}

// Return substring of line before any // comment
static std::string codeOnly(const std::string& line) {
    size_t cmt = findLineComment(line);
    if (cmt == std::string::npos) return line;
    return line.substr(0, cmt);
}

// Check if `pattern` appears in `line` before any line comment,
// and not purely inside a string literal (basic heuristic: count quotes before match)
static bool appearsInCode(const std::string& line, const std::string& pattern) {
    std::string code = codeOnly(line);
    size_t pos = code.find(pattern);
    if (pos == std::string::npos) return false;
    // Count unescaped quotes before the match position
    int quotes = 0;
    for (size_t i = 0; i < pos; i++) {
        if (code[i] == '\\') { i++; continue; }
        if (code[i] == '"') quotes++;
    }
    return (quotes % 2 == 0);  // even quotes = not inside a string literal
}

// Check if `pattern` appears after a line comment (in comment text)
static bool onlyInComment(const std::string& line, const std::string& pattern) {
    if (!appearsInCode(line, pattern)) {
        return line.find(pattern) != std::string::npos;
    }
    return false;
}

static void addFinding(std::vector<Finding>& out, const std::string& filename,
                       int lineNum, const std::string& sev, const std::string& cwe,
                       const std::string& msg, const std::string& snippet) {
    out.push_back({filename, lineNum, sev, cwe, msg, trim(snippet)});
}

// Check a single line for all known patterns
static void checkLine(const std::string& filename, int lineNum,
                      const std::string& line, std::vector<Finding>& findings) {
    auto add = [&](const char* sev, const char* cwe, const char* msg) {
        addFinding(findings, filename, lineNum, sev, cwe, msg, line);
    };

    // --- Buffer overflow (CWE-120) ---
    if (appearsInCode(line, "gets("))
        add("HIGH", "CWE-120",
            "gets() has no bounds checking — replace with fgets(buf,sizeof(buf),stdin)");

    if (appearsInCode(line, "strcpy("))
        add("MEDIUM", "CWE-120",
            "strcpy() has no bounds checking — use strncpy() or strlcpy()");

    if (appearsInCode(line, "strcat("))
        add("MEDIUM", "CWE-120",
            "strcat() has no bounds checking — use strncat(dst, src, sizeof(dst)-strlen(dst)-1)");

    if (appearsInCode(line, "sprintf("))
        add("MEDIUM", "CWE-120",
            "sprintf() can overflow destination buffer — use snprintf()");

    if (appearsInCode(line, "vsprintf("))
        add("MEDIUM", "CWE-120",
            "vsprintf() can overflow destination buffer — use vsnprintf()");

    if (appearsInCode(line, "strncpy("))
        add("LOW", "CWE-120",
            "strncpy() does not null-terminate if src >= n — ensure manual null termination");

    // scanf without width specifier: look for %s without a width number
    if (appearsInCode(line, "scanf(")) {
        // Check for unbound %s: "%s" without a preceding number like "%64s"
        static const std::regex unboundS(R"(%[^0-9"]*s)");
        std::string code = codeOnly(line);
        std::smatch m;
        if (std::regex_search(code, m, unboundS))
            add("MEDIUM", "CWE-120",
                "scanf with unbound %s — specify width e.g. %63s");
    }

    // --- Format string (CWE-134) ---
    // printf/fprintf/syslog where first format arg looks like a variable (not a literal)
    // Heuristic: printf( immediately followed by a non-quote non-space token
    {
        static const std::regex fmtNoLiteral(
            R"(\b(printf|fprintf|syslog|dprintf|err|errx|warn|warnx)\s*\(\s*(?!\"|\s*stderr|\s*stdout)[^,\);])");
        std::string code = codeOnly(line);
        std::smatch m;
        if (std::regex_search(code, m, fmtNoLiteral)) {
            std::string fn = m[1].str();
            add("HIGH", "CWE-134",
                fn + "() called with non-literal format argument — format string injection risk");
        }
    }

    // --- Command injection (CWE-78) ---
    if (appearsInCode(line, "system("))
        add("HIGH", "CWE-78",
            "system() executes a shell command — use execv() with argument array instead");

    if (appearsInCode(line, "popen("))
        add("HIGH", "CWE-78",
            "popen() executes a shell command — validate all arguments");

    if (appearsInCode(line, "execve(") || appearsInCode(line, "execl(") ||
        appearsInCode(line, "execlp(") || appearsInCode(line, "execvp("))
        add("MEDIUM", "CWE-78",
            "exec*() process creation — ensure arguments are not user-controlled without validation");

    // --- NULL pointer dereference (CWE-476) ---
    // malloc result assigned then immediately used on next line without NULL check
    // (multi-line tracking is limited in a single-line scanner; flag the malloc call)
    if (appearsInCode(line, "malloc(") &&
        line.find("if") == std::string::npos &&
        line.find("!= NULL") == std::string::npos &&
        line.find("== NULL") == std::string::npos)
        add("LOW", "CWE-476",
            "malloc() return value — check for NULL before dereferencing");

    // --- Use-after-free (CWE-416) --- very basic: free( on a line by itself
    if (appearsInCode(line, "free("))
        add("LOW", "CWE-416",
            "free() call — ensure the pointer is not used or freed again after this point");

    // --- Hardcoded credentials (CWE-798) ---
    {
        static const std::regex cred(
            R"(\b(password|passwd|secret|api_key|apikey|token|auth_token|private_key)\s*=\s*\"[^\"]+\")",
            std::regex::icase);
        std::string code = codeOnly(line);
        std::smatch m;
        if (std::regex_search(code, m, cred))
            add("HIGH", "CWE-798",
                "Hardcoded credential detected — load from environment variable or secure vault");
    }

    // --- SQL injection (CWE-89) ---
    // sprintf building a query with %s or string concatenation
    if ((appearsInCode(line, "sprintf(") || appearsInCode(line, "snprintf(")) &&
         appearsInCode(line, "SELECT ") && appearsInCode(line, "%"))
        add("HIGH", "CWE-89",
            "SQL query constructed with sprintf + user input — use parameterized queries");

    // mysql_query / sqlite3_exec with a variable argument
    if (appearsInCode(line, "mysql_query(") || appearsInCode(line, "sqlite3_exec("))
        add("MEDIUM", "CWE-89",
            "SQL execution function — verify the query string is not user-controlled");

    // --- Integer issues (CWE-190/195) ---
    // Cast of signed integer to size_t / unsigned
    {
        static const std::regex intCast(
            R"(\(size_t\)\s*\-|\(unsigned\s+int\)\s*\-|\(uint\d+_t\)\s*\-)");
        std::string code = codeOnly(line);
        if (std::regex_search(code, intCast))
            add("MEDIUM", "CWE-190",
                "Signed value cast to unsigned/size_t — negative value becomes large positive");
    }

    // --- Path traversal (CWE-22) ---
    // fopen with a variable that may contain "../"
    if (appearsInCode(line, "fopen(") || appearsInCode(line, "CreateFileA(") ||
        appearsInCode(line, "CreateFileW("))
        add("LOW", "CWE-22",
            "File open call — validate path does not contain traversal sequences like ../");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <source.c>\n", argv[0]);
        return 1;
    }

    std::ifstream in(argv[1]);
    if (!in) { fprintf(stderr, "Cannot open: %s\n", argv[1]); return 1; }

    std::vector<Finding> findings;
    std::string line;
    int lineNum = 0;

    while (std::getline(in, line)) {
        lineNum++;
        checkLine(argv[1], lineNum, line, findings);
    }

    if (findings.empty()) {
        printf("No issues found in: %s\n", argv[1]);
        return 0;
    }

    for (const auto& f : findings) {
        printf("%s:%d: [%s] %s: %s\n",
               f.filename.c_str(), f.line,
               f.severity.c_str(), f.cwe.c_str(), f.message.c_str());
        if (!f.snippet.empty())
            printf("  > %s\n", f.snippet.c_str());
    }

    int high=0, med=0, low=0;
    for (auto& f : findings) {
        if      (f.severity=="HIGH")   high++;
        else if (f.severity=="MEDIUM") med++;
        else                           low++;
    }

    printf("\n--- Summary: %zu finding(s) ---\n", findings.size());
    printf("  HIGH  : %d\n", high);
    printf("  MEDIUM: %d\n", med);
    printf("  LOW   : %d\n", low);

    return 0;
}
