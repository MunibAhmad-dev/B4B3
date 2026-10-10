// solutions/sol03_report_gen.cpp
// Module 36 — SAST Tool, Solution 3
//
// Complete report generator.
// Reads findings from stdin (format: file:line:cwe:severity:message)
// or uses embedded samples. Produces text, JSON, and HTML output.
//
// Compile: g++ -std=c++17 -Wall -o sol03.exe sol03_report_gen.cpp
// Run:     sol03.exe [--format text|json|html] [-o <output_file>] [input_file]
//          (no input file = use built-in samples)
//          echo "src/main.c:14:CWE-120:HIGH:gets() danger" | sol03.exe --format json

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cctype>

struct Finding {
    std::string file;
    int         line;
    std::string cwe;
    std::string severity;
    std::string message;
    std::string snippet;
    std::string remediation;
};

// Escape a string for JSON output
static std::string jsonEscape(const std::string& s) {
    std::string r;
    r.reserve(s.size() + 8);
    for (char c : s) {
        if      (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else if (c == '\t') r += "\\t";
        else                r += c;
    }
    return r;
}

// Escape a string for HTML
static std::string htmlEscape(const std::string& s) {
    std::string r;
    for (char c : s) {
        if      (c == '<')  r += "&lt;";
        else if (c == '>')  r += "&gt;";
        else if (c == '&')  r += "&amp;";
        else if (c == '"')  r += "&quot;";
        else                r += c;
    }
    return r;
}

// Severity color (for HTML/terminal)
static const char* severityColor(const std::string& sev) {
    if (sev == "HIGH")   return "#d73a4a";
    if (sev == "MEDIUM") return "#e36209";
    if (sev == "LOW")    return "#0075ca";
    return "#555555";
}

static const char* severityANSI(const std::string& sev) {
    if (sev == "HIGH")   return "\033[1;31m";  // bold red
    if (sev == "MEDIUM") return "\033[1;33m";  // bold yellow
    if (sev == "LOW")    return "\033[1;34m";  // bold blue
    return "\033[0m";
}

// =====================================================================
// Text table
// =====================================================================

static void printTextTable(const std::vector<Finding>& findings, FILE* out) {
    const int COL_FILE = 22, COL_SEV = 7, COL_CWE = 9, COL_MSG = 42;

    auto hline = [&]() {
        fprintf(out, "+-%s-+-%s-+-%s-+-%s-+\n",
            std::string(COL_FILE,'-').c_str(),
            std::string(COL_SEV,'-').c_str(),
            std::string(COL_CWE,'-').c_str(),
            std::string(COL_MSG,'-').c_str());
    };

    auto pad = [](const std::string& s, int w) -> std::string {
        if ((int)s.size() >= w) return s.substr(0, w-1) + "~";
        return s + std::string(w - s.size(), ' ');
    };

    hline();
    fprintf(out, "| %s | %s | %s | %s |\n",
        pad("File:Line",    COL_FILE).c_str(),
        pad("Sev",          COL_SEV).c_str(),
        pad("CWE",          COL_CWE).c_str(),
        pad("Message",      COL_MSG).c_str());
    hline();

    int high=0, med=0, low=0;
    for (const auto& f : findings) {
        std::string fileLine = f.file + ":" + std::to_string(f.line);
        fprintf(out, "| %s | %s%s%s | %s | %s |\n",
            pad(fileLine, COL_FILE).c_str(),
            severityANSI(f.severity),
            pad(f.severity, COL_SEV).c_str(),
            "\033[0m",
            pad(f.cwe, COL_CWE).c_str(),
            pad(f.message, COL_MSG).c_str());

        if (!f.snippet.empty())
            fprintf(out, "|   %-*s  |\n", COL_FILE+COL_SEV+COL_CWE+COL_MSG+9,
                    ("  > " + f.snippet).c_str());

        if (f.severity=="HIGH")   high++;
        else if (f.severity=="MEDIUM") med++;
        else low++;
    }

    hline();
    fprintf(out, "\n  Total: %zu finding(s) — HIGH: %d  MEDIUM: %d  LOW: %d\n\n",
            findings.size(), high, med, low);

    // Remediation for HIGH findings
    bool hasHigh = false;
    for (auto& f : findings) if (f.severity=="HIGH") { hasHigh=true; break; }
    if (hasHigh) {
        fprintf(out, "--- Remediations for HIGH findings ---\n");
        for (auto& f : findings) {
            if (f.severity == "HIGH" && !f.remediation.empty()) {
                fprintf(out, "  %s:%d [%s]: %s\n",
                        f.file.c_str(), f.line, f.cwe.c_str(),
                        f.remediation.c_str());
            }
        }
    }
}

// =====================================================================
// JSON
// =====================================================================

static void printJSON(const std::vector<Finding>& findings, FILE* out) {
    fprintf(out, "[\n");
    for (size_t i=0; i<findings.size(); i++) {
        const auto& f = findings[i];
        fprintf(out,
            "  {\n"
            "    \"file\"        : \"%s\",\n"
            "    \"line\"        : %d,\n"
            "    \"cwe\"         : \"%s\",\n"
            "    \"severity\"    : \"%s\",\n"
            "    \"message\"     : \"%s\",\n"
            "    \"snippet\"     : \"%s\",\n"
            "    \"remediation\" : \"%s\"\n"
            "  }%s\n",
            jsonEscape(f.file).c_str(),
            f.line,
            jsonEscape(f.cwe).c_str(),
            jsonEscape(f.severity).c_str(),
            jsonEscape(f.message).c_str(),
            jsonEscape(f.snippet).c_str(),
            jsonEscape(f.remediation).c_str(),
            (i+1<findings.size()) ? "," : "");
    }
    fprintf(out, "]\n");
}

// =====================================================================
// HTML
// =====================================================================

static void printHTML(const std::vector<Finding>& findings,
                      const std::string& sourceFile, FILE* out) {
    // Count by severity
    int high=0, med=0, low=0;
    for (auto& f : findings) {
        if (f.severity=="HIGH") high++;
        else if (f.severity=="MEDIUM") med++;
        else low++;
    }

    fprintf(out, R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAST Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 2em; background: #f8f9fa; color: #212529; }
h1 { color: #343a40; }
.summary { display: flex; gap: 1em; margin: 1em 0; }
.badge { padding: .4em 1em; border-radius: 4px; font-weight: bold; color: #fff; font-size: 1.1em; }
.badge-high   { background: #d73a4a; }
.badge-medium { background: #e36209; }
.badge-low    { background: #0075ca; }
table { width: 100%%; border-collapse: collapse; margin-top: 1em; }
th { background: #343a40; color: #fff; padding: .5em .7em; text-align: left; }
tr:nth-child(even) { background: #e9ecef; }
td { padding: .4em .7em; vertical-align: top; font-size: .9em; }
.sev-HIGH   { color: #d73a4a; font-weight: bold; }
.sev-MEDIUM { color: #e36209; font-weight: bold; }
.sev-LOW    { color: #0075ca; font-weight: bold; }
code { background: #f1f1f1; padding: .1em .3em; border-radius: 3px; font-size: .88em; }
.snippet { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: .2em .5em; border-radius: 3px; }
</style>
</head>
<body>
<h1>SAST Report</h1>
)");

    if (!sourceFile.empty())
        fprintf(out, "<p>Scanned: <code>%s</code></p>\n", htmlEscape(sourceFile).c_str());

    fprintf(out,
        "<div class=\"summary\">\n"
        "  <span class=\"badge badge-high\">HIGH: %d</span>\n"
        "  <span class=\"badge badge-medium\">MEDIUM: %d</span>\n"
        "  <span class=\"badge badge-low\">LOW: %d</span>\n"
        "  <span class=\"badge\" style=\"background:#555\">TOTAL: %zu</span>\n"
        "</div>\n", high, med, low, findings.size());

    fprintf(out,
        "<table>\n"
        "<tr><th>#</th><th>File:Line</th><th>Severity</th><th>CWE</th>"
        "<th>Message</th><th>Snippet</th><th>Remediation</th></tr>\n");

    int n=1;
    for (auto& f : findings) {
        std::string fileLine = htmlEscape(f.file) + ":" + std::to_string(f.line);
        fprintf(out,
            "<tr>\n"
            "  <td>%d</td>\n"
            "  <td><code>%s</code></td>\n"
            "  <td class=\"sev-%s\">%s</td>\n"
            "  <td>%s</td>\n"
            "  <td>%s</td>\n"
            "  <td><span class=\"snippet\">%s</span></td>\n"
            "  <td>%s</td>\n"
            "</tr>\n",
            n++,
            fileLine.c_str(),
            htmlEscape(f.severity).c_str(), htmlEscape(f.severity).c_str(),
            htmlEscape(f.cwe).c_str(),
            htmlEscape(f.message).c_str(),
            htmlEscape(f.snippet).c_str(),
            htmlEscape(f.remediation).c_str());
    }

    fprintf(out, "</table>\n</body>\n</html>\n");
}

// =====================================================================
// Parse findings from a line: "file:line:cwe:severity:message"
// =====================================================================
static bool parseFinding(const std::string& s, Finding& f) {
    std::vector<std::string> parts;
    std::istringstream ss(s);
    std::string tok;
    // Split on ':' but allow ':' in message (only split first 4)
    int field = 0;
    std::string rest = s;
    while (field < 4) {
        size_t pos = rest.find(':');
        if (pos == std::string::npos) break;
        parts.push_back(rest.substr(0, pos));
        rest = rest.substr(pos+1);
        field++;
    }
    parts.push_back(rest); // message remainder

    if (parts.size() < 5) return false;
    f.file     = parts[0];
    f.line     = atoi(parts[1].c_str());
    f.cwe      = parts[2];
    f.severity = parts[3];
    f.message  = parts[4];
    return true;
}

// Built-in sample findings
static std::vector<Finding> sampleFindings() {
    return {
        {"src/main.c",   14, "CWE-120", "HIGH",
         "gets() has no bounds checking",
         "    gets(inputBuffer);",
         "Replace with fgets(inputBuffer, sizeof(inputBuffer), stdin)"},

        {"src/main.c",   27, "CWE-78", "HIGH",
         "system() with user-controlled argument",
         "    system(userCmd);",
         "Validate input; use execv() with argument array instead of system()"},

        {"src/parser.c", 88, "CWE-120", "MEDIUM",
         "strcpy() has no bounds checking",
         "    strcpy(dest, src);",
         "Use strncpy(dest, src, sizeof(dest)-1) and manually null-terminate"},

        {"src/auth.c",  112, "CWE-798", "HIGH",
         "Hardcoded password literal",
         "    if (strcmp(pass, \"admin123\") == 0)",
         "Load credentials from environment variable or encrypted configuration"},

        {"src/net.c",    55, "CWE-134", "MEDIUM",
         "printf with non-literal format argument",
         "    printf(userMsg);",
         "Use printf(\"%s\", userMsg) — never printf(userMsg)"},

        {"src/db.c",     73, "CWE-89", "HIGH",
         "SQL injection risk in query construction",
         "    sprintf(query, \"SELECT * FROM users WHERE name='%s'\", input);",
         "Use parameterized queries / prepared statements"},

        {"src/file.c",   31, "CWE-22", "MEDIUM",
         "fopen with user-supplied path",
         "    fopen(filePath, \"r\");",
         "Validate path: reject '..' components, restrict to allowed base directory"},
    };
}

int main(int argc, char* argv[]) {
    const char* format = "text";
    const char* outPath = nullptr;
    const char* inPath = nullptr;

    for (int i=1; i<argc; i++) {
        if (strcmp(argv[i],"--format")==0 && i+1<argc) format = argv[++i];
        else if (strcmp(argv[i],"-o")==0 && i+1<argc)  outPath = argv[++i];
        else if (argv[i][0] != '-')                    inPath  = argv[i];
    }

    // Load findings
    std::vector<Finding> findings;
    if (inPath) {
        std::ifstream in(inPath);
        std::string line;
        while (std::getline(in, line)) {
            Finding f;
            if (parseFinding(line, f)) findings.push_back(f);
        }
    } else {
        findings = sampleFindings();
    }

    if (findings.empty()) {
        fprintf(stderr, "No findings to report.\n");
        return 0;
    }

    FILE* out = stdout;
    if (outPath) {
        out = fopen(outPath, "w");
        if (!out) { perror("fopen output"); return 1; }
    }

    // Sort: HIGH first, then MEDIUM, then LOW; within each by file+line
    std::sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        auto rank = [](const std::string& s) {
            return s=="HIGH" ? 0 : s=="MEDIUM" ? 1 : 2;
        };
        if (rank(a.severity) != rank(b.severity)) return rank(a.severity) < rank(b.severity);
        if (a.file != b.file) return a.file < b.file;
        return a.line < b.line;
    });

    if      (strcmp(format,"json")==0) printJSON(findings, out);
    else if (strcmp(format,"html")==0) printHTML(findings, inPath ? inPath : "(sample)", out);
    else                               printTextTable(findings, out);

    if (outPath) {
        fclose(out);
        printf("Report written to: %s\n", outPath);
    }

    return 0;
}
