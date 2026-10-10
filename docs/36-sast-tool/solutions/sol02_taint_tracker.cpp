// solutions/sol02_taint_tracker.cpp
// Module 36 — SAST Tool, Solution 2
//
// Complete two-pass taint tracker for single C/C++ files.
//
// Pass 1: detect variables assigned from taint sources (argv, getenv, fgets, recv, scanf)
// Pass 2: detect tainted variables appearing in sinks (system, popen, exec*, mysql_query,
//         sqlite3_exec, fopen)
//
// Compile: g++ -std=c++17 -Wall -o sol02.exe sol02_taint_tracker.cpp
// Run:     sol02.exe <source.c>

#include <cstdio>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <regex>
#include <algorithm>
#include <cctype>

struct TaintFinding {
    int         line;
    std::string variable;
    std::string sink;
    std::string cwe;
    std::string snippet;
};

// Extract variable name from a pattern like:
//   char* VAR = ...
//   const char* VAR = ...
//   char VAR[] = ...
//   char* VAR;  (then VAR used as fgets argument)
static std::string extractVarFromDecl(const std::string& line) {
    // Match: (type) (*)* IDENTIFIER followed by = or [ or ,
    static const std::regex declRe(
        R"(\b(?:const\s+)?(?:char|int|size_t|ssize_t|unsigned)\s*\*?\s*([a-zA-Z_]\w*)\s*(?:=|\[|;|\,))");
    std::smatch m;
    if (std::regex_search(line, m, declRe))
        return m[1].str();
    return "";
}

// Extract the Nth argument (0-based) from a function call on the line
// Very simplified: splits on commas within outermost parens
static std::string getArgN(const std::string& line, const std::string& funcName, int argIndex) {
    size_t fpos = line.find(funcName + "(");
    if (fpos == std::string::npos) return "";
    size_t parenOpen = line.find('(', fpos);
    if (parenOpen == std::string::npos) return "";

    int depth=1; size_t i = parenOpen+1;
    std::vector<std::string> args;
    std::string cur;
    while (i < line.size() && depth > 0) {
        char c = line[i];
        if (c=='(' || c=='[') depth++;
        else if (c==')' || c==']') { depth--; if (depth==0) break; }
        else if (c==',' && depth==1) { args.push_back(cur); cur=""; i++; continue; }
        cur += c;
        i++;
    }
    args.push_back(cur);

    if (argIndex < (int)args.size()) {
        std::string a = args[argIndex];
        // trim
        size_t s=0, e=a.size();
        while (s<e && isspace((unsigned char)a[s])) s++;
        while (e>s && isspace((unsigned char)a[e-1])) e--;
        return a.substr(s, e-s);
    }
    return "";
}

// Extract a clean identifier from an expression like "&var", "var", "*var"
static std::string cleanIdent(const std::string& expr) {
    std::string s = expr;
    // Remove & and *
    for (char& c : s) if (c=='&'||c=='*') c=' ';
    // Find first identifier
    static const std::regex idRe(R"([a-zA-Z_]\w*)");
    std::smatch m;
    if (std::regex_search(s, m, idRe)) return m[0].str();
    return "";
}

static std::string codeOnly(const std::string& line) {
    bool inStr = false;
    for (size_t i=0; i+1<line.size(); i++) {
        if (line[i]=='\\' && inStr) { i++; continue; }
        if (line[i]=='"') { inStr = !inStr; continue; }
        if (!inStr && line[i]=='/' && line[i+1]=='/') return line.substr(0, i);
    }
    return line;
}

static std::set<std::string> pass1_findTaintedVars(const std::vector<std::string>& lines) {
    std::set<std::string> tainted;

    // Regex patterns for taint sources
    // Pattern A: char* var = argv[...]
    static const std::regex argvAssign(
        R"(\b(?:const\s+)?(?:char|auto)\s*\*+\s*([a-zA-Z_]\w*)\s*=\s*argv\[)");

    // Pattern B: char* var = getenv(...)
    static const std::regex getenvAssign(
        R"(\b(?:const\s+)?(?:char|auto)\s*\*+\s*([a-zA-Z_]\w*)\s*=\s*getenv\()");

    // Pattern C: fgets(var, ...) — first arg is tainted
    static const std::regex fgetsCall(R"(\bfgets\s*\()");

    // Pattern D: recv(sock, var, ...) — second arg is tainted
    static const std::regex recvCall(R"(\brecv\s*\()");

    // Pattern E: scanf/fscanf — arguments after format are tainted
    static const std::regex scanfCall(R"(\b(?:scanf|fscanf|sscanf)\s*\()");

    // Pattern F: read(fd, var, ...) — second arg
    static const std::regex readCall(R"(\bread\s*\()");

    for (const auto& line : lines) {
        std::string code = codeOnly(line);
        std::smatch m;

        // Pattern A — argv assignment
        if (std::regex_search(code, m, argvAssign)) {
            tainted.insert(m[1].str());
        }

        // Also catch: var = argv[N] without declaration on same line
        {
            static const std::regex argvRHS(R"(\b([a-zA-Z_]\w*)\s*=\s*argv\[)");
            if (std::regex_search(code, m, argvRHS)) {
                tainted.insert(m[1].str());
            }
        }

        // Pattern B — getenv assignment
        if (std::regex_search(code, m, getenvAssign)) {
            tainted.insert(m[1].str());
        }
        {
            static const std::regex getenvRHS(R"(\b([a-zA-Z_]\w*)\s*=\s*getenv\()");
            if (std::regex_search(code, m, getenvRHS)) {
                tainted.insert(m[1].str());
            }
        }

        // Pattern C — fgets(buf, ...)
        if (std::regex_search(code, m, fgetsCall)) {
            std::string arg = getArgN(code, "fgets", 0);
            std::string id  = cleanIdent(arg);
            if (!id.empty()) tainted.insert(id);
        }

        // Pattern D — recv(sock, buf, ...)
        if (std::regex_search(code, m, recvCall)) {
            std::string arg = getArgN(code, "recv", 1);
            std::string id  = cleanIdent(arg);
            if (!id.empty()) tainted.insert(id);
        }

        // Pattern E — scanf/fscanf
        if (std::regex_search(code, m, scanfCall)) {
            std::string fname = (code.find("fscanf") != std::string::npos) ? "fscanf" :
                                (code.find("sscanf") != std::string::npos) ? "sscanf" : "scanf";
            int startArg = (fname == "scanf") ? 1 : 2;
            for (int a = startArg; a < 6; a++) {
                std::string arg = getArgN(code, fname, a);
                if (arg.empty()) break;
                std::string id = cleanIdent(arg);
                if (!id.empty()) tainted.insert(id);
            }
        }

        // Pattern F — read(fd, buf, ...)
        if (std::regex_search(code, m, readCall)) {
            std::string arg = getArgN(code, "read", 1);
            std::string id  = cleanIdent(arg);
            if (!id.empty()) tainted.insert(id);
        }

        // Generic: any assignment from a tainted variable propagates taint
        // e.g.: char* cmd = userInput;
        // (simple heuristic: check RHS of assignments)
        {
            static const std::regex assign(
                R"(\b([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*))");
            std::string remaining = code;
            std::sregex_iterator it(remaining.begin(), remaining.end(), assign);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                std::string lhs = (*it)[1].str();
                std::string rhs = (*it)[2].str();
                if (tainted.count(rhs) && !tainted.count(lhs)) {
                    tainted.insert(lhs);
                }
            }
        }
    }

    return tainted;
}

struct SinkInfo {
    const char* keyword;
    const char* cwe;
    const char* category;
};

static const SinkInfo SINKS[] = {
    {"system(",      "CWE-78",  "OS command injection"},
    {"popen(",       "CWE-78",  "OS command injection"},
    {"execve(",      "CWE-78",  "OS process execution"},
    {"execl(",       "CWE-78",  "OS process execution"},
    {"execlp(",      "CWE-78",  "OS process execution"},
    {"execvp(",      "CWE-78",  "OS process execution"},
    {"mysql_query(", "CWE-89",  "SQL injection"},
    {"sqlite3_exec(","CWE-89",  "SQL injection"},
    {"PQexec(",      "CWE-89",  "SQL injection"},
    {"fopen(",       "CWE-22",  "path traversal"},
    {"open(",        "CWE-22",  "path traversal"},
    {"unlink(",      "CWE-22",  "path traversal"},
    {nullptr,        nullptr,    nullptr}
};

static std::vector<TaintFinding> pass2_findSinks(
        const std::vector<std::string>& lines,
        const std::set<std::string>& tainted) {
    std::vector<TaintFinding> findings;

    for (int i=0; i<(int)lines.size(); i++) {
        std::string code = codeOnly(lines[i]);

        for (int s=0; SINKS[s].keyword; s++) {
            if (code.find(SINKS[s].keyword) == std::string::npos) continue;

            for (const auto& var : tainted) {
                // Check if the tainted variable name appears in this sink call
                // Simple approach: variable appears in the argument region
                size_t sinkPos = code.find(SINKS[s].keyword);
                size_t parenPos = sinkPos + strlen(SINKS[s].keyword);
                std::string afterSink = code.substr(parenPos);

                // Use word-boundary matching: var must appear as an identifier
                static const std::regex wb("[^a-zA-Z0-9_]([a-zA-Z_]\\w*)[^a-zA-Z0-9_]");
                std::string padded = " " + afterSink + " ";
                std::sregex_iterator it(padded.begin(), padded.end(), wb);
                std::sregex_iterator end;
                bool found = false;
                for (; it != end && !found; ++it) {
                    if ((*it)[1].str() == var) found = true;
                }

                if (found) {
                    // Avoid duplicate findings for same line+var+sink
                    bool dup = false;
                    for (auto& f : findings)
                        if (f.line==i+1 && f.variable==var && f.sink==SINKS[s].keyword) {
                            dup=true; break;
                        }
                    if (!dup) {
                        std::string snippet = lines[i];
                        size_t trim = snippet.find_first_not_of(" \t");
                        if (trim != std::string::npos) snippet = snippet.substr(trim);
                        findings.push_back({i+1, var, SINKS[s].keyword,
                                            SINKS[s].cwe, snippet});
                    }
                }
            }
        }
    }

    return findings;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <source.c>\n", argv[0]);
        return 1;
    }

    std::ifstream in(argv[1]);
    if (!in) { fprintf(stderr, "Cannot open: %s\n", argv[1]); return 1; }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);

    printf("=== Pass 1: Taint Source Detection ===\n");
    auto tainted = pass1_findTaintedVars(lines);

    if (tainted.empty()) {
        printf("No tainted variables detected.\n\n");
    } else {
        printf("Tainted variables (%zu):\n", tainted.size());
        for (auto& v : tainted) printf("  '%s'\n", v.c_str());
        printf("\n");
    }

    printf("=== Pass 2: Sink Detection ===\n");
    auto findings = pass2_findSinks(lines, tainted);

    if (findings.empty()) {
        printf("No taint flows to sinks detected.\n");
    } else {
        for (auto& f : findings) {
            printf("%s:%d: [HIGH] %s: tainted variable '%s' flows into '%s' — %s\n",
                   argv[1], f.line, f.cwe.c_str(),
                   f.variable.c_str(), f.sink.c_str(), f.cwe.c_str());
            printf("  > %s\n", f.snippet.c_str());
        }
        printf("\n%zu taint flow(s) found\n", findings.size());
    }

    return 0;
}
