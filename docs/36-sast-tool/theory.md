# Module 36 — SAST Tool

## 1. What Is Static Analysis?

Static Application Security Testing (SAST) analyzes source code or compiled binaries without executing them. The goal is to identify vulnerabilities — unsafe function calls, tainted data flows, integer issues, hardcoded secrets — before the software reaches production. SAST complements dynamic testing (fuzzing, penetration testing) because it can cover every code path, not just executed ones.

---

## 2. Analysis Approaches

### 2.1 Regex / Pattern Matching

The simplest approach: scan each line of source for dangerous function names or string patterns.

**Advantages**:
- Trivial to implement
- Fast — O(lines × patterns)
- Language-agnostic (works on any text)

**Disadvantages**:
- High false-positive rate: `strsafe_strcpy(dest, src)` triggers a `strcpy` check
- No understanding of context: `gets` in a comment fires
- Cannot track data flow: `char* p = argv[1]; system(p);` requires two-line correlation
- No understanding of type: `printf(hardcoded_literal)` is safe; `printf(userInput)` is not

**When to use**: quick triage pass; pre-commit hooks checking for obvious mistakes; code review assistance.

### 2.2 AST-Based Analysis

Parse the source into an Abstract Syntax Tree, then walk the tree checking structural properties.

**Advantages**:
- Understands syntax precisely: comments, string literals, and macro expansions are handled correctly
- Can check function call arguments specifically: `sprintf(buf, fmt, ...)` where `fmt` is not a literal
- Can track variable types and scope

**Disadvantages**:
- Requires a language-specific parser (clang, tree-sitter, pycparser)
- Harder to implement from scratch
- Slower build-time integration

Tools that use AST: clang-tidy (C/C++ with clang's full AST), Semgrep (pseudo-AST patterns), Infer (Facebook, Java/C/ObjC).

### 2.3 Data Flow / Taint Analysis

Tracks how values propagate through a program from **sources** (untrusted input) to **sinks** (dangerous operations).

A finding is generated only when a tainted value reaches a sink without going through a sanitizer.

```
Source:  char* input = argv[1];
                        ^^^^^^ tainted

Propagation: char* copy = input;   // copy is also tainted

Sink:   system(copy);              // tainted value in command execution → CWE-78
```

**Sources** (common in C/C++):
- `argv[]`, `argc`
- `getenv()` return value
- `fgets()`, `gets()` into a buffer
- `recv()`, `read()` network/file data
- `scanf()` into variables

**Sinks** (dangerous operations):
- Command injection: `system()`, `popen()`, `execve()`, `execl()`, `execlp()`, `execvp()`
- SQL injection: `mysql_query()`, `sqlite3_exec()`, `PQexec()`
- Format string: `printf(tainted)`, `fprintf(f, tainted)`, `syslog(p, tainted)`
- Path traversal: `fopen(tainted)`, `open(tainted)`, `CreateFile(tainted)`
- Buffer copy: `strcpy(buf, tainted)` where buf size is known

**Sanitizers** (clean operations):
- `snprintf()` (limits output length)
- `strnlen()`, bounds checking
- Whitelist validation functions

---

## 3. CWE Reference

CWE (Common Weakness Enumeration) is a community-maintained catalog of software weaknesses. SAST tools report findings using CWE IDs for interoperability.

| CWE ID | Name | Example |
|--------|------|---------|
| CWE-120 | Buffer Copy without Checking Size of Input | `strcpy(dest, src)` |
| CWE-121 | Stack-based Buffer Overflow | `char buf[16]; gets(buf)` |
| CWE-122 | Heap-based Buffer Overflow | `malloc(n); memcpy without bounds` |
| CWE-134 | Uncontrolled Format String | `printf(user_input)` |
| CWE-190 | Integer Overflow or Wraparound | `(int)(a+b)` where a,b are unsigned |
| CWE-195 | Signed to Unsigned Conversion Error | `size_t n = (size_t)(-1)` |
| CWE-22  | Path Traversal | `fopen(path, "r")` with `../` in path |
| CWE-78  | OS Command Injection | `system(user_controlled)` |
| CWE-89  | SQL Injection | `sprintf(query, "SELECT * FROM users WHERE id=%s", input)` |
| CWE-416 | Use After Free | `free(p); *p = 0;` |
| CWE-476 | NULL Pointer Dereference | `p = malloc(n); *p = 0;` without NULL check |
| CWE-798 | Use of Hard-coded Credentials | `password = "admin123"` |
| CWE-327 | Use of Broken Cryptographic Algorithm | `MD5(password)` |
| CWE-676 | Use of Potentially Dangerous Function | `gets()`, `mktemp()` |

---

## 4. The False Positive Problem

SAST tools are notorious for false positives (reported findings that are not real vulnerabilities). High FP rates cause "alert fatigue" — developers start ignoring all findings.

### 4.1 Sources of False Positives

- **Regex over-matching**: `strcpy` in a variable name, comment, or string literal
- **Missing context**: `printf(literal)` flagged as format string, but the literal is a compile-time constant
- **Safe wrappers**: code uses `safe_strcpy()` internally which wraps `strcpy` safely — the SAST sees `strcpy`
- **Intentional usage**: test code, benchmarks, or security research code that intentionally calls dangerous functions

### 4.2 Reducing False Positives

- **Suppression comments**: `// NOSONAR`, `// nosec`, `// SAST:ignore`
- **Allowlisting**: known-safe patterns excluded from results
- **Severity tiers**: LOW findings are reviewed manually; HIGH are blocking
- **Contextual checks**: check that the format argument is a string literal (AST check) rather than matching any call

### 4.3 False Negative Rate

Missing real vulnerabilities (false negatives) is the other failure mode. Pure regex scanners miss:
- Two-line taint flows (`int n = atoi(argv[1]); malloc(n);`)
- Indirect calls through function pointers
- Vulnerabilities introduced by macro expansion
- Off-by-one errors that require value-range analysis

---

## 5. Semgrep Rule Basics

Semgrep is an open-source tool that uses pseudo-AST pattern matching across many languages. Rules are written in YAML:

```yaml
rules:
  - id: dangerous-gets
    pattern: gets(...)
    message: "CWE-120: gets() has no bounds checking. Use fgets() instead."
    languages: [c, cpp]
    severity: ERROR
    metadata:
      cwe: CWE-120

  - id: format-string-injection
    patterns:
      - pattern: printf($FMT, ...)
      - pattern-not: printf("...", ...)
    message: "CWE-134: printf with non-literal format argument"
    languages: [c, cpp]
    severity: WARNING
```

Key pattern syntax:
- `...` — matches any sequence of arguments
- `$X` — matches any single expression, binds to metavariable X
- `pattern-not` — exclude matches that also match this sub-pattern
- `pattern-either` — match if any sub-pattern matches
- `metavariable-regex` — constrain a metavariable by regex

---

## 6. IDE Integration

SAST is most effective when developers see findings immediately in their editor.

### 6.1 clang-tidy

Runs clang checks plus community checks (`cppcoreguidelines-*`, `cert-*`, `readability-*`).

```bash
# Run on a single file with all cert checks
clang-tidy file.c -checks='cert-*,cppcoreguidelines-*' -- -std=c11

# Integrate with CMake
set(CMAKE_CXX_CLANG_TIDY clang-tidy;-checks=cert-*,cppcoreguidelines-*)
```

Key check families:
- `cert-err34-c`: unsafe conversion from string (atoi, atol)
- `cert-str31-c`: `strlen` result used as size for `strncat` (off-by-one)
- `bugprone-use-after-move`
- `cppcoreguidelines-avoid-goto`

### 6.2 cppcheck

Standalone C/C++ checker with a focus on definite bugs rather than style:

```bash
cppcheck --enable=all --std=c11 --xml src/ 2>report.xml
```

Checks: buffer overflow, null pointer dereference, use-after-free, division by zero, unsigned underflow.

### 6.3 Visual Studio Code Analyzer

VS 2019+ has built-in code analysis:
- `/analyze` compiler flag enables SAL (Source Annotation Language) analysis
- Integrates with the Code Analysis SDK
- Reports CWE warnings directly in the Error List

### 6.4 CI/CD Integration

```yaml
# GitHub Actions example
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/c  # pre-built C/C++ ruleset
```

Fail the build when HIGH severity findings are present; report MEDIUM/LOW as warnings.

---

## 7. Building a Regex Scanner: Design Checklist

When implementing a line-based pattern scanner:

1. **Strip comments before matching**: C/C++ single-line (`// ...`) and multi-line (`/* ... */`) comments contain function names that are not calls
2. **Skip string literals**: a `strcpy` inside a string literal is not a call
3. **Match function call syntax**: `gets(` not just `gets`; require `(` immediately after name
4. **Check argument context for format strings**: is the first argument after the function name a string literal?
5. **Track line continuations**: backslash at end of line; macro bodies
6. **Report column number**: enables IDE integration for single-click navigation
7. **Assign CWE ID**: standardized; enables downstream tooling
8. **Assign severity**: HIGH (always dangerous, e.g., `gets`), MEDIUM (dangerous with user input, e.g., `strcpy`), LOW (informational, e.g., `strncpy` off-by-one risk)

---

## 8. Report Formats

| Format | Use case |
|--------|----------|
| Text / terminal | Developer CLI workflow |
| JSON | Machine-readable; consumed by CI/CD dashboards, JIRA, DefectDojo |
| SARIF | GitHub Code Scanning, VS Code; industry standard for SAST output |
| HTML | Management reports; security review presentations |
| CSV | Spreadsheet analysis; tracking over time |

SARIF (Static Analysis Results Interchange Format) is an OASIS standard. A minimal SARIF file:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": { "driver": { "name": "MySASTTool", "version": "1.0" } },
    "results": [{
      "ruleId": "CWE-120",
      "level": "error",
      "message": { "text": "gets() has no bounds checking" },
      "locations": [{ "physicalLocation": {
        "artifactLocation": { "uri": "src/main.c" },
        "region": { "startLine": 42, "startColumn": 5 }
      }}]
    }]
  }]
}
```

---

## Key Takeaways

- Regex scanners are fast and easy to build but have high false positive rates and miss multi-line flows
- Taint analysis tracks untrusted data from sources (argv, getenv, recv) to sinks (system, printf, fopen)
- CWE IDs provide a standardized vocabulary for vulnerability classification
- Suppression and allowlisting are essential for keeping FP rates manageable in production
- Semgrep bridges the gap between simple regex and full AST analysis
- SAST is most effective when integrated into IDE and CI/CD (immediate developer feedback loop)
- No scanner catches everything — SAST is one layer in a defense-in-depth security program
