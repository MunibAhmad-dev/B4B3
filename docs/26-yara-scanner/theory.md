# Module 26 — YARA Scanner

## What YARA is

YARA is a pattern-matching tool designed for malware researchers.
A YARA rule describes a malware family by the patterns it leaves:
strings, byte sequences, or combinations with boolean logic.

Think of it as "regex for malware" but more powerful — you can match:
- Exact strings or hex bytes
- Regex patterns
- PE header fields (using the `pe` module)
- Entropy ranges, file size conditions
- Combinations: "contains string A AND string B but NOT string C"

YARA rules are used by:
- VirusTotal (scans every upload against thousands of rules)
- CrowdStrike, Carbon Black, Defender ATP
- Internal SIEM platforms for retrospective scanning
- Incident responders scanning memory dumps

---

## 2. Writing YARA Rules

```yara
rule SuspiciousRAT
{
    meta:
        description = "Generic RAT beacon pattern"
        author      = "Your name"
        date        = "2026-10-01"

    strings:
        $url1  = "http://" ascii wide
        $url2  = "https://" ascii wide
        $api1  = "CreateRemoteThread" ascii
        $api2  = "VirtualAllocEx" ascii
        $api3  = "WriteProcessMemory" ascii
        $mutex = "Global\\" ascii wide
        // Hex pattern — common shellcode prologue
        $sc    = { 48 83 EC 28 [0-8] 48 8B ?? }

    condition:
        uint16(0) == 0x5A4D        // MZ header
        and filesize < 5MB
        and (
            ($api1 and $api2 and $api3)  // injection triad
            or ($sc and 1 of ($url*))    // shellcode + network
        )
}
```

**String modifiers:**
- `ascii` — match ASCII encoding (default)
- `wide` — match UTF-16LE (common in Windows)
- `nocase` — case insensitive
- `fullword` — must be a full word (bounded by non-alphanumeric)

**PE module conditions:**
```yara
import "pe"
rule SuspiciousPE {
    condition:
        pe.number_of_sections < 3          // packed files often have few sections
        or pe.section_index(".UPX0") >= 0  // UPX packed
        or for any section in pe.sections: (
            section.entropy > 7.2           // high entropy = encrypted/packed
        )
        or pe.timestamp < 946684800         // before 2000-01-01 (often fake/zeroed)
}
```

---

## 3. libyara Integration in C++

**libyara** is the C library underlying the `yara` command-line tool.

```cpp
#include <yara.h>
#pragma comment(lib, "libyara.lib")

// Callback called for each rule match
int scanCallback(YR_SCAN_CONTEXT* context, int message,
                  void* messageData, void* userData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)messageData;
        printf("[MATCH] Rule: %s\n", rule->identifier);

        // Print matching strings
        YR_STRING* str;
        yr_rule_strings_foreach(rule, str) {
            YR_MATCH* match;
            yr_string_matches_foreach(context, str, match) {
                printf("  String %s at offset 0x%llX\n",
                       str->identifier, (ULONGLONG)match->offset);
            }
        }
    }
    return CALLBACK_CONTINUE;
}

bool scanFile(const char* rulesPath, const char* targetPath) {
    yr_initialize();

    YR_COMPILER* compiler = nullptr;
    yr_compiler_create(&compiler);

    FILE* f = fopen(rulesPath, "r");
    if (yr_compiler_add_file(compiler, f, nullptr, rulesPath) > 0) {
        printf("[-] Rule compilation error\n");
        fclose(f); yr_compiler_destroy(compiler); yr_finalize();
        return false;
    }
    fclose(f);

    YR_RULES* rules = nullptr;
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    int result = yr_rules_scan_file(rules, targetPath, 0,
                                     scanCallback, nullptr, 10);

    yr_rules_destroy(rules);
    yr_finalize();
    return result == ERROR_SUCCESS;
}
```

**Scanning process memory:**
```cpp
// Instead of yr_rules_scan_file, use yr_rules_scan_mem:
HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
// ... enumerate regions and scan each one:
yr_rules_scan_mem(rules, regionData, regionSize, 0, scanCallback, nullptr, 10);
```

---

## 4. Writing Effective Rules

**Good rule = high specificity + low false positives**

Tips:
1. Use multiple unique strings — a single short string will match too broadly
2. Include PE structural conditions (section entropy, import count)
3. Test against a corpus of clean files: `yara rule.yar clean_files/ -r`
4. Use `pe.imports("kernel32.dll", "CreateRemoteThread")` for API-specific rules
5. Combine byte patterns with string patterns for shellcode detection

**Common detection patterns:**

```yara
// Detect process hollowing
rule ProcessHollowing {
    strings:
        $f1 = "NtUnmapViewOfSection" ascii
        $f2 = "ZwUnmapViewOfSection" ascii
        $f3 = "NtWriteVirtualMemory" ascii
        $f4 = "SetThreadContext" ascii

    condition:
        uint16(0) == 0x5A4D
        and 3 of them
}

// Detect reflective DLL injection loader stub
rule ReflectiveDLLLoader {
    strings:
        // ReflectiveLoader export name
        $s1 = "ReflectiveLoader" ascii wide
        // Common pattern in loader: PEB walking
        $s2 = { 65 48 8B 04 25 60 00 00 00 }  // mov rax, gs:[0x60]

    condition:
        any of them
}
```

---

## 5. Command-line YARA Usage

```bash
# Scan a file
yara rule.yar target.exe

# Scan a directory recursively
yara -r rule.yar C:\Users\

# Scan running processes
yara -p 64 rule.yar -d  # scan all processes

# Print only matching files (no details)
yara -l rule.yar C:\path\

# Count matches per rule
yara -C rule.yar target.exe

# Use compiled rules (faster for large rule sets)
yarac rules.yar compiled.yarc
yara compiled.yarc target.exe
```

---

## 6. Rule Sets to Study

- **YARA-Rules** (GitHub) — general malware
- **Neo23x0/signature-base** — Florian Roth's rules (very comprehensive)
- **elastic/detection-rules** — Elastic SIEM YARA rules
- **reversinglabs/reversinglabs-yara-rules** — sample coverage

Study these to understand how professionals write rules for real malware families.

---

## Exercises

- `ex01_write_rules.yar` — write 5 YARA rules for common patterns (RAT, ransomware, dropper)
- `ex02_file_scanner.cpp` — libyara scanner for files/directories
- `ex03_process_scanner.cpp` — scan all running processes with a ruleset
- `ex04_rule_optimizer.cpp` — test a rule against a corpus, measure false positive rate
