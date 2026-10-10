# RE-12: Security Researcher Capstone

## The Full RE Workflow

A systematic approach to an unknown binary:

```
1. TRIAGE         — hash + AV, basic file info, pack/obfuscation detection
2. STATIC LEVEL 1 — strings, imports, entropy, PE metadata
3. STATIC LEVEL 2 — disassembly: entry point, cfg, TLS, anti-debug
4. UNPACK (if needed) — find OEP, dump, IAT rebuild
5. DYNAMIC        — sandbox / VM: file/reg/net/proc behavior
6. DEOBFUSCATE    — decode config (XOR/b64/custom), find C2
7. DOCUMENT       — YARA rule, IOC list, family classification
8. REPORT         — timeline, impact, detection recommendations
```

---

## Family Classification

| Behavior cluster | Family type |
|-----------------|-------------|
| Beacon + task dispatch + keylog | RAT |
| File enumeration + BCrypt + ransom note | Ransomware |
| Download + drop + execute | Loader/Dropper |
| Process hiding + hook + DKOM | Rootkit |
| Credential dump (LSASS / SAM) | Infostealer |
| Lateral movement + SMB/RDP | Worm/Lateral mover |

---

## Writing Detections

### YARA
- Meta: threat name, author, confidence
- Strings: mutex, C2 format, hardcoded key, unique API sequence
- Condition: combine with file size and `$mz at 0`

### Sigma (log-based)
```yaml
title: Suspicious Injection Sequence
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 8
    TargetImage|endswith: '\lsass.exe'
  condition: selection
```

### Sysmon Rules
- Event 1: process create — parent/child anomalies
- Event 3: network — beaconing intervals
- Event 10: process access (LSASS open)
- Event 7: image load — unusual DLLs

---

## Threat Intel Output

A research report should include:

1. **Executive summary** — what the malware does, who it targets
2. **Technical analysis** — full static + dynamic findings
3. **IOC table** — hashes, C2 IPs/domains, mutex, registry keys, file paths
4. **YARA rule** — ready-to-deploy, tested on samples
5. **Detection recommendations** — which log sources, what thresholds
6. **Remediation** — how to remove persistence, clean infected hosts

---

## Capstone Project

Build a complete analysis report on a **self-authored** sample:
1. Write a minimal RAT-like program (beacon, command execute, exfil)
2. Apply obfuscation: XOR-encode strings, dynamic API resolution
3. Run your own tool suite against it (all RE-01 through RE-11 workable tools)
4. Write the report: IOC list, YARA rule, Sysmon detection
5. Verify YARA fires on your sample but not on clean binaries

---

## Exercises

1. `ex01_full_analysis.cpp` — Full automated report generator: runs all analysis phases, outputs structured report
2. `ex02_yara_writer.cpp`   — Given IOC list (strings, import hashes), generate a YARA rule automatically
3. `ex03_report_target.cpp` — A benign but obfuscated target binary to analyze as the capstone sample

## Key References

- MITRE ATT&CK: attack.mitre.org
- VirusTotal Graph for pivot analysis
- MalwareBazaar + Unpac.me for real samples
- *Malware Analyst's Cookbook* — Ligh, Adair, Hartstein, Richard
