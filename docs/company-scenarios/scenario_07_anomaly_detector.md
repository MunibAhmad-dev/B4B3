# Scenario 07 — Endpoint Anomaly Detector

## Client Brief

**Industry:** Law firm (sensitive client data)  
**Request:** "We want to detect if something unusual is running on our endpoints —
processes that appeared since yesterday, new network connections to unknown IPs,
new persistence entries. We want a daily report so IT can review it each morning."

---

## Objective

Build an anomaly detector that:
1. Takes a baseline snapshot of: running processes + network connections + persistence
2. Runs again later and produces a DIFF report: what is NEW since baseline
3. Cross-references new network connections against a list of known-good IPs/ranges
4. Scores each anomaly: LOW / MEDIUM / HIGH based on severity heuristics
5. Saves report to a file and (optionally) emails it

---

## Deliverable

- `AnomalyDetect.exe --baseline` — take and save baseline
- `AnomalyDetect.exe --check` — compare current state to baseline, produce report
- `anomaly_report_YYYY-MM-DD.txt` — daily report file
- Runs as standard user (admin required only for network connection details)

---

## Skills Required

- Module 12 (defensive tools — process monitor, network connection monitor,
  persistence scanner, snapshot diff approach)
- Module 10 (persistence — where to look)
- Module 05 (processes — Toolhelp32 snapshot)

---

## Scoring Heuristics

| Finding | Score |
|---------|-------|
| New process in C:\Users\, %TEMP%, or %APPDATA% | HIGH |
| New process with no company code signing | MEDIUM |
| New network connection to a non-RFC1918 IP | HIGH |
| New network connection to port 4444, 1337, 9999 | HIGH |
| New HKCU Run entry pointing to non-standard path | HIGH |
| New HKLM Run entry | MEDIUM |
| New scheduled task | MEDIUM |
| New startup folder entry | MEDIUM |
| Process with high CPU (>80%) and no company signature | MEDIUM |

---

## Test Plan

1. Take baseline.
2. Open Calculator (calc.exe) — a new process.
3. Establish an outbound TCP connection (netcat to a test server).
4. Add a test HKCU Run entry.
5. Run --check — confirm all three anomalies are reported.
6. Score: Calculator should be LOW (Microsoft-signed), connection should be HIGH,
   Run entry should be HIGH (pointing to temp path).

---

## Architecture

```
Baseline snapshot:
  processes.json    → [{pid, name, path, parent, creation_time}]
  connections.json  → [{proto, local_addr, local_port, remote_addr, remote_port, state, pid}]
  persistence.json  → [{location, name, command}]

Diff algorithm:
  For each item in current_snapshot:
    if item.key NOT in baseline: it's NEW → add to anomaly report
    if item.key in baseline but value changed: it's MODIFIED → add to report

  For each item in baseline:
    if item.key NOT in current: it was REMOVED (less suspicious, but log it)

Scoring:
  Apply heuristics table to each anomaly
  Sort report: HIGH → MEDIUM → LOW
```
