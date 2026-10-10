# Scenario 05 — File Integrity Monitor

## Client Brief

**Industry:** PCI-DSS compliant retail  
**Request:** "PCI-DSS 11.5 requires a file integrity monitor on all system files.
We need a lightweight C++ agent that monitors C:\Windows\System32 and our
application directory, alerts on any change, and can prove to auditors that
no files were modified without a change ticket."

---

## Objective

Build an FIM agent that:
1. Takes a baseline snapshot (SHA-256 of every file in specified paths)
2. Runs in the background and monitors for changes using ReadDirectoryChangesW
3. On any change: recompute SHA-256, compare to baseline, log the delta
4. Alerts include: CREATED / MODIFIED / DELETED / RENAMED
5. Stores baseline in a tamper-evident file (baseline SHA-256 is itself hashed)
6. Provides a --baseline flag to create/update the baseline
7. Provides a --verify flag to compare current state to baseline and exit

---

## Deliverable

- `FIMAgent.exe` — runs as a Windows service or standalone
- `fim_baseline.json` — the baseline snapshot
- `fim_alerts.log` — running log of all detected changes
- A 1-page document explaining how this satisfies PCI-DSS 11.5

---

## Skills Required

- Module 12 (defensive tools — SHA-256, ReadDirectoryChangesW, baseline diff)
- Module 04 (Windows internals — file paths, registry for service installation)

---

## PCI-DSS 11.5 Coverage

| Requirement | How this tool satisfies it |
|-------------|---------------------------|
| Monitor critical system files | Configurable path list including System32 |
| Alert on unauthorized changes | ReadDirectoryChangesW + SHA-256 comparison |
| Weekly comparison of current vs. baseline | --verify flag for scheduled task |
| Tamper-evident log | Log entries include HMAC or chain hash |
| Alert to security personnel | Email/syslog integration (bonus) |

---

## Test Plan

1. Baseline: `FIMAgent.exe --baseline C:\Windows\System32\notepad.exe`
2. Copy notepad.exe to a temp location and modify it (patch one byte).
3. Replace original with modified version.
4. Run: `FIMAgent.exe --verify` — should report MODIFIED with hash mismatch.
5. Check fim_alerts.log.
6. Restore original, re-run --verify — should report CLEAN.

---

## Architecture

```
FIMAgent.exe --baseline
  → enumerate all files in configured paths
  → compute SHA-256 for each
  → write fim_baseline.json (JSON array of {path, sha256, size, mtime})
  → write baseline_hash.txt (SHA-256 of fim_baseline.json itself)

FIMAgent.exe --monitor (background)
  → load baseline
  → ReadDirectoryChangesW on each monitored path (recursive)
  → on FILE_ACTION_MODIFIED/ADDED/REMOVED:
      recompute SHA-256
      compare to baseline entry
      if different: write to fim_alerts.log, optionally alert

FIMAgent.exe --verify
  → load baseline
  → enumerate all files
  → compare each SHA-256 to baseline
  → print CLEAN / MODIFIED / DELETED / NEW for each file
  → exit code 0 if clean, 1 if changes detected
```
