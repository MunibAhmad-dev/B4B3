# Scenario 04 — Persistence Scanner

## Client Brief

**Industry:** Government contractor  
**Request:** "After a suspected intrusion, we need to audit all Windows workstations
for persistence mechanisms. We can't send an analyst to each machine —
we need a single executable that runs and produces a report."

---

## Objective

Build a persistence scanner that checks:
1. HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (user-level autorun)
2. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (system-level autorun)
3. Startup folder: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
4. Scheduled tasks (via COM — ITaskService)
5. Services (HKLM\SYSTEM\CurrentControlSet\Services — looking for unusual entries)
6. IFEO debugger key (Image File Execution Options — common persistence vector)

For each finding:
- Print the key/path/name
- Print the command it runs
- Flag if the binary is unsigned, missing, or in a suspicious location

---

## Deliverable

- `PersistScan.exe` — outputs report to stdout and to persist_report.txt
- Report categorises findings: KNOWN GOOD / SUSPICIOUS / MISSING BINARY
- Runs as standard user (no admin required for HKCU + startup folder checks)

---

## Skills Required

- Module 10 (persistence advanced — scheduled tasks, IFEO, COM)
- Module 04 (Windows internals — registry, file paths)

---

## Test Plan

1. Add a test entry to HKCU Run: reg add ... /v TestPersist /d "calc.exe"
2. Add a test .lnk to the startup folder.
3. Run PersistScan.exe as standard user.
4. Confirm TestPersist appears in the report.
5. Run as admin — confirm additional HKLM entries are also reported.
6. Delete test entries and re-run — confirm they are gone.

---

## Binary Reputation Check

For each persistence entry that points to an EXE:
1. Check if the file exists (if not → MISSING BINARY — suspicious)
2. Check if it is in a trusted location (C:\Windows\, C:\Program Files\)
3. Check for a valid code signature (WinVerifyTrust)
4. Flag anything in %TEMP%, %APPDATA%, or %PUBLIC% as HIGH RISK
