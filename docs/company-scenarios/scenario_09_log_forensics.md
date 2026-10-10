# Scenario 09 — Log Forensics Tool

## Client Brief

**Industry:** E-commerce  
**Request:** "We think someone accessed our admin panel without authorisation
last Tuesday. We have Windows event logs but no SIEM. We need a tool that
can parse the Security/System event logs and surface suspicious events
around the time window."

---

## Objective

Build a log forensics tool that:
1. Queries Windows Event Log (Security, System, Application) via EvtQuery
2. Filters by time range and event IDs
3. Extracts and formats relevant fields for each event
4. Highlights events known to be associated with attacks (see table below)
5. Exports findings to a human-readable timeline report

---

## Deliverable

- `LogForensics.exe --channel Security --start "2026-10-01 09:00" --end "2026-10-01 18:00"`
- Outputs to stdout and `forensics_report.txt`
- Runs as admin (required to read Security log)

---

## Skills Required

- Module 12 (defensive tools — event log theory, event IDs table, EvtQuery)
- Module 04 (Windows internals — understanding what these events mean)

---

## High-Priority Event IDs

| Event ID | Log | Meaning | Why it matters |
|----------|-----|---------|----------------|
| 4624 | Security | Successful logon | Who logged in, from where |
| 4625 | Security | Failed logon | Brute force attempts |
| 4648 | Security | Logon with explicit credentials | Lateral movement indicator |
| 4672 | Security | Special privileges assigned | Admin logon |
| 4688 | Security | Process creation (if audited) | What was executed |
| 4698 | Security | Scheduled task created | Persistence |
| 4720 | Security | User account created | Backdoor account |
| 4776 | Security | NTLM auth attempted | Pass-the-hash indicator |
| 7045 | System | Service installed | Persistence or malware |
| 1102 | Security | Audit log cleared | Attacker covering tracks |

---

## Test Plan

1. Generate test events: fail 5 logons, then succeed.
2. Run tool against the Security log for the last 5 minutes.
3. Confirm failed logon events (4625) appear.
4. Confirm successful logon (4624) appears after them.
5. Clear the log (wevtutil cl Security) — re-run — confirm event 1102 is flagged.

---

## Report Format

```
=== LOG FORENSICS REPORT ===
Channel: Security
Window: 2026-10-01 09:00:00 → 2026-10-01 18:00:00
Generated: 2026-10-01 19:45:00

[HIGH] 14:32:11  EventID=1102  AUDIT LOG CLEARED by DOMAIN\admin
[HIGH] 14:31:08  EventID=4720  New user account created: "support_backup"
[MED]  14:30:44  EventID=4698  Scheduled task created: "SystemUpdate" → C:\Temp\update.exe
[MED]  13:15:22  EventID=4672  Special privileges: DOMAIN\admin (SeDebugPrivilege)
[INFO] 13:14:55  EventID=4624  Logon: DOMAIN\admin from 10.0.0.44 (Type 3 — Network)
[INFO] 13:14:50  EventID=4625  Failed logon: DOMAIN\admin from 10.0.0.44 (x5 attempts)

Total events in window: 847
High severity: 2
Medium severity: 2
Info: 843
```
