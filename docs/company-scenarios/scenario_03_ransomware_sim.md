# Scenario 03 — Ransomware Readiness Test

## Client Brief

**Industry:** Manufacturing  
**Team size:** 200 employees, critical OT network adjacent  
**Request:** "We've never tested our backup and recovery process under simulated
ransomware. We need to know: how long does recovery take? Does our EDR detect
the encryption behaviour? We want a controlled simulation that we can stop
at any time."

---

## Objective

Build a ransomware simulator that:
1. Operates ONLY on a designated test directory (requires SIM_APPROVED.flag)
2. Encrypts matching files using AES-256-CBC, appending .enc extension
3. Drops a clearly-labelled fake ransom note
4. Provides a --recover flag that instantly decrypts all .enc files
5. Logs every action with timestamps to a sim_log.txt
6. Triggers EDR detection so the IR team can observe and respond

---

## Deliverable

- `RansomSim.exe` — the simulation binary
- `RansomSim.exe --recover` — recovery binary (same binary, different flag)
- An incident report template the IR team fills in during the exercise
- A summary: detection time, recovery time, gaps found

---

## Skills Required

- Module 15 (ransomware simulation — AES-256-CBC, file enumeration, sentinel file)
- Module 13 exercise 02 (file enumerator — enumerate by extension)
- Module 12 (defensive tools — understanding what EDR sees)

---

## Constraints

- Binary must contain a hard-coded test directory path — NEVER enumerate user folders
- SIM_APPROVED.flag sentinel must be checked before ANY file operation
- Recovery must be instant and complete — no data loss
- The ransom note must contain "AUTHORISED SIMULATION" in large text
- Simulation log must record: each file path, timestamp, bytes processed
- Do NOT delete originals — write .enc files alongside originals
- Do NOT simulate shadow copy deletion (even as a log message)

---

## Test Plan

1. Create C:\RansomwareSimTest\, add 10 test documents.
2. Create SIM_APPROVED.flag inside it.
3. Run RansomSim.exe — observe EDR alert (expected within 30 seconds for good EDR).
4. Record: time from first file write to EDR alert.
5. Run RansomSim.exe --recover.
6. Verify all original files are still intact, .enc files are gone.
7. Review sim_log.txt — confirm all actions logged.

---

## Incident Report Template

```
Date:          __________
Assessor:      __________
EDR Platform:  __________

Timeline:
  Simulation start:         __:__:__
  First EDR alert:          __:__:__
  Detection latency:        __ seconds
  Backup team notified:     __:__:__
  Recovery started:         __:__:__
  Recovery complete:        __:__:__
  Total downtime simulated: __ minutes

EDR Alert Details:
  Alert name:   __________
  Severity:     __________
  Action taken: __________

Gaps Found:
  [ ] No EDR alert generated
  [ ] Recovery took > 1 hour
  [ ] Backup was not current (data loss > __ hours)
  [ ] IR runbook was not followed

Recommendations:
  __________
```
