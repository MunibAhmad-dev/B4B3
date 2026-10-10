# Scenario 01 — Phishing Awareness Payload

## Client Brief

**Industry:** Financial services  
**Team size:** 120 employees  
**Request:** "We want to run a phishing simulation. If an employee clicks the link,
we want to measure: did they just visit, or did they download the file too?
If they ran the file, we want to know their machine name."

---

## Objective

Build a payload that:
1. Runs silently after double-click (no console window, no UAC popup)
2. Collects: machine hostname, username, Windows version
3. Phones home to the C2 server with that data
4. Does NOT install persistence, NOT exfiltrate documents, NOT cause damage
5. Reports itself as "OneDriveHelper" in Task Manager for authenticity

---

## Deliverable

- `OneDriveHelper.exe` — the payload binary
- A screenshot showing the C2 receiving a beacon from a test machine
- A 1-page report: how many employees in the test group clicked vs. ran the file

---

## Skills Required

- Module 03 (constexpr string obfuscation — hide the C2 URL)
- Module 04 (Windows internals — WinMain, no console window)
- Module 07 (networking — WinINet HTTPS POST to C2)
- Module 09 (RAT architecture — config embedding, botId generation)

---

## Constraints

- Binary must be signed (or explain why it won't be)
- C2 URL must use HTTPS
- Payload must terminate after one successful beacon
- No Registry writes, no file drops other than itself
- Must log: timestamp, IP, machine name, username, OS version

---

## Test Plan

1. Run on a clean Windows 10/11 VM.
2. Confirm no console window appears.
3. Confirm no UAC prompt appears.
4. Confirm C2 server receives a POST with the correct JSON.
5. Confirm the process exits cleanly after the beacon.
6. Run Windows Defender scan on the binary — note the result.

---

## Notes

This is exactly what the project's RAT stub does, but stripped to just the
beacon phase. No persistence. No command loop. Think of it as a "canary binary"
for phishing awareness training.

See: the phishing landing page in `c2-server/routes/phish.js` which serves
this binary from the /dl/exe endpoint.
