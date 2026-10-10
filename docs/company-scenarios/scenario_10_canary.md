# Scenario 10 — Security Awareness Canary

## Client Brief

**Industry:** Any  
**Request:** "We want to know if anyone on our network accesses a specific
sensitive-looking file that should never be opened. We'll plant it in
a shared drive. If anyone opens it, we want to know immediately —
who, when, from which machine."

---

## Objective

Build a canary file that:
1. Looks like a legitimate document (e.g. "Salaries_2026.xlsx" or "Customer_Passwords.txt")
2. When opened, silently phones home to a webhook/C2 with: machine name, username, timestamp, file path
3. Uses a minimal, one-shot design — no persistence, no further network activity
4. The phone-home should work even if the victim has no Office/Excel installed
   (so the canary is an EXE disguised with an appropriate icon + extension trick)

---

## Deliverable

- `canary_builder.py` (or C++ tool) — takes webhook URL + filename + icon, outputs canary EXE
- The canary EXE itself (named `Salaries_2026.exe` or similar)
- C2-side logging endpoint (already exists in `c2-server/routes/phish.js`)
- A report template the blue team fills in after an alert fires

---

## Skills Required

- Module 01-04 (C++ basics → Windows internals: WinMain, WinINet, no console window)
- Module 07 (WinINet HTTPS POST)
- Module 09 (beacon payload — this is basically the phishing payload from Scenario 01)
- Scenario 01 (phishing payload — reuse and adapt)

---

## Design Notes

The simplest reliable canary is an EXE that:
1. Runs silently (WinMain + -mwindows flag)
2. Collects machine name + username + timestamp
3. POSTs JSON to the webhook in one shot
4. Exits

No persistence. No loops. No file drops. One network call.

To make it look like a document:
- Rename it to `Salaries_2026.pdf.exe` (name hides true extension in Explorer by default)
- Or compile with a PDF/Excel icon embedded as a resource
- In a corporate environment, plant on a shared drive path that looks sensitive

---

## Alert Format (webhook POST body)

```json
{
  "event": "canary_opened",
  "canary_name": "Salaries_2026.pdf",
  "machine": "WORKSTATION-14",
  "user": "jsmith",
  "domain": "CORP",
  "os": "Windows 11 22H2",
  "timestamp": "2026-10-01T14:32:11Z",
  "file_path": "\\\\fileserver\\sensitive\\Salaries_2026.pdf"
}
```

---

## Test Plan

1. Build canary with webhook pointing to your C2 server's /beacon endpoint.
2. Place it on a test machine.
3. Double-click it.
4. Confirm: no console window, no UAC prompt.
5. Within 5 seconds: C2 receives the beacon with correct machine/user.
6. Process exits automatically.
7. Check Windows Defender doesn't block it (note result).

---

## Legal Note

Canary files are a defensive technique. The key requirement is that the
company owns the infrastructure where the canary is deployed. Never deploy
a canary on infrastructure you don't own or control.
