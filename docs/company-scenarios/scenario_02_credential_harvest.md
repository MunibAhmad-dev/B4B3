# Scenario 02 — Credential Harvest Simulation

## Client Brief

**Industry:** Healthcare  
**Team size:** 40 employees, all on Windows workstations  
**Request:** "Our incident response team wants to know what an attacker could grab
from a compromised workstation in 5 minutes. Specifically: browser saved passwords,
WiFi passwords, and Windows credentials. We've authorised a test on one machine."

---

## Objective

Build a tool that runs on the authorised test machine and:
1. Extracts Chrome saved passwords (DPAPI path)
2. Lists saved WiFi SSIDs + plaintext PSK (via netsh or WlanOpenHandle)
3. Enumerates Windows Credential Manager entries
4. Saves results to a report file on the Desktop
5. Does NOT send data to any network endpoint (blue team analysis only)

---

## Deliverable

- `CredHarvest.exe` — runs interactively, outputs report
- `credential_report.txt` — sample output on the test machine
- A 1-page risk summary: what an attacker could do with this data

---

## Skills Required

- Module 11 (credential access — DPAPI, Chrome, WiFi, CredEnumerate)
- Module 04 (Windows internals — reading registry, running as current user)

---

## Constraints

- Must run without admin rights (user-context credentials only)
- Chrome must be closed before running (DPAPI key in user profile)
- No network calls — write to a local report file only
- Report must be clearly labelled "SECURITY ASSESSMENT — AUTHORISED TEST"
- Run only on the specified test machine

---

## Test Plan

1. Add a test Chrome password entry manually.
2. Add a test WiFi network entry (or use an existing home network).
3. Add a test Windows Credential Manager entry.
4. Run the tool as a standard user (no admin).
5. Open credential_report.txt — confirm all three categories are present.
6. Confirm no network calls were made (Wireshark capture during run).

---

## Architecture Notes

Chrome password path:
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data   (SQLite)
%LOCALAPPDATA%\Google\Chrome\User Data\Local State           (DPAPI key JSON)
```

WiFi:
```
netsh wlan show profile <SSID> key=clear
```
or
```
WlanOpenHandle() → WlanEnumInterfaces() → WlanGetProfile(..., WLAN_PROFILE_GET_PLAINTEXT_KEY)
```
(Requires admin for WlanGetProfile with plaintext key in Vista+. netsh works as user for profiles the user created.)

Windows Credential Manager:
```
CredEnumerate(nullptr, 0, &count, &creds)
```
Enumerates all credentials the current user can read.
