# Scenario 08 — Internal Port Scanner

## Client Brief

**Industry:** Hospital (HIPAA compliance)  
**Request:** "Our compliance audit requires us to show that no unexpected ports
are open on our internal servers. We need a tool that can scan a list of
target IPs/CIDRs and produce a report showing what's open vs. what's expected."

---

## Objective

Build an authorised internal port scanner that:
1. Accepts a target list: individual IPs, ranges (192.168.1.1-50), CIDR (/24)
2. Scans a configurable port set (full 1-65535, top-1000, or custom list)
3. Grabs banners from open ports for service identification
4. Compares results against a whitelist: "server X should only have ports Y,Z open"
5. Flags any port open that is NOT in the whitelist as UNEXPECTED
6. Produces a compliance report

---

## Deliverable

- `PortScan.exe --targets targets.txt --whitelist whitelist.json --report report.txt`
- `targets.txt` — one IP/range per line
- `whitelist.json` — expected open ports per host
- `report.txt` — findings sorted by severity

---

## Skills Required

- Module 14 (network tools — threaded port scanner, banner grabbing)
- Module 07 (Winsock)

---

## Whitelist Format

```json
{
  "192.168.1.1": { "expected": [80, 443, 22], "name": "router" },
  "192.168.1.10": { "expected": [3389, 445], "name": "workstation-01" },
  "192.168.1.100": { "expected": [80, 443, 3306], "name": "web-db-server" }
}
```

Findings are classified:
- **EXPECTED** — port is open and in whitelist (compliant)
- **UNEXPECTED** — port is open but NOT in whitelist (violation, investigate)
- **MISSING** — port is in whitelist but NOT open (may indicate service failure)

---

## Test Plan

1. Set up a local VM with known open ports (e.g. nginx on 80, SSH on 22).
2. Create whitelist.json — list only port 80 as expected.
3. Run scan — confirm port 22 appears as UNEXPECTED.
4. Add port 22 to whitelist — re-scan — confirm it is now EXPECTED.
5. Stop nginx — re-scan — confirm port 80 appears as MISSING.

---

## Compliance Report Format

```
INTERNAL PORT SCAN — COMPLIANCE REPORT
Date: 2026-10-01
Assessor: [name]

SUMMARY
  Hosts scanned:  12
  UNEXPECTED open ports: 3
  MISSING expected ports: 1

VIOLATIONS (require immediate investigation):
  192.168.1.100  :4444  OPEN  (no whitelist entry) — banner: nc/netcat
  192.168.1.100  :6379  OPEN  (no whitelist entry) — banner: Redis 6.2.1
  192.168.1.200  :23    OPEN  (no whitelist entry) — banner: telnet login

WARNING (expected port not responding):
  192.168.1.100  :443   CLOSED (expected OPEN) — possible service failure
```
