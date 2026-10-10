# Scenario 06 — Network Inventory Tool

## Client Brief

**Industry:** SMB (50 employees, no dedicated IT)  
**Request:** "We inherited this network and have no idea what's on it.
We need a tool we can run from any Windows machine on the LAN that gives us
a list of every device: IP, hostname, open ports."

---

## Objective

Build a network inventory scanner that:
1. Auto-detects the local /24 subnet
2. For each .1–.254 address, probes common ports to detect live hosts
3. Does reverse DNS lookup on each live host
4. Prints a table: IP | Hostname | Open Ports
5. Exports to CSV

---

## Deliverable

- `NetInventory.exe` — single self-contained executable
- `inventory_YYYY-MM-DD.csv` — output file
- Runs without admin rights (TCP connect scan, no raw sockets)
- Completes a full /24 scan in under 60 seconds

---

## Skills Required

- Module 14 (network tools — port scanner, DNS resolver, subnet detection)
- Module 07 (basic Winsock)

---

## Expected CSV Format

```csv
IP,Hostname,Port22,Port80,Port443,Port445,Port3306,Port3389,Port8080
192.168.1.1,router.local,0,1,1,0,0,0,0
192.168.1.10,workstation-01.local,0,0,0,1,0,1,0
192.168.1.20,,1,1,0,0,0,0,0
```

---

## Test Plan

1. Run on a known LAN with 3+ devices.
2. Verify the router (192.168.x.1) appears with port 80 open.
3. Verify your own machine appears.
4. Open the CSV in Excel — confirm it parses correctly.
5. Measure elapsed time for a full /24 scan.

---

## Performance Target

- 254 hosts × 10 ports = 2,540 probe attempts
- With 64 concurrent threads and 500 ms timeout:
  max time = ceil(2540 / 64) × 0.5s ≈ 20 seconds
- Target: scan complete in < 30 seconds on a 100 Mbps LAN
