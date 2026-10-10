# Exercise 01 — Network Discovery

**Goal:** Map every device on the company WiFi. Identify IP cameras, smart TVs,
IoT devices, PCs, and phones.

**Time estimate:** 30 minutes  
**Tools needed:** nmap, Wireshark

---

## Task 1 — Find your own network info

Run the following and fill in the blanks:

```cmd
ipconfig /all
```

Record:
- Your IP address: `192.168.___.___`
- Subnet mask: `255.255.255.___`
- Gateway (router IP): `192.168.___.___`
- Your WiFi adapter MAC: `___:___:___:___:___:___`
- DNS server: `___.___.___:___`

---

## Task 2 — Ping sweep

```bash
nmap -sn 192.168.X.0/24
```

Replace `X` with your subnet. Save output:

```bash
nmap -sn 192.168.X.0/24 -oN scan_hosts.txt
```

**Questions:**
1. How many devices responded?
2. Can you identify the router by its MAC vendor?
3. Are any vendor names unexpected?

---

## Task 3 — IoT and camera hunt

```bash
# Scan for camera/streaming/IoT ports
nmap -p 554,8080,8443,1935,7547,9999,49152 --open 192.168.X.0/24

# Run UPnP discovery
nmap --script=upnp-info 192.168.X.0/24

# Identify devices with HTTP interfaces
nmap -p 80,8080 --open 192.168.X.0/24
```

For each device with port 80 open, open `http://192.168.X.YYY` in a browser.
Many IoT devices (cameras, smart plugs, routers) have a web UI here.

**Questions:**
1. Did you find any IP cameras (port 554 open)?
2. Are there devices with unexplained open ports?
3. Do any web interfaces load without a password prompt?

---

## Task 4 — OS and service fingerprinting

Pick 3 devices from your scan and run:

```bash
nmap -A -T4 192.168.X.YYY
```

**Record for each:**
- Device type (PC, phone, printer, IoT)
- OS guess
- Open ports and what service nmap thinks is on each

---

## Task 5 — DHCP lease table

On Windows, the router admin panel (usually `http://192.168.1.1`) has a
DHCP leases page showing every device that has connected with:
- Hostname they reported
- MAC address
- IP they were assigned
- Lease expiry

Compare this against your nmap scan — any devices in DHCP but not
responding to ping?  Those may be asleep or using ping-block firewalls.

---

## Expected deliverable

A table:

| IP | MAC | Vendor | Hostname | Ports open | Device type |
|----|-----|--------|----------|-----------|------------|
| 192.168.1.1 | ... | TP-Link | router | 80,443 | Router |
| 192.168.1.23 | ... | Apple | iPhone-Munib | — | Phone |
| ... | | | | | |
