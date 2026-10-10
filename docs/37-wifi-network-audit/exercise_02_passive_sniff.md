# Exercise 02 — Passive Traffic Monitoring

**Goal:** Without intercepting anyone's traffic, capture and analyse what
is passively visible on the network from your device.

**Tools:** Wireshark, bettercap

---

## Task 1 — Baseline Wireshark capture

1. Open Wireshark → select your WiFi interface → Start capture
2. Let it run for 2 minutes with no filter
3. Stop capture

Apply each filter below and answer the question:

### Filter: `arp`
- How many unique devices sent ARP requests?
- Do you see ARP replies? From whom?

### Filter: `dns`
- What domains are being queried on the network?
- Can you identify which queries are yours vs broadcast?
- Are there queries for internal hostnames (e.g. `CORP-PC-01.local`)?

### Filter: `mdns`
- mDNS (multicast DNS) is used by Apple devices and IoT
- What `.local` hostnames appear?
- Any device advertising a service (printer, Airplay, Chromecast)?

### Filter: `ssdp` or `udp port 1900`
- SSDP is UPnP discovery — smart TVs, media servers
- What devices are announcing themselves?

### Filter: `http`
- Any unencrypted HTTP traffic visible?
- What URLs? What devices?

---

## Task 2 — DNS monitoring with bettercap

```bash
# Start bettercap (run as admin)
bettercap -iface "Wi-Fi"

# Inside console:
net.probe on
net.show
set net.sniff.verbose true
set net.sniff.filter udp port 53
net.sniff on
```

Wait 5 minutes. Watch what DNS queries appear.

**Record:**
- Top 5 most queried domains
- Any queries for ad/tracking networks?
- Any queries that look like internal company hostnames?

---

## Task 3 — Identify your own traffic baseline

Run this while browsing normally for 10 minutes:

```bash
# Wireshark filter — your IP only
ip.addr == 192.168.X.YOUR_IP
```

Then export as CSV: `File → Export Packet Dissections → As CSV`

**Questions:**
1. How many packets per minute does normal browsing generate?
2. What percentage is HTTPS (port 443) vs HTTP (port 80)?
3. What DNS servers does your device use?
4. Do you see any unexpected outbound connections?

---

## Notes

Passive sniffing on a modern switched WiFi network will show you:
- All broadcast traffic (ARP, mDNS, SSDP, DHCP) — from everyone
- Your own unicast traffic
- Some multicast traffic

You will NOT see unicast traffic between two other devices on a properly
configured WPA2 AP. That requires active ARP poisoning (Exercise 03).
