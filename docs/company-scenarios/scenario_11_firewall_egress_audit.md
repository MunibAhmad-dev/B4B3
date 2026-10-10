# Scenario 11 — Firewall Egress Audit: Tor / Dark Web Block Validation

## Brief

**Client:** Internal Security Team  
**Type:** Blue team — control validation  
**Difficulty:** Medium  

A company has deployed firewall rules intended to block employees from accessing
the Tor network and dark web. Before rolling out a security awareness policy,
the SOC team needs to **prove the controls actually work** — not assume they do.

You are given a Windows workstation on the internal network and asked to write
a tool that:

1. Attempts every known path to reach the Tor network from inside the corporate
   network.
2. Reports each path as **BLOCKED** or **REACHABLE**.
3. Produces a summary firewall effectiveness score.
4. Writes a machine-readable JSON report the SOC can feed into their SIEM.

---

## Objective

Validate that the following are all blocked by the corporate firewall:

| # | Test | Why it matters |
|---|------|---------------|
| 1 | TCP connect to Tor directory authority IPs on port 9001 | OR/relay entry point |
| 2 | TCP connect to Tor directory authority IPs on port 9030 | Directory fetching |
| 3 | TCP connect to Tor directory authority IPs on port 443 | HTTPS bridge fallback |
| 4 | DNS A-record lookup for `check.torproject.org` | DNS-based block check |
| 5 | HTTP GET to `http://check.torproject.org/` | HTTP egress |
| 6 | HTTPS GET to `https://check.torproject.org/` | HTTPS egress to Tor site |
| 7 | TCP to `meek-azure.torproject.org:443` | Meek pluggable transport |
| 8 | TCP to `snowflake.torproject.org:443` | Snowflake PT |
| 9 | DNS lookup for any `.onion` label at resolver | DNS filter check |

---

## Deliverable

`firewall_egress_tester.exe` that:

- Runs with no arguments and auto-discovers local DNS settings
- Prints a live result line per test (`[BLOCKED]` / `[REACHABLE]` / `[ERROR]`)
- Prints a summary: `X / Y tests blocked (Z%)`
- Writes `egress_report_<timestamp>.json` to the current directory

---

## Skills Required

- Module 07 (Networking / Winsock) — TCP connect, Winsock initialisation
- Module 12 (Defensive Tools) — structured reporting pattern
- Module 14 (Network Tools) — DNS resolver, port scanner patterns

---

## Constraints

- Must not install Tor or any third-party software
- Must not download or execute any payload
- Must not modify the system or firewall rules
- All tests are **read-only probe attempts** — no data is exfiltrated
- Must run as standard user (no admin required)
- Timeout per probe: 3 seconds maximum

---

## Test Plan

### Phase 1 — Baseline (no firewall)
Run on a machine with direct internet access. All 9 tests should show
`[REACHABLE]`. Confirms the tool works and the targets are up.

### Phase 2 — Behind corporate firewall
Run on an internal corporate machine. Expected: all 9 show `[BLOCKED]`.
If any show `[REACHABLE]`, the firewall has a gap — file a finding.

### Phase 3 — Partial-block check
If the company blocks only port 9001/9030 but not 443, tests 3/7/8 may
still pass. This exposes reliance on port-based (not IP/domain-based) blocking.

### Pass criteria
All 9 tests `BLOCKED` = firewall policy is effective.  
Any `REACHABLE` = open finding for the SOC.

---

## Expected Output

```
[*] Firewall Egress Audit Tool v1.0
[*] Timestamp: 2025-10-09 14:32:11
[*] Hostname:  CORP-WS-042

Running 9 egress probe tests...

[1/9] TCP 171.25.193.9:9001  (Tor DA maatuska OR)    ... [BLOCKED]
[2/9] TCP 171.25.193.9:9030  (Tor DA maatuska DIR)   ... [BLOCKED]
[3/9] TCP 86.59.21.38:443    (Tor DA tor26 HTTPS)    ... [BLOCKED]
[4/9] DNS  check.torproject.org                      ... [BLOCKED]
[5/9] HTTP http://check.torproject.org/              ... [BLOCKED]
[6/9] HTTPS check.torproject.org:443                 ... [BLOCKED]
[7/9] TCP meek-azure.torproject.org:443  (Meek PT)   ... [BLOCKED]
[8/9] TCP snowflake.torproject.org:443   (Snowflake)  ... [BLOCKED]
[9/9] DNS  facebookwkhpilnemxj3asber7cyber.onion     ... [BLOCKED]

==============================
FIREWALL EFFECTIVENESS: 9/9 tests BLOCKED (100%)
STATUS: PASS — all dark web egress paths blocked
Report saved: egress_report_20251009_143211.json
==============================
```

---

## Manual Test Procedure (Human Tester)

> **Authorization required.** This procedure must only be run by an authorized
> security team member on a corporate machine with written approval from IT/SOC.
> The goal is to confirm the firewall blocks the attempt — not to successfully
> reach the dark web.

---

### Step 1 — Download Tor Browser (official source only)

On the test machine, open a standard browser and go to:

```
https://www.torproject.org/download/
```

- Download **Tor Browser for Windows** (the `.exe` installer)
- If the download itself is blocked by the firewall → **finding: category-block
  is working at the download stage.** Document it and stop here — the firewall
  is already blocking at the first step.
- If it downloads successfully → proceed to Step 2.

---

### Step 2 — Install Tor Browser

Run the downloaded installer. It installs to your user profile by default —
**no admin rights needed.**

```
Default install path: C:\Users\<you>\Desktop\Tor Browser\
```

If the installer is blocked by an endpoint agent (e.g. CrowdStrike, Defender
Application Control) → document that as an **additional control layer** finding.

---

### Step 3 — Launch Tor Browser and attempt to connect

1. Open `Tor Browser\Start Tor Browser.exe`
2. Click **Connect** on the startup screen
3. Watch the bootstrap progress bar

**What to look for:**

| Outcome | What it means |
|---------|--------------|
| Bootstrap stalls at "Loading network status" or 0–10% | Firewall is blocking Tor directory fetches — **PASS** |
| Bootstrap stalls at "Establishing a Tor circuit" | Directory fetch succeeded but relay connections blocked — **PARTIAL PASS** |
| Bootstrap reaches 100% and browser opens | Firewall is NOT blocking Tor — **FAIL, raise a finding** |
| Error: "Tor exited during startup" | Endpoint agent killed the process — **additional control working** |

---

### Step 4 — Try built-in bridges (if Step 3 stalls)

If the standard connection fails, Tor Browser offers "pluggable transports"
that disguise traffic as normal HTTPS. Test these too:

1. Click **Configure Connection** on the startup screen
2. Under **Use a bridge**, select **Built-in bridges**
3. Try each bridge type one at a time:
   - `obfs4` — obfuscated TCP
   - `meek-azure` — tunnels through Azure CDN
   - `snowflake` — uses WebRTC via browser-based volunteers

**Expected result behind a strong firewall:** all three fail to bootstrap.  
If `meek-azure` or `snowflake` succeeds, the firewall has a gap — CDN and
WebRTC egress is not restricted. **Raise a finding for each that succeeds.**

---

### Step 5 — Attempt to visit known .onion sites

> Only attempt this if bootstrap succeeds (Step 3 or 4). If blocked, skip.

If the Tor circuit does build, navigate to these well-known test addresses to
confirm end-to-end connectivity. These are public, non-illegal reference sites:

| Site | .onion address | Purpose |
|------|---------------|---------|
| Tor Project official hidden service | `http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion` | Confirm .onion resolution works |
| DuckDuckGo search (onion) | `https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion` | Non-illegal, well-known |
| Proton Mail onion | `https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion` | Privacy service |

**Document whether each loads or times out.**

---

### Step 6 — Record and report findings

Fill in this table for the SOC report:

| Test | Result | Notes |
|------|--------|-------|
| Tor Browser download | BLOCKED / ALLOWED | |
| Tor Browser install | BLOCKED / ALLOWED | |
| Bootstrap (direct) | BLOCKED / PARTIAL / CONNECTED | % reached |
| Bridge: obfs4 | BLOCKED / CONNECTED | |
| Bridge: meek-azure | BLOCKED / CONNECTED | |
| Bridge: snowflake | BLOCKED / CONNECTED | |
| .onion: Tor Project | BLOCKED / LOADED | |
| .onion: DuckDuckGo | BLOCKED / LOADED | |
| .onion: ProtonMail | BLOCKED / LOADED | |

**Pass:** all rows = BLOCKED.  
**Fail:** any row = ALLOWED / CONNECTED / LOADED → open firewall gap finding.

---

### Step 7 — Clean up

After the test, remove Tor Browser from the machine:

1. Close Tor Browser
2. Delete the `Tor Browser` folder from the Desktop / install location
3. Empty the Recycle Bin
4. Run your C++ egress tester (`firewall_egress_tester.exe`) to confirm no
   residual Tor processes are listening on port 9050

---

## Notes for the Analyst

- A firewall that blocks only by port (9001/9030) is **weaker** than one that
  also blocks by IP or domain category. Tor increasingly uses port 443 and
  bridges to bypass port-only blocks.
- DNS-level blocking (returning NXDOMAIN) is the easiest to test and bypass —
  employees can switch to a public DNS (8.8.8.8) to circumvent it.
- True defence requires **IP reputation blocking + TLS SNI inspection** or
  a full Tor-category block in a next-gen firewall.
- This tool does NOT test whether a proxy or VPN would bypass the firewall —
  that requires a separate proxy-egress test scenario.
