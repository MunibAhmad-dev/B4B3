#!/usr/bin/env node
/**
 * B4DB4B3-RAT Detection Coverage Tester
 * ───────────────────────────────────────
 * Runs structured test cases against the C2 detection engine to find gaps
 * in ATT&CK coverage.  For each scenario the tester:
 *
 *   1. Injects simulated telemetry events
 *   2. Queries the detection engine for fired alerts
 *   3. Checks whether expected detections (DR/COR rules) triggered
 *   4. If a gap is found → tries alternate event variants for the same technique
 *   5. Records pass / gap / partial per ATT&CK technique
 *
 * Output: console report  +  JSON saved to coverage-report-<timestamp>.json
 *         (also POSTed to the C2 server at /api/coverage-run)
 *
 * Usage:
 *   node coverage-tester.js [options]
 *
 * Options:
 *   --host      C2 hostname        (default: localhost)
 *   --port      C2 port            (default: 443)
 *   --auth      C2 auth key        (default: changeme)
 *   --botId     Test bot prefix    (default: COV)  — gets _<runId> suffix
 *   --delay     ms between events  (default: 300)
 *   --http      Use plain HTTP
 *   --save      Save JSON report   (default: true)
 */

"use strict";

const https = require("https");
const http  = require("http");
const fs    = require("fs");
const path  = require("path");

// ── Argument parsing ──────────────────────────────────────────────────────────

const args = {};
process.argv.slice(2).forEach((a, i, arr) => {
  if (a.startsWith("--")) {
    const key = a.slice(2);
    const next = arr[i + 1];
    args[key] = (next && !next.startsWith("--")) ? next : true;
  }
});

const HOST     = args.host  || "localhost";
const PORT     = parseInt(args.port || "443", 10);
const AUTH     = args.auth  || "changeme";
const BOT_PFX  = args.botId || "COV";
const DELAY_MS = parseInt(args.delay || "300", 10);
const USE_HTTP = args.http === true || args.http === "true";
const DO_SAVE  = args.save !== "false";
const transport = USE_HTTP ? http : https;
const proto     = USE_HTTP ? "http" : "https";

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function request(method, urlPath, body = null) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: HOST, port: PORT, path: urlPath, method,
      headers: {}, rejectUnauthorized: false,
    };
    if (body) {
      const d = JSON.stringify(body);
      opts.headers["Content-Type"]   = "application/json";
      opts.headers["Content-Length"] = Buffer.byteLength(d);
    }
    const req = transport.request(opts, res => {
      let buf = "";
      res.on("data", d => buf += d);
      res.on("end",  () => resolve({ status: res.statusCode, body: buf }));
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function checkin(botId, label) {
  const info = encodeURIComponent(`WIN-COV-LAB | CoverageTester | x64 | ${label}`);
  return request("GET", `/checkin?id=${botId}&auth=${AUTH}&info=${info}`);
}

function sendEvent(botId, evt) {
  return request("POST", `/event?id=${botId}&auth=${AUTH}`, { ...evt, bot: botId });
}

function getBot(botId) {
  return request("GET", `/api/bot/${botId}`, null)
    .then(r => JSON.parse(r.body));
}

function postCoverageRun(run) {
  // Admin session needed — skip silently if no cookie jar (CLI context)
  return request("POST", `/api/coverage-run?auth=${AUTH}`, run).catch(() => null);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Event library ─────────────────────────────────────────────────────────────

const EVT = {
  exec_temp:      { cat:"process",    type:"spawn",      sev:"medium", rule:"PROC_002", ev:"[COV] Process launched from Temp",      path:"C:\\Users\\lab\\AppData\\Local\\Temp\\test.exe",            tid:"T1204.002", tname:"User Execution: Malicious File"        },
  exec_appdata:   { cat:"process",    type:"spawn",      sev:"medium", rule:"PROC_003", ev:"[COV] Process launched from AppData",    path:"C:\\Users\\lab\\AppData\\Roaming\\test.exe",                tid:"T1204.002", tname:"User Execution: Malicious File"        },
  discovery_procs:{ cat:"process",    type:"enum",       sev:"low",    rule:"PROC_001", ev:"[COV] Process enumeration",                                                                                  tid:"T1057",     tname:"Process Discovery"                     },
  discovery_net:  { cat:"network",    type:"enum",       sev:"low",    rule:"NET_001",  ev:"[COV] TCP table enumeration",                                                                                tid:"T1049",     tname:"System Network Connections Discovery"   },
  persist_reg:    { cat:"registry",   type:"write",      sev:"high",   rule:"REG_001",  ev:"[COV] Registry Run key written", hive:"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", value:"TestKey", tid:"T1547.001", tname:"Boot/Logon Autostart: Registry Run Keys" },
  persist_regmod: { cat:"registry",   type:"modify",     sev:"high",   rule:"REG_002",  ev:"[COV] Registry RunOnce key modified",    hive:"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", value:"TestOnce", tid:"T1547.001", tname:"Boot/Logon Autostart: Registry Run Keys" },
  persist_svc:    { cat:"service",    type:"create",     sev:"high",   rule:"SVC_001",  ev:"[COV] New service created",              service:"CovTestSvc",                                              tid:"T1543.003", tname:"Create or Modify System Process: Win Service" },
  c2_port:        { cat:"network",    type:"connect",    sev:"high",   rule:"NET_002",  ev:"[COV] C2 connection on non-standard port", remote:"10.0.0.50:4444",                                         tid:"T1571",     tname:"Non-Standard Port"                    },
  file_drop:      { cat:"file",       type:"create",     sev:"medium", rule:"FILE_001", ev:"[COV] Executable dropped to Temp",       path:"C:\\Users\\lab\\AppData\\Local\\Temp\\cov.exe",              tid:"T1105",     tname:"Ingress Tool Transfer"                },
  sim_screenshot: { cat:"collection", type:"simulation", sev:"medium", rule:"SCR_001",  ev:"[COV] Screen capture simulated",         simulated:true,                                                    tid:"T1113",     tname:"Screen Capture"                        },
  sim_camera:     { cat:"collection", type:"simulation", sev:"medium", rule:"CAM_001",  ev:"[COV] Camera access simulated",          simulated:true,                                                    tid:"T1125",     tname:"Video Capture"                         },
  sim_mic:        { cat:"collection", type:"simulation", sev:"medium", rule:"MIC_001",  ev:"[COV] Microphone access simulated",      simulated:true,                                                    tid:"T1123",     tname:"Audio Capture"                         },
  sim_cred:       { cat:"collection", type:"simulation", sev:"high",   rule:"CRED_001", ev:"[COV] Credential store access simulated",simulated:true,                                                    tid:"T1555",     tname:"Credentials from Password Stores"      },
  sim_filecol:    { cat:"collection", type:"simulation", sev:"low",    rule:"FCOL_001", ev:"[COV] File metadata collection simulated",simulated:true,                                                   tid:"T1005",     tname:"Data from Local System"                },
};

// ── Test cases ────────────────────────────────────────────────────────────────
// Each test: primary event sequence → expected detection rules.
// variants: alternate event sequences for the same technique (tested if primary fails).
// remediations: blue-team fixes for when this technique has a gap.

const TEST_CASES = [
  {
    id: "TC_001", name: "Registry Run Key Persistence",
    tid: "T1547.001", tname: "Boot/Logon Autostart: Registry Run Keys", phase: "Persistence",
    events:      ["persist_reg"],
    expectedDR:  ["DR_003"],
    variants:    [{ label:"RunOnce key", events:["persist_regmod"], expectedDR:["DR_004"] }],
    sigmaRule:   "sigma/run_key_persistence.yml",
    remediations: [
      "Enable Sysmon Event ID 13 (RegistryValueSet) for HKCU/HKLM Run/RunOnce keys",
      "Alert on registry writes by processes not in the software-install allowlist",
    ],
  },
  {
    id: "TC_002", name: "Service-Based Persistence",
    tid: "T1543.003", tname: "Create or Modify System Process: Windows Service", phase: "Persistence",
    events:     ["persist_svc"],
    expectedDR: ["DR_006"],
    variants:   [],
    sigmaRule:  "sigma/unusual_service_creation.yml",
    remediations: [
      "Monitor Windows Event ID 7045 (new service installed)",
      "Baseline known services; alert on any new service name not in the baseline",
    ],
  },
  {
    id: "TC_003", name: "Malicious Execution from Temp",
    tid: "T1204.002", tname: "User Execution: Malicious File", phase: "Execution",
    events:     ["exec_temp"],
    expectedDR: ["DR_001"],
    variants:   [{ label:"AppData execution", events:["exec_appdata"], expectedDR:["DR_002"] }],
    sigmaRule:  "sigma/self_copying_executable.yml",
    remediations: [
      "Enable Sysmon Event ID 1 (ProcessCreate); filter on image path containing Temp or AppData",
      "Consider Software Restriction Policies or AppLocker to block execution from %TEMP%",
    ],
  },
  {
    id: "TC_004", name: "C2 on Non-Standard Port",
    tid: "T1571", tname: "Non-Standard Port", phase: "C2",
    events:     ["c2_port"],
    expectedDR: ["DR_005"],
    variants:   [],
    sigmaRule:  "sigma/rat_c2_communication.yml",
    remediations: [
      "Implement egress firewall rules; only allow HTTPS (443) and DNS (53) outbound from endpoints",
      "Deploy network-layer DPI to detect non-browser HTTPS traffic",
    ],
  },
  {
    id: "TC_005", name: "Process Discovery",
    tid: "T1057", tname: "Process Discovery", phase: "Discovery",
    events:     ["discovery_procs"],
    expectedDR: ["DR_009"],
    variants:   [],
    sigmaRule:  null,
    remediations: [
      "Alert on CreateToolhelp32Snapshot calls from processes not in an enumeration allowlist",
      "Combine with other discovery indicators — process enumeration alone has high FP rate",
    ],
  },
  {
    id: "TC_006", name: "Network Connections Discovery",
    tid: "T1049", tname: "System Network Connections Discovery", phase: "Discovery",
    events:     ["discovery_net"],
    expectedDR: ["DR_008"],
    variants:   [],
    sigmaRule:  null,
    remediations: [
      "Monitor GetExtendedTcpTable API usage from non-system processes",
      "Consider hunting for processes that combine network enumeration with C2 activity",
    ],
  },
  {
    id: "TC_007", name: "Ingress Tool Transfer",
    tid: "T1105", tname: "Ingress Tool Transfer", phase: "Collection",
    events:     ["file_drop"],
    expectedDR: ["DR_007"],
    variants:   [],
    sigmaRule:  "sigma/self_copying_executable.yml",
    remediations: [
      "Enable Sysmon Event ID 11 (FileCreate); alert on PE files written to Temp/AppData",
      "Enable Windows Defender PUA protection and real-time monitoring",
    ],
  },
  {
    id: "TC_008", name: "Screen Capture",
    tid: "T1113", tname: "Screen Capture", phase: "Collection",
    events:     ["sim_screenshot"],
    expectedDR: ["DR_012"],
    variants:   [],
    sigmaRule:  "sigma/unusual_screenshot_activity.yml",
    remediations: [
      "Monitor GDI BitBlt + GetDC API calls from non-UI background processes",
      "Alert on JPEG/PNG file creation in Temp by non-imaging applications",
    ],
  },
  {
    id: "TC_009", name: "Camera Access",
    tid: "T1125", tname: "Video Capture", phase: "Collection",
    events:     ["sim_camera"],
    expectedDR: ["DR_010"],
    variants:   [],
    sigmaRule:  null,
    remediations: [
      "Enable Windows Privacy audit log for camera access (Event ID 4688 + DeviceIoControl)",
      "Alert on camera device access from non-video-conferencing processes",
      "Windows 11: use Privacy Dashboard to review camera access history",
    ],
  },
  {
    id: "TC_010", name: "Microphone Access",
    tid: "T1123", tname: "Audio Capture", phase: "Collection",
    events:     ["sim_mic"],
    expectedDR: ["DR_011"],
    variants:   [],
    sigmaRule:  null,
    remediations: [
      "Monitor WASAPI/DirectSound device open calls from non-audio processes",
      "Windows 11: Privacy Dashboard microphone access history",
      "Consider blocking microphone API access in process isolation policy",
    ],
  },
  {
    id: "TC_011", name: "Credential Store Access",
    tid: "T1555", tname: "Credentials from Password Stores", phase: "CredAccess",
    events:     ["sim_cred"],
    expectedDR: ["DR_013"],
    variants:   [],
    sigmaRule:  null,
    remediations: [
      "Enable DPAPI audit events; monitor CryptUnprotectData calls from unexpected processes",
      "Alert on Windows Credential Manager API access outside known password managers",
      "Deploy PAM solution to enforce credential access controls",
    ],
  },
  {
    id: "TC_012", name: "Full Deployment Correlation",
    tid: "COR_001", tname: "RAT Deploy: Execution + Persistence + C2", phase: "Correlation",
    events:     ["exec_temp", "persist_reg", "c2_port"],
    expectedDR: ["DR_001", "DR_003", "DR_005"],
    expectedCOR:["COR_001"],
    variants:   [],
    sigmaRule:  null,
    remediations: [
      "Ensure correlation engine window (300s) covers typical dropper dwell time",
      "Tune confidence threshold: COR_001 at 90% should always alert",
    ],
  },
  {
    id: "TC_013", name: "Surveillance Collection Correlation",
    tid: "COR_006", tname: "Full Surveillance: Camera + Mic + Screen", phase: "Correlation",
    events:     ["sim_camera", "sim_mic", "sim_screenshot"],
    expectedDR: ["DR_010", "DR_011", "DR_012"],
    expectedCOR:["COR_006"],
    variants:   [],
    sigmaRule:  null,
    remediations: [
      "COR_006 fires when av + audio + screenshot tags co-occur — ensure all three DR rules are active",
    ],
  },
];

// ── Coverage test runner ──────────────────────────────────────────────────────

const HR = "─".repeat(64);
const PASS  = "\x1b[32m✓ PASS\x1b[0m";
const FAIL  = "\x1b[31m✗ GAP \x1b[0m";
const PART  = "\x1b[33m~ PARTIAL\x1b[0m";

async function runTest(tc, botId) {
  // Send primary event sequence
  for (const key of tc.events) {
    const evt = EVT[key];
    if (!evt) continue;
    const r = await sendEvent(botId, { ...evt, bot: botId }).catch(() => null);
    if (!r || r.status >= 400) return { result:"ERROR", reason:`Send failed: ${key}` };
    if (DELAY_MS > 0) await sleep(DELAY_MS);
  }

  // Query detection state
  const bot = await getBot(botId).catch(() => null);
  if (!bot) return { result:"ERROR", reason:"Could not query bot state" };

  const firedDR  = new Set((bot.detections  || []).map(d => d.dr_id));
  const firedCOR = new Set((bot.incidents   || []).map(i => i.cor_id));

  const drMissed  = (tc.expectedDR  || []).filter(id => !firedDR.has(id));
  const corMissed = (tc.expectedCOR || []).filter(id => !firedCOR.has(id));

  if (drMissed.length === 0 && corMissed.length === 0) {
    return {
      result: "PASS",
      firedDR:  [...firedDR],
      firedCOR: [...firedCOR],
      variant:  null,
    };
  }

  // Try variants for DR gaps
  for (const variant of (tc.variants || [])) {
    for (const key of variant.events) {
      const evt = EVT[key];
      if (!evt) continue;
      await sendEvent(botId, { ...evt, bot: botId }).catch(() => null);
      if (DELAY_MS > 0) await sleep(DELAY_MS);
    }
    const bot2 = await getBot(botId).catch(() => null);
    if (!bot2) continue;
    const firedDR2  = new Set((bot2.detections || []).map(d => d.dr_id));
    const firedCOR2 = new Set((bot2.incidents  || []).map(i => i.cor_id));
    const stillMissedDR  = (variant.expectedDR  || tc.expectedDR  || []).filter(id => !firedDR2.has(id));
    const stillMissedCOR = (tc.expectedCOR || []).filter(id => !firedCOR2.has(id));
    if (stillMissedDR.length === 0 && stillMissedCOR.length === 0) {
      return {
        result:   "PARTIAL",
        firedDR:  [...firedDR2],
        firedCOR: [...firedCOR2],
        variant:  variant.label,
        note:     `Primary missed [${drMissed.join(",")}]; variant "${variant.label}" succeeded`,
      };
    }
  }

  return {
    result:   "GAP",
    firedDR:  [...firedDR],
    firedCOR: [...firedCOR],
    missedDR: drMissed,
    missedCOR: corMissed,
    variant:  null,
  };
}

async function run() {
  const runId   = `RUN_${Date.now()}`;
  const botId   = `${BOT_PFX}_${runId.slice(4, 14)}`;
  const startMs = Date.now();

  console.log(HR);
  console.log("B4DB4B3-RAT  Detection Coverage Tester");
  console.log(HR);
  console.log(`Target  : ${proto}://${HOST}:${PORT}`);
  console.log(`Run ID  : ${runId}`);
  console.log(`Test bot: ${botId}`);
  console.log(`Tests   : ${TEST_CASES.length}`);
  console.log(HR);

  // Check-in
  process.stdout.write("[+] Registering test bot ... ");
  const ci = await checkin(botId, runId).catch(e => ({ error: e.message }));
  if (ci.error || ci.status !== 200) {
    console.log(`FAILED: ${ci.error || "HTTP " + ci.status}`);
    process.exit(1);
  }
  console.log("OK\n");

  const results = [];

  for (const tc of TEST_CASES) {
    process.stdout.write(`  [${tc.id}] ${tc.name.padEnd(42)} `);
    const res = await runTest(tc, botId);
    const icon = res.result === "PASS" ? PASS : res.result === "PARTIAL" ? PART : FAIL;
    console.log(icon + (res.note ? `  (${res.note})` : ""));
    results.push({ ...tc, ...res, timestamp: new Date().toISOString() });
  }

  // ── Summary ───────────────────────────────────────────────────────────────

  const pass    = results.filter(r => r.result === "PASS").length;
  const partial = results.filter(r => r.result === "PARTIAL").length;
  const gap     = results.filter(r => r.result === "GAP").length;
  const coveragePct = Math.round((pass + partial * 0.5) / TEST_CASES.length * 100);
  const elapsed = ((Date.now() - startMs) / 1000).toFixed(1);

  console.log("\n" + HR);
  console.log("Coverage Report");
  console.log(HR);
  console.log(`Passed   : ${pass}  / ${TEST_CASES.length}`);
  console.log(`Partial  : ${partial}  (primary failed but variant succeeded)`);
  console.log(`Gaps     : ${gap}  (no detection fired for any variation)`);
  console.log(`Coverage : ${coveragePct}%  (${pass} full + ${partial} partial)`);
  console.log(`Duration : ${elapsed}s`);

  const gaps = results.filter(r => r.result === "GAP");
  if (gaps.length) {
    console.log("\n\x1b[31mDetection Coverage Gaps:\x1b[0m");
    for (const g of gaps) {
      console.log(`\n  ${g.id}  ${g.tid}  —  ${g.name}`);
      console.log(`  Phase: ${g.phase}`);
      if (g.missedDR?.length)  console.log(`  Missing DR  : ${g.missedDR.join(", ")}`);
      if (g.missedCOR?.length) console.log(`  Missing COR : ${g.missedCOR.join(", ")}`);
      if (g.sigmaRule) console.log(`  Sigma rule  : ${g.sigmaRule}  (deploy to close gap)`);
      if (g.remediations?.length) {
        console.log("  Remediation:");
        g.remediations.forEach(r => console.log(`    • ${r}`));
      }
    }
  } else {
    console.log("\n\x1b[32mAll techniques detected — no coverage gaps found.\x1b[0m");
  }

  // ATT&CK coverage matrix (text)
  console.log("\n" + HR);
  console.log("ATT&CK Coverage Matrix");
  console.log(HR);
  const phases = [...new Set(results.map(r => r.phase))];
  for (const ph of phases) {
    const phResults = results.filter(r => r.phase === ph);
    const phBar = phResults.map(r => r.result === "PASS" ? "\x1b[32m█\x1b[0m" : r.result === "PARTIAL" ? "\x1b[33m▓\x1b[0m" : "\x1b[31m░\x1b[0m").join("");
    console.log(`  ${ph.padEnd(14)}  ${phBar}  ${phResults.filter(r=>r.result==="PASS").length}/${phResults.length}`);
  }
  console.log("  Legend: \x1b[32m█\x1b[0m=Detected  \x1b[33m▓\x1b[0m=Partial  \x1b[31m░\x1b[0m=Gap");

  // Blue-team recommendations summary
  if (gaps.length) {
    console.log("\n" + HR);
    console.log("Blue-Team Remediation Recommendations");
    console.log(HR);
    const allRec = [...new Set(gaps.flatMap(g => g.remediations || []))];
    allRec.forEach((r, i) => console.log(`  ${String(i+1).padStart(2)}. ${r}`));
  }

  console.log("\n" + HR);

  // ── Persist report ────────────────────────────────────────────────────────

  const report = {
    runId,
    timestamp:    new Date().toISOString(),
    botId,
    host:         `${HOST}:${PORT}`,
    durationMs:   Date.now() - startMs,
    total:        TEST_CASES.length,
    pass, partial, gap, coveragePct,
    tests: results.map(r => ({
      id:          r.id,
      name:        r.name,
      tid:         r.tid,
      phase:       r.phase,
      result:      r.result,
      variant:     r.variant || null,
      firedDR:     r.firedDR  || [],
      firedCOR:    r.firedCOR || [],
      missedDR:    r.missedDR  || [],
      missedCOR:   r.missedCOR || [],
      sigmaRule:   r.sigmaRule || null,
      remediations:r.remediations || [],
      note:        r.note || null,
    })),
    gaps: gaps.map(g => ({
      id: g.id, tid: g.tid, name: g.name, phase: g.phase,
      missedDR: g.missedDR, sigmaRule: g.sigmaRule,
      remediations: g.remediations,
    })),
  };

  if (DO_SAVE) {
    const fname = `coverage-report-${Date.now()}.json`;
    const fpath = path.join(__dirname, fname);
    fs.writeFileSync(fpath, JSON.stringify(report, null, 2));
    console.log(`Report saved: ${fpath}`);
  }

  // POST to server (best-effort, doesn't require admin session in this flow)
  await postCoverageRun(report);

  process.exit(gap > 0 ? 1 : 0); // non-zero exit = gaps found (useful for CI)
}

run().catch(err => {
  console.error("Fatal:", err.message);
  process.exit(2);
});
