#!/usr/bin/env node
/**
 * B4DB4B3-RAT Attack Simulator
 * ─────────────────────────────
 * Sends realistic telemetry events to the C2 server to exercise the
 * detection and correlation pipeline WITHOUT adding new offensive
 * capabilities to the stub binary.
 *
 * Usage:
 *   node simulator.js [options]
 *
 * Options:
 *   --host      C2 hostname        (default: localhost)
 *   --port      C2 port            (default: 443)
 *   --auth      C2 auth key        (default: changeme)
 *   --botId     Simulated bot ID   (default: SIM_001)
 *   --scenario  Scenario to run    (default: full)
 *               full | persistence | discovery | c2_beacon | dropper
 *   --delay     ms between events  (default: 500)
 *   --http      Use plain HTTP instead of HTTPS
 */

"use strict";

const https = require("https");
const http  = require("http");

// ── Argument parsing ──────────────────────────────────────────────────────────

const args = {};
process.argv.slice(2).forEach((a, i, arr) => {
  if (a.startsWith("--")) {
    const key = a.slice(2);
    const next = arr[i + 1];
    args[key] = (next && !next.startsWith("--")) ? next : true;
  }
});

const HOST     = args.host     || "localhost";
const PORT     = parseInt(args.port  || "443", 10);
const AUTH     = args.auth     || "changeme";
const BOT_ID   = args.botId    || "SIM_001";
const SCENARIO = (args.scenario || "full").toLowerCase();
const DELAY_MS = parseInt(args.delay || "500", 10);
const USE_HTTP = args.http === true || args.http === "true";
const transport = USE_HTTP ? http : https;
const proto     = USE_HTTP ? "http" : "https";

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function request(method, urlPath, body = null) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname:           HOST,
      port:               PORT,
      path:               urlPath,
      method,
      headers:            {},
      rejectUnauthorized: false, // allow self-signed lab cert
    };
    if (body) {
      const data = JSON.stringify(body);
      opts.headers["Content-Type"]   = "application/json";
      opts.headers["Content-Length"] = Buffer.byteLength(data);
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

function checkin() {
  const info = encodeURIComponent(`WIN-SIM-LAB | Simulator | x64 | ${new Date().toISOString()}`);
  return request("GET", `/checkin?id=${BOT_ID}&auth=${AUTH}&info=${info}`);
}

function sendEvent(evt) {
  return request("POST", `/event?id=${BOT_ID}&auth=${AUTH}`, { ...evt, bot: BOT_ID });
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ── Event library ─────────────────────────────────────────────────────────────
// Each event matches the Telemetry.cpp Emit() JSON schema. The `rule` field
// is matched by the server's DETECTION_RULES table to fire detections.

const EVENTS = {

  // ── Execution ────────────────────────────────────────────────────────────────
  exec_temp: {
    cat: "process", type: "spawn", sev: "medium",
    rule: "PROC_002",
    ev:   "Process launched from Temp: C:\\Users\\lab\\AppData\\Local\\Temp\\update.exe",
    path: "C:\\Users\\lab\\AppData\\Local\\Temp\\update.exe",
    tid: "T1204.002", tname: "User Execution: Malicious File",
    phase: "Execution",
  },
  exec_appdata: {
    cat: "process", type: "spawn", sev: "medium",
    rule: "PROC_003",
    ev:   "Process launched from AppData: C:\\Users\\lab\\AppData\\Roaming\\svchost32.exe",
    path: "C:\\Users\\lab\\AppData\\Roaming\\svchost32.exe",
    tid: "T1204.002", tname: "User Execution: Malicious File",
    phase: "Execution",
  },

  // ── Discovery ────────────────────────────────────────────────────────────────
  discovery_procs: {
    cat: "process", type: "enum", sev: "low",
    rule: "PROC_001",
    ev:   "Process enumeration via CreateToolhelp32Snapshot",
    tid: "T1057", tname: "Process Discovery",
    phase: "Discovery",
  },
  discovery_net: {
    cat: "network", type: "enum", sev: "low",
    rule: "NET_001",
    ev:   "TCP table enumeration via GetExtendedTcpTable",
    tid: "T1049", tname: "System Network Connections Discovery",
    phase: "Discovery",
  },

  // ── Persistence ──────────────────────────────────────────────────────────────
  persist_reg_run: {
    cat: "registry", type: "write", sev: "high",
    rule: "REG_001",
    ev:   "Autorun key written: HKCU\\...\\Run\\B4B3Update",
    hive:  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    value: "B4B3Update",
    tid: "T1547.001", tname: "Boot/Logon Autostart: Registry Run Keys",
    phase: "Persistence",
  },
  persist_reg_runonce: {
    cat: "registry", type: "modify", sev: "high",
    rule: "REG_002",
    ev:   "RunOnce key modified: HKLM\\...\\RunOnce\\SvcUpdater",
    hive:  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    value: "SvcUpdater",
    tid: "T1547.001", tname: "Boot/Logon Autostart: Registry Run Keys",
    phase: "Persistence",
  },
  persist_service: {
    cat: "service", type: "create", sev: "high",
    rule: "SVC_001",
    ev:   "New service created: B4B3UpdateSvc",
    service: "B4B3UpdateSvc",
    tid: "T1543.003", tname: "Create or Modify System Process: Win Service",
    phase: "Persistence",
  },

  // ── C2 ───────────────────────────────────────────────────────────────────────
  c2_port: {
    cat: "network", type: "connect", sev: "high",
    rule: "NET_002",
    ev:   "Outbound connection on non-standard port: 10.0.0.50:4444",
    remote: "10.0.0.50:4444",
    tid: "T1571", tname: "Non-Standard Port",
    phase: "C2",
  },

  // ── Collection ───────────────────────────────────────────────────────────────
  file_drop: {
    cat: "file", type: "create", sev: "medium",
    rule: "FILE_001",
    ev:   "Executable dropped to Temp: C:\\Users\\lab\\AppData\\Local\\Temp\\payload.exe",
    path: "C:\\Users\\lab\\AppData\\Local\\Temp\\payload.exe",
    tid: "T1105", tname: "Ingress Tool Transfer",
    phase: "Collection",
  },

  // ── Simulation-only events (no real device access) ─────────────────────────
  // These emit the same JSON schema as real events but are purely synthetic.
  // Use pre-recorded WAV/video files in the lab instead of live device access.
  sim_screenshot: {
    cat: "collection", type: "simulation", sev: "medium",
    rule: "SCR_001",
    ev:   "[SIM] Screen capture initiated — no live capture, using pre-recorded frame",
    simulated: true,
    tid: "T1113", tname: "Screen Capture",
    phase: "Collection",
  },
  sim_camera: {
    cat: "collection", type: "simulation", sev: "medium",
    rule: "CAM_001",
    ev:   "[SIM] Camera access requested — CAMERA_ACCESS_REQUESTED event emitted (no recording)",
    simulated: true,
    result: "simulated",
    tid: "T1125", tname: "Video Capture",
    phase: "Collection",
  },
  sim_microphone: {
    cat: "collection", type: "simulation", sev: "medium",
    rule: "MIC_001",
    ev:   "[SIM] Microphone access requested — MICROPHONE_ACCESS_REQUESTED event emitted (pre-recorded WAV)",
    simulated: true,
    duration_s: 10,
    result: "simulated",
    tid: "T1123", tname: "Audio Capture",
    phase: "Collection",
  },
  sim_file_collection: {
    cat: "collection", type: "simulation", sev: "low",
    rule: "FCOL_001",
    ev:   "[SIM] File metadata collection — directory walk, filenames/sizes only (no content read)",
    simulated: true,
    tid: "T1005", tname: "Data from Local System",
    phase: "Collection",
  },
  sim_credential: {
    cat: "collection", type: "simulation", sev: "high",
    rule: "CRED_001",
    ev:   "[SIM] Credential store access attempted — CREDENTIAL_ACCESS_SIMULATION event (no real extraction)",
    simulated: true,
    tid: "T1555", tname: "Credentials from Password Stores",
    phase: "CredAccess",
  },
};

// ── Scenarios ─────────────────────────────────────────────────────────────────
// Each scenario is an ordered list of event keys. Ordering matters because the
// correlation engine looks for co-occurring tags within a time window.

const SCENARIOS = {
  // All attack phases — triggers COR_001 (Execution + Persistence + C2, 90% confidence)
  full: [
    "exec_temp",        // Execution       → DR_001 [proc_suspicious]
    "discovery_procs",  // Discovery       → DR_009 [discovery]
    "file_drop",        // Collection      → DR_007 [file_drop]
    "persist_reg_run",  // Persistence     → DR_003 [persistence]
    "c2_port",          // C2              → DR_005 [network_c2]
    "exec_appdata",     // Execution again → DR_002 [proc_suspicious]
    "discovery_net",    // Discovery       → DR_008 [network]
    "persist_service",  // Persistence     → DR_006 [persistence]
  ],

  // Only persistence mechanics — triggers COR rule for persistence
  persistence: [
    "persist_reg_run",
    "persist_reg_runonce",
    "persist_service",
  ],

  // Only discovery activity
  discovery: [
    "discovery_procs",
    "discovery_net",
  ],

  // Repeated C2 connections — exercises beaconing detection (CV analysis)
  c2_beacon: [
    "c2_port",
    "c2_port",
    "c2_port",
    "c2_port",
    "c2_port",
    "c2_port",
  ],

  // File drop + execute — triggers COR_003 (Drop + Execute, 75% confidence)
  dropper: [
    "file_drop",
    "exec_temp",
    "persist_reg_run",
  ],

  // Camera + mic + screen — triggers COR_006 (Full Surveillance, 95% confidence)
  surveillance: [
    "sim_screenshot",
    "sim_camera",
    "sim_microphone",
    "sim_file_collection",
  ],

  // Credential access + C2 — triggers COR_008 (Credential Access + C2, 88% confidence)
  credential_exfil: [
    "sim_credential",
    "c2_port",
  ],

  // Full RAT operational pattern — all phases including collection
  full_op: [
    "exec_temp",
    "persist_reg_run",
    "c2_port",
    "discovery_procs",
    "sim_screenshot",
    "sim_file_collection",
    "sim_credential",
  ],
};

// ── Main ──────────────────────────────────────────────────────────────────────

const HR = "─".repeat(60);

function pad(s, n) { return String(s).padEnd(n); }

async function run() {
  const scenario = SCENARIOS[SCENARIO];
  if (!scenario) {
    console.error(`Unknown scenario: "${SCENARIO}"`);
    console.error(`Available: ${Object.keys(SCENARIOS).join(", ")}`);
    process.exit(1);
  }

  console.log(HR);
  console.log("B4DB4B3-RAT Attack Simulator");
  console.log(HR);
  console.log(`${pad("Target",  9)}: ${proto}://${HOST}:${PORT}`);
  console.log(`${pad("Bot ID",  9)}: ${BOT_ID}`);
  console.log(`${pad("Scenario",9)}: ${SCENARIO}  (${scenario.length} event(s))`);
  console.log(`${pad("Delay",   9)}: ${DELAY_MS} ms`);
  console.log(HR);

  const startMs = Date.now();

  // Step 1 — Register the simulated bot
  process.stdout.write("[+] Checking in as simulated bot ... ");
  try {
    const ci = await checkin();
    if (ci.status !== 200) throw new Error(`HTTP ${ci.status}`);
    console.log("OK");
  } catch (e) {
    console.log(`FAILED: ${e.message}`);
    console.error("    Hint: is the C2 server running? Is the auth key correct?");
    process.exit(1);
  }

  console.log("");

  const stats = { sent: 0, failed: 0, phases: new Set(), techniques: new Set() };

  // Step 2 — Send events in sequence
  for (const key of scenario) {
    const evt = EVENTS[key];
    if (!evt) {
      console.error(`  [!] Unknown event key: ${key}`);
      continue;
    }
    const label = `[${evt.phase}] ${evt.ev.substring(0, 58)}`;
    process.stdout.write(`  ⟶  ${label}... `);
    try {
      const r = await sendEvent(evt);
      if (r.status >= 400) throw new Error(`HTTP ${r.status}`);
      console.log("OK");
      stats.sent++;
      stats.phases.add(evt.phase);
      if (evt.tid) stats.techniques.add(evt.tid);
    } catch (e) {
      console.log(`FAILED (${e.message})`);
      stats.failed++;
    }
    if (DELAY_MS > 0) await sleep(DELAY_MS);
  }

  // Step 3 — Print summary
  const elapsed = ((Date.now() - startMs) / 1000).toFixed(1);
  console.log("");
  console.log(HR);
  console.log("Simulation Summary");
  console.log(HR);
  console.log(`${pad("Events sent",    18)}: ${stats.sent} / ${scenario.length}`);
  console.log(`${pad("ATT&CK techniques",18)}: ${stats.techniques.size}  (${[...stats.techniques].join(", ")})`);
  console.log(`${pad("Attack phases",  18)}: ${[...stats.phases].join(" → ")}`);
  console.log(`${pad("Duration",       18)}: ${elapsed}s`);
  console.log(`${pad("Dashboard",      18)}: ${proto}://${HOST}:${PORT}/  (filter by bot: ${BOT_ID})`);
  console.log(HR);

  if (stats.failed > 0)
    console.error(`[!] ${stats.failed} event(s) failed — check --host / --port / --auth`);

  // Print expected detections based on the scenario
  console.log("");
  console.log("Expected detections on the dashboard:");
  const tags = new Set();
  for (const key of scenario) {
    const evt = EVENTS[key];
    if (!evt) continue;
    const dr = DR_TAGS[evt.rule];
    if (dr) { console.log(`  DR match: ${dr.name}  [${dr.tags.join(", ")}]`); dr.tags.forEach(t => tags.add(t)); }
  }

  const coveredTags = [...tags];
  console.log("");
  console.log("Correlation tags covered: " + (coveredTags.join(", ") || "(none)"));

  for (const cor of COR_INFO) {
    const covered = cor.requires.every(t => tags.has(t));
    const icon = covered ? "✓" : "○";
    console.log(`  ${icon}  ${cor.name}  (requires: ${cor.requires.join(" + ")})`);
  }
  console.log("");
}

// Local copies of DR/COR metadata for the summary (no server import needed)
const DR_TAGS = {
  PROC_001: { name: "DR_009: Process Discovery",                 tags: ["discovery"]          },
  PROC_002: { name: "DR_001: Process Launched from Temp",        tags: ["proc_suspicious"]    },
  PROC_003: { name: "DR_002: Process Launched from AppData",     tags: ["proc_suspicious"]    },
  REG_001:  { name: "DR_003: New Autostart Registry Key",        tags: ["persistence"]        },
  REG_002:  { name: "DR_004: Modified Autostart Registry Key",   tags: ["persistence"]        },
  NET_001:  { name: "DR_008: New TCP Connection",                tags: ["network"]            },
  NET_002:  { name: "DR_005: Connection on Suspicious Port",     tags: ["network_c2"]         },
  SVC_001:  { name: "DR_006: New Windows Service Created",       tags: ["persistence"]        },
  FILE_001: { name: "DR_007: Executable Dropped in Temp/AppData",tags: ["file_drop"]          },
  CAM_001:  { name: "DR_010: Camera Access Attempted",           tags: ["collection","av"]    },
  MIC_001:  { name: "DR_011: Microphone Access Attempted",       tags: ["collection","audio"] },
  SCR_001:  { name: "DR_012: Screen Capture Initiated",          tags: ["collection","screenshot"] },
  CRED_001: { name: "DR_013: Credential Store Access",           tags: ["credential_access"]  },
  FCOL_001: { name: "DR_014: File Metadata Collection",          tags: ["collection"]         },
};

const COR_INFO = [
  { name: "COR_001: RAT Deploy (Execution + Persistence + C2)",  requires: ["proc_suspicious","persistence","network_c2"], confidence: 90 },
  { name: "COR_002: Persistence + C2 Channel",                   requires: ["persistence","network_c2"],                  confidence: 70 },
  { name: "COR_003: Drop + Execute from Temp",                   requires: ["file_drop","proc_suspicious"],               confidence: 75 },
  { name: "COR_004: Drop + Autostart Persistence",               requires: ["file_drop","persistence"],                   confidence: 65 },
  { name: "COR_005: Suspicious Execution + Network Activity",    requires: ["proc_suspicious","network_c2"],              confidence: 60 },
  { name: "COR_006: Full Surveillance (Camera + Mic + Screen)", requires: ["av","audio","screenshot"],                   confidence: 95 },
  { name: "COR_007: Persistence + Collection Activity",         requires: ["persistence","collection"],                  confidence: 80 },
  { name: "COR_008: Credential Access + C2 Exfiltration",       requires: ["credential_access","network_c2"],            confidence: 88 },
];

run().catch(err => {
  console.error("Fatal:", err.message);
  process.exit(1);
});
