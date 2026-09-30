#!/usr/bin/env node
/**
 * B4DB4B3-RAT  Android Telemetry Simulator
 * ─────────────────────────────────────────
 * Emits Android malware behavior events to the C2 detection server
 * WITHOUT accessing any real device, camera, microphone or sensor.
 *
 * All events follow the same JSON schema as the Windows simulator but
 * include `platform:"android"` and use Android rule IDs (ACAM_001, etc.)
 * which map to MITRE ATT&CK for Mobile techniques.
 *
 * Usage:
 *   node android-simulator.js [options]
 *
 * Options:
 *   --host       C2 hostname          (default: localhost)
 *   --port       C2 port              (default: 443)
 *   --auth       C2 auth key          (default: changeme)
 *   --botId      Bot identifier       (default: ANDROID_SIM_001)
 *   --scenario   Scenario name        (default: full_spyware)
 *     full_spyware | surveillance | sms_spy | persistence | c2_beacon
 *     permission_harvest | anti_analysis | credential_theft
 *   --delay      ms between events    (default: 400)
 *   --pkg        Simulated package    (default: com.lab.specimen)
 *   --http       Use plain HTTP
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
const BOT_ID   = args.botId    || "ANDROID_SIM_001";
const SCENARIO = (args.scenario || "full_spyware").toLowerCase();
const DELAY_MS = parseInt(args.delay || "400", 10);
const PKG      = args.pkg      || "com.lab.specimen";
const USE_HTTP = args.http === true || args.http === "true";
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

function checkin() {
  const info = encodeURIComponent(
    `ANDROID | Emulator | SDK 34 | ${PKG} | ${new Date().toISOString()}`
  );
  return request("GET", `/checkin?id=${BOT_ID}&auth=${AUTH}&info=${info}`);
}

function sendEvent(evt) {
  return request("POST", `/event?id=${BOT_ID}&auth=${AUTH}`, {
    ...evt, bot: BOT_ID, platform: "android", pkg: PKG,
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Android event library ─────────────────────────────────────────────────────
// Each event has: cat, type, sev, rule, ev, phase, tid, tname
// Additional fields: pkg, permission, component, remote, simulated

const EVT = {

  // ── App lifecycle ───────────────────────────────────────────────────────────
  app_install: {
    cat: "lifecycle", type: "install", sev: "info",
    rule: "ALIFE_001",
    ev:   `App installed: ${PKG}`,
    tid: "T1418", tname: "Software Discovery",
    phase: "Execution",
  },
  app_launch: {
    cat: "lifecycle", type: "launch", sev: "info",
    rule: "ALIFE_002",
    ev:   `App launched: ${PKG}`,
    tid: "T1418", tname: "Software Discovery",
    phase: "Execution",
  },
  app_background_service: {
    cat: "lifecycle", type: "service_start", sev: "low",
    rule: "AFGS_001",
    ev:   `Foreground service started — ${PKG} remains active when backgrounded`,
    component: `${PKG}/.C2ForegroundService`,
    tid: "T1541", tname: "Foreground Persistence",
    phase: "Persistence",
  },

  // ── Permission access events ────────────────────────────────────────────────
  perm_camera: {
    cat: "permission", type: "access", sev: "high",
    rule: "ACAM_001",
    ev:   `Camera permission accessed — ${PKG}`,
    permission: "android.permission.CAMERA",
    simulated: true,
    tid: "T1512", tname: "Video Capture",
    phase: "Collection",
  },
  perm_microphone: {
    cat: "permission", type: "access", sev: "high",
    rule: "AMIC_001",
    ev:   `Microphone permission accessed — ${PKG} (RECORD_AUDIO)`,
    permission: "android.permission.RECORD_AUDIO",
    simulated: true,
    tid: "T1429", tname: "Audio Capture",
    phase: "Collection",
  },
  perm_location_fine: {
    cat: "permission", type: "access", sev: "high",
    rule: "ALOC_001",
    ev:   `Precise GPS location requested — ${PKG} (ACCESS_FINE_LOCATION)`,
    permission: "android.permission.ACCESS_FINE_LOCATION",
    tid: "T1430", tname: "Location Tracking",
    phase: "Collection",
  },
  perm_location_background: {
    cat: "permission", type: "access", sev: "critical",
    rule: "ALOC_002",
    ev:   `Background location access requested — ${PKG} can track location when app is closed`,
    permission: "android.permission.ACCESS_BACKGROUND_LOCATION",
    tid: "T1430", tname: "Location Tracking",
    phase: "Collection",
  },
  perm_contacts: {
    cat: "permission", type: "access", sev: "medium",
    rule: "ACON_001",
    ev:   `Contact list read by ${PKG}`,
    permission: "android.permission.READ_CONTACTS",
    tid: "T1432", tname: "Access Contact List",
    phase: "Collection",
  },
  perm_sms_read: {
    cat: "permission", type: "access", sev: "high",
    rule: "ASMS_001",
    ev:   `SMS messages read by ${PKG}`,
    permission: "android.permission.READ_SMS",
    tid: "T1412", tname: "Capture SMS Messages",
    phase: "Collection",
  },
  perm_sms_send: {
    cat: "permission", type: "access", sev: "high",
    rule: "ASMS_002",
    ev:   `SMS message sent by ${PKG} without user interaction`,
    permission: "android.permission.SEND_SMS",
    tid: "T1412", tname: "Capture SMS Messages",
    phase: "Collection",
  },
  perm_call_log: {
    cat: "permission", type: "access", sev: "high",
    rule: "ACALL_001",
    ev:   `Call history read by ${PKG}`,
    permission: "android.permission.READ_CALL_LOG",
    tid: "T1432", tname: "Access Contact List",
    phase: "Collection",
  },
  perm_accessibility: {
    cat: "permission", type: "access", sev: "critical",
    rule: "AACC_001",
    ev:   `Accessibility service bound — ${PKG} can intercept ALL UI input and read screen`,
    permission: "android.permission.BIND_ACCESSIBILITY_SERVICE",
    component: `${PKG}/.SpyAccessibilityService`,
    tid: "T1411", tname: "Input Capture",
    phase: "Collection",
  },
  perm_notifications: {
    cat: "permission", type: "access", sev: "medium",
    rule: "ANOT_001",
    ev:   `Notification listener registered — ${PKG} can read all app notifications`,
    permission: "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    tid: "T1517", tname: "Access Notifications",
    phase: "Collection",
  },
  perm_clipboard: {
    cat: "permission", type: "access", sev: "medium",
    rule: "ACLIP_001",
    ev:   `Clipboard content read by ${PKG}`,
    permission: "android.permission.READ_CLIPBOARD",
    tid: "T1409", tname: "Access Stored Application Data",
    phase: "Collection",
  },
  perm_overlay: {
    cat: "permission", type: "access", sev: "high",
    rule: "AOVL_001",
    ev:   `System alert window (overlay) active — ${PKG} drawing over other apps`,
    permission: "android.permission.SYSTEM_ALERT_WINDOW",
    tid: "T1411", tname: "Input Capture",
    phase: "Collection",
  },

  // ── Persistence ─────────────────────────────────────────────────────────────
  persist_boot_receiver: {
    cat: "persistence", type: "broadcast_receiver", sev: "medium",
    rule: "ABOOT_001",
    ev:   `Boot receiver registered — ${PKG} auto-starts on device reboot`,
    component: `${PKG}/.BootReceiver`,
    permission: "android.permission.RECEIVE_BOOT_COMPLETED",
    tid: "T1624.001", tname: "Boot or Logon Initialization Scripts: Broadcast Receivers",
    phase: "Persistence",
  },
  persist_device_admin: {
    cat: "persistence", type: "device_admin", sev: "critical",
    rule: "AADM_001",
    ev:   `Device administrator activated — ${PKG} cannot be uninstalled without disabling admin first`,
    component: `${PKG}/.DeviceAdminReceiver`,
    tid: "T1626", tname: "Abuse Elevation Control Mechanism",
    phase: "Persistence",
  },
  persist_work_profile: {
    cat: "persistence", type: "work_profile", sev: "high",
    rule: "AFGS_001",
    ev:   `Foreground service with WAKE_LOCK — ${PKG} prevents device sleep to maintain C2`,
    component: `${PKG}/.WatchdogService`,
    tid: "T1541", tname: "Foreground Persistence",
    phase: "Persistence",
  },

  // ── Network / C2 ────────────────────────────────────────────────────────────
  net_c2_http: {
    cat: "network", type: "connect", sev: "high",
    rule: "ANET_001",
    ev:   `Suspicious outbound HTTP request to non-CDN host from ${PKG}`,
    remote: "185.220.101.47:8080",
    path:   "/api/check",
    tid: "T1437", tname: "Application Layer Protocol",
    phase: "C2",
  },
  net_c2_https: {
    cat: "network", type: "connect", sev: "medium",
    rule: "ANET_002",
    ev:   `Encrypted C2 channel — TLS to non-browser process: ${PKG}`,
    remote: "185.220.101.47:443",
    path:   "/v2/sync",
    tid: "T1521", tname: "Encrypted Channel",
    phase: "C2",
  },
  net_c2_beacon: {
    cat: "network", type: "beacon", sev: "medium",
    rule: "ANET_001",
    ev:   `Regular C2 polling — ${PKG} beaconing every ~30s`,
    remote: "185.220.101.47:443",
    path:   "/poll",
    interval_s: 30,
    tid: "T1437", tname: "Application Layer Protocol",
    phase: "C2",
  },
  net_dns_suspicious: {
    cat: "network", type: "dns", sev: "medium",
    rule: "ANET_001",
    ev:   `DNS query for newly-registered domain — ${PKG}`,
    domain: "update-cdn-static.xyz",
    tid: "T1437", tname: "Application Layer Protocol",
    phase: "C2",
  },

  // ── Data collection (simulation — no real data) ─────────────────────────────
  data_location_exfil: {
    cat: "exfil", type: "upload", sev: "high",
    rule: "ALOC_001",
    ev:   `[SIM] Location coordinates sent to C2 — lat/lon simulated`,
    simulated: true,
    remote: "185.220.101.47:443",
    tid: "T1430", tname: "Location Tracking",
    phase: "Exfiltration",
  },
  data_camera_frame: {
    cat: "collection", type: "simulation", sev: "high",
    rule: "ACAM_001",
    ev:   `[SIM] Camera frame captured — no real image, pre-recorded stub used`,
    simulated: true,
    tid: "T1512", tname: "Video Capture",
    phase: "Collection",
  },
  data_mic_audio: {
    cat: "collection", type: "simulation", sev: "high",
    rule: "AMIC_001",
    ev:   `[SIM] Microphone recording — pre-recorded WAV stub, no live audio`,
    simulated: true,
    duration_s: 10,
    tid: "T1429", tname: "Audio Capture",
    phase: "Collection",
  },
  data_screen_capture: {
    cat: "collection", type: "simulation", sev: "medium",
    rule: "ASCR_001",
    ev:   `[SIM] Screen capture via MediaProjection API — no real screenshot`,
    simulated: true,
    tid: "T1513", tname: "Screen Capture",
    phase: "Collection",
  },
  data_sms_intercept: {
    cat: "collection", type: "intercept", sev: "high",
    rule: "ASMS_001",
    ev:   `[SIM] SMS messages read and queued for exfiltration`,
    simulated: true,
    count: 47,
    tid: "T1412", tname: "Capture SMS Messages",
    phase: "Collection",
  },
  data_contacts_dump: {
    cat: "collection", type: "dump", sev: "medium",
    rule: "ACON_001",
    ev:   `[SIM] Contact list exported — ${PKG}`,
    simulated: true,
    count: 312,
    tid: "T1432", tname: "Access Contact List",
    phase: "Collection",
  },
  data_keylog: {
    cat: "collection", type: "keylog", sev: "critical",
    rule: "AACC_001",
    ev:   `[SIM] Keystroke capture via AccessibilityService — passwords at risk`,
    simulated: true,
    tid: "T1411", tname: "Input Capture",
    phase: "Collection",
  },
  data_file_enum: {
    cat: "collection", type: "enum", sev: "low",
    rule: "AFILE_001",
    ev:   `External storage enumerated by ${PKG}`,
    path:  "/sdcard",
    tid: "T1533", tname: "Data from Local System",
    phase: "Collection",
  },
  data_app_enum: {
    cat: "discovery", type: "enum", sev: "low",
    rule: "AAPP_001",
    ev:   `Installed app list enumerated by ${PKG} (banking app detection)`,
    tid: "T1418", tname: "Software Discovery",
    phase: "Discovery",
  },

  // ── Anti-analysis ────────────────────────────────────────────────────────────
  aa_emulator_check: {
    cat: "anti_analysis", type: "check", sev: "medium",
    rule: "AEMU_001",
    ev:   `Emulator detection check — ${PKG} read Build.FINGERPRINT and IMEI`,
    checks: ["Build.FINGERPRINT", "IMEI=000000000000000", "ro.product.model"],
    tid: "T1633", tname: "Virtualization/Sandbox Evasion",
    phase: "DefenseEvasion",
  },
  aa_root_check: {
    cat: "anti_analysis", type: "check", sev: "high",
    rule: "AROOT_001",
    ev:   `Root detection / SU binary access attempted by ${PKG}`,
    checks: ["/system/bin/su", "/sbin/su", "com.topjohnwu.magisk"],
    tid: "T1626", tname: "Abuse Elevation Control Mechanism",
    phase: "DefenseEvasion",
  },
  aa_debugger_check: {
    cat: "anti_analysis", type: "check", sev: "medium",
    rule: "AEMU_001",
    ev:   `Debugger detection — ${PKG} called android.os.Debug.isDebuggerConnected()`,
    tid: "T1633", tname: "Virtualization/Sandbox Evasion",
    phase: "DefenseEvasion",
  },
  aa_hook_detect: {
    cat: "anti_analysis", type: "check", sev: "high",
    rule: "AEMU_001",
    ev:   `Frida/Xposed hook detection — ${PKG} scanned for hooking frameworks`,
    checks: ["frida-agent", "XposedBridge", "de.robv.android.xposed"],
    tid: "T1633", tname: "Virtualization/Sandbox Evasion",
    phase: "DefenseEvasion",
  },

  // ── Credential / financial targeting ─────────────────────────────────────────
  cred_overlay: {
    cat: "credential", type: "overlay", sev: "critical",
    rule: "AOVL_001",
    ev:   `[SIM] Overlay attack — ${PKG} drew fake login screen over banking app`,
    simulated: true,
    target_pkg: "com.example.bankapp",
    tid: "T1411", tname: "Input Capture",
    phase: "CredAccess",
  },
  cred_accessibility_capture: {
    cat: "credential", type: "keylog", sev: "critical",
    rule: "AACC_001",
    ev:   `[SIM] Banking credentials captured via AccessibilityService event stream`,
    simulated: true,
    tid: "T1411", tname: "Input Capture",
    phase: "CredAccess",
  },
};

// ── Scenarios ─────────────────────────────────────────────────────────────────

const SCENARIOS = {
  // Full spyware — all capabilities, triggers ACOR_001 + ACOR_003
  full_spyware: [
    "app_install",
    "app_launch",
    "perm_camera",
    "perm_microphone",
    "perm_location_fine",
    "perm_contacts",
    "perm_sms_read",
    "perm_accessibility",
    "perm_notifications",
    "perm_clipboard",
    "persist_boot_receiver",
    "net_c2_https",
    "data_camera_frame",
    "data_mic_audio",
    "data_sms_intercept",
    "data_screen_capture",
  ],

  // Camera + microphone + screen — surveillance, triggers ACOR_001
  surveillance: [
    "perm_camera",
    "perm_microphone",
    "data_camera_frame",
    "data_mic_audio",
    "data_screen_capture",
    "net_c2_https",
  ],

  // SMS interceptor — read/send SMS, intercept calls
  sms_spy: [
    "perm_sms_read",
    "perm_sms_send",
    "perm_call_log",
    "perm_contacts",
    "data_sms_intercept",
    "data_contacts_dump",
    "net_c2_http",
  ],

  // Persistence mechanisms
  persistence: [
    "app_background_service",
    "persist_boot_receiver",
    "persist_device_admin",
    "persist_work_profile",
  ],

  // Repeated C2 beaconing
  c2_beacon: [
    "net_c2_beacon",
    "net_c2_beacon",
    "net_c2_beacon",
    "net_c2_beacon",
    "net_c2_beacon",
    "net_c2_beacon",
  ],

  // Collect every permission-sensitive data point
  permission_harvest: [
    "perm_camera",
    "perm_microphone",
    "perm_location_fine",
    "perm_location_background",
    "perm_contacts",
    "perm_sms_read",
    "perm_call_log",
    "perm_accessibility",
    "perm_notifications",
    "perm_clipboard",
    "perm_overlay",
    "data_app_enum",
    "data_file_enum",
  ],

  // Anti-analysis: emulator/root/debugger/hook checks
  anti_analysis: [
    "aa_emulator_check",
    "aa_root_check",
    "aa_debugger_check",
    "aa_hook_detect",
  ],

  // Credential theft via overlay + accessibility
  credential_theft: [
    "perm_accessibility",
    "perm_overlay",
    "data_app_enum",       // find banking apps first
    "cred_overlay",
    "cred_accessibility_capture",
    "net_c2_https",
  ],
};

// ── Summary metadata (local mirror of server rules) ──────────────────────────

const DR_ANDROID = {
  ACAM_001:  { name:"ADR_001: Camera Access",           tags:["android_collection","android_av"]     },
  AMIC_001:  { name:"ADR_002: Microphone Access",       tags:["android_collection","android_audio"]  },
  ALOC_001:  { name:"ADR_003: Location Access",         tags:["android_tracking"]                    },
  ALOC_002:  { name:"ADR_003b: Background Location",    tags:["android_tracking"]                    },
  ACON_001:  { name:"ADR_004: Contacts Read",           tags:["android_collection"]                  },
  ASMS_001:  { name:"ADR_005: SMS Read",                tags:["android_collection","android_comms"]  },
  ASMS_002:  { name:"ADR_005b: SMS Send",               tags:["android_collection","android_comms"]  },
  ACALL_001: { name:"ADR_006: Call Log Access",         tags:["android_collection"]                  },
  AACC_001:  { name:"ADR_007: Accessibility Service",   tags:["android_input","android_persist"]     },
  ABOOT_001: { name:"ADR_008: Boot Receiver",           tags:["android_persistence"]                 },
  AADM_001:  { name:"ADR_009: Device Admin",            tags:["android_persist","android_da"]        },
  ANOT_001:  { name:"ADR_010: Notification Access",     tags:["android_collection"]                  },
  ACLIP_001: { name:"ADR_011: Clipboard Access",        tags:["android_collection"]                  },
  ANET_001:  { name:"ADR_012: Suspicious Network",      tags:["android_c2"]                          },
  ANET_002:  { name:"ADR_013: Encrypted C2 Channel",   tags:["android_c2"]                          },
  AAPP_001:  { name:"ADR_014: App Enumeration",         tags:["android_discovery"]                   },
  AROOT_001: { name:"ADR_015: Root/SU Access",          tags:["android_priv_esc"]                    },
  AEMU_001:  { name:"ADR_016: Emulator/Debug Check",   tags:["android_anti_analysis"]               },
  ASCR_001:  { name:"ADR_017: Screen Capture",          tags:["android_collection","android_screen"] },
  AFILE_001: { name:"ADR_018: External Storage Read",  tags:["android_collection"]                  },
  AOVL_001:  { name:"ADR_019: Overlay Attack",          tags:["android_input"]                       },
  AFGS_001:  { name:"ADR_020: Foreground Service",      tags:["android_persistence"]                 },
  ALIFE_001: { name:"ADR_021: App Installed",           tags:["android_lifecycle"]                   },
  ALIFE_002: { name:"ADR_022: App Launched",            tags:["android_lifecycle"]                   },
};

const COR_ANDROID = [
  { name:"ACOR_001: Full Surveillance (Cam+Mic+Location)", requires:["android_av","android_audio","android_tracking"], confidence:95 },
  { name:"ACOR_002: SMS/Call Spy (Contacts+SMS+CallLog)",  requires:["android_collection","android_comms"],            confidence:85 },
  { name:"ACOR_003: Spyware Profile (Persist+Collect+C2)", requires:["android_persistence","android_collection","android_c2"], confidence:88 },
  { name:"ACOR_004: Anti-Analysis + Privilege Escalation", requires:["android_anti_analysis","android_priv_esc"],       confidence:80 },
  { name:"ACOR_005: Overlay Credential Theft",             requires:["android_input","android_c2"],                     confidence:90 },
];

// ── Runner ────────────────────────────────────────────────────────────────────

const HR = "─".repeat(64);

async function run() {
  const scenario = SCENARIOS[SCENARIO];
  if (!scenario) {
    console.error(`Unknown scenario: "${SCENARIO}"`);
    console.error(`Available: ${Object.keys(SCENARIOS).join(", ")}`);
    process.exit(1);
  }

  console.log(HR);
  console.log("B4DB4B3-RAT  Android Simulator");
  console.log(HR);
  console.log(`Target   : ${proto}://${HOST}:${PORT}`);
  console.log(`Bot ID   : ${BOT_ID}`);
  console.log(`Package  : ${PKG}`);
  console.log(`Scenario : ${SCENARIO}  (${scenario.length} events)`);
  console.log(`Delay    : ${DELAY_MS} ms`);
  console.log(HR);

  const startMs = Date.now();

  process.stdout.write("[+] Checking in as Android agent ... ");
  try {
    const ci = await checkin();
    if (ci.status !== 200) throw new Error(`HTTP ${ci.status}`);
    console.log("OK");
  } catch (e) {
    console.log(`FAILED: ${e.message}`);
    process.exit(1);
  }
  console.log("");

  const stats = { sent: 0, failed: 0, phases: new Set(), techniques: new Set() };
  const coveredTags = new Set();

  for (const key of scenario) {
    const evt = EVT[key];
    if (!evt) { console.error(`  [!] Unknown event: ${key}`); continue; }

    const label = `[${evt.phase}] ${evt.ev.substring(0, 56)}`;
    process.stdout.write(`  ⟶  ${label}... `);
    try {
      const r = await sendEvent(evt);
      if (r.status >= 400) throw new Error(`HTTP ${r.status}`);
      console.log("OK");
      stats.sent++;
      stats.phases.add(evt.phase);
      if (evt.tid) stats.techniques.add(evt.tid);
      const dr = DR_ANDROID[evt.rule];
      if (dr) dr.tags.forEach(t => coveredTags.add(t));
    } catch (e) {
      console.log(`FAILED (${e.message})`);
      stats.failed++;
    }
    if (DELAY_MS > 0) await sleep(DELAY_MS);
  }

  // Print summary
  const elapsed = ((Date.now() - startMs) / 1000).toFixed(1);
  console.log("");
  console.log(HR);
  console.log("Simulation Summary");
  console.log(HR);
  console.log(`Events sent        : ${stats.sent} / ${scenario.length}`);
  console.log(`ATT&CK Mobile TIDs : ${stats.techniques.size}  (${[...stats.techniques].join(", ")})`);
  console.log(`Attack phases      : ${[...stats.phases].join(" → ")}`);
  console.log(`Duration           : ${elapsed}s`);
  console.log(`Dashboard          : ${proto}://${HOST}:${PORT}/  (bot: ${BOT_ID})`);

  console.log("");
  console.log("Expected correlations:");
  for (const cor of COR_ANDROID) {
    const hit = cor.requires.every(t => coveredTags.has(t));
    console.log(`  ${hit ? "✓" : "○"}  ${cor.name}  (${cor.confidence}% confidence)`);
  }
  console.log(HR);

  if (stats.failed > 0)
    console.error(`[!] ${stats.failed} event(s) failed — check --host/--port/--auth`);
}

run().catch(err => { console.error("Fatal:", err.message); process.exit(1); });
