"use strict";

const path = require("path");

const AUTH_KEY    = process.env.C2_AUTH    || "changeme";
const ADMIN_PASS  = process.env.ADMIN_PASS || "admin123";
const PORT        = parseInt(process.env.C2_PORT || "4444", 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "";
const UPLOADS_DIR = path.join(__dirname, "..", "uploads");

const MAX_EVENTS     = 2000;
const MAX_DETECTIONS = 500;
const MAX_INCIDENTS  = 200;
const MAX_NETLOG     = 500;

// ── Detection Rules ───────────────────────────────────────────────────────────

const DETECTION_RULES = [
  { id:"DR_001", name:"Process Launched from Temp",      match:{rule:"PROC_002"}, tags:["proc_suspicious"], confidence:35, tid:"T1204.002" },
  { id:"DR_002", name:"Process Launched from AppData",   match:{rule:"PROC_003"}, tags:["proc_suspicious"], confidence:20, tid:"T1204.002" },
  { id:"DR_003", name:"New Autostart Registry Key",      match:{rule:"REG_001" }, tags:["persistence"],     confidence:40, tid:"T1547.001" },
  { id:"DR_004", name:"Modified Autostart Registry Key", match:{rule:"REG_002" }, tags:["persistence"],     confidence:30, tid:"T1547.001" },
  { id:"DR_005", name:"Connection on Suspicious Port",   match:{rule:"NET_002" }, tags:["network_c2"],      confidence:35, tid:"T1571"     },
  { id:"DR_006", name:"New Windows Service Created",     match:{rule:"SVC_001" }, tags:["persistence"],     confidence:40, tid:"T1543.003" },
  { id:"DR_007", name:"Executable Dropped in Temp/AppData", match:{rule:"FILE_001"}, tags:["file_drop"],   confidence:30, tid:"T1105"     },
  { id:"DR_008", name:"New TCP Connection Established",  match:{rule:"NET_001" }, tags:["network"],         confidence:10, tid:"T1049"     },
  { id:"DR_009", name:"Process Discovery",               match:{rule:"PROC_001"}, tags:["discovery"],       confidence: 5, tid:"T1057"     },
  { id:"DR_010", name:"Camera Access Attempted",         match:{rule:"CAM_001" }, tags:["collection","av"],            confidence:70, tid:"T1125"     },
  { id:"DR_011", name:"Microphone Access Attempted",     match:{rule:"MIC_001" }, tags:["collection","audio"],         confidence:70, tid:"T1123"     },
  { id:"DR_012", name:"Screen Capture Initiated",        match:{rule:"SCR_001" }, tags:["collection","screenshot"],    confidence:50, tid:"T1113"     },
  { id:"DR_013", name:"Credential Store Access",         match:{rule:"CRED_001"}, tags:["credential_access"],          confidence:80, tid:"T1555"     },
  { id:"DR_014", name:"File Metadata Collection",        match:{rule:"FCOL_001"}, tags:["collection"],                 confidence:35, tid:"T1005"     },
  { id:"ADR_001", name:"Android: Camera Access",               match:{rule:"ACAM_001" }, tags:["android_collection","android_av"],              confidence:65, tid:"T1512"     },
  { id:"ADR_002", name:"Android: Microphone Access",           match:{rule:"AMIC_001" }, tags:["android_collection","android_audio"],           confidence:65, tid:"T1429"     },
  { id:"ADR_003", name:"Android: Location Tracking",           match:{rule:"ALOC_001" }, tags:["android_tracking"],                             confidence:55, tid:"T1430"     },
  { id:"ADR_004", name:"Android: Background Location",         match:{rule:"ALOC_002" }, tags:["android_tracking"],                             confidence:75, tid:"T1430"     },
  { id:"ADR_005", name:"Android: Contact List Read",           match:{rule:"ACON_001" }, tags:["android_collection"],                           confidence:50, tid:"T1432"     },
  { id:"ADR_006", name:"Android: SMS Read/Send",               match:{rule:"ASMS_001" }, tags:["android_collection","android_comms"],           confidence:70, tid:"T1412"     },
  { id:"ADR_007", name:"Android: SMS Sent Silently",           match:{rule:"ASMS_002" }, tags:["android_collection","android_comms"],           confidence:80, tid:"T1412"     },
  { id:"ADR_008", name:"Android: Call Log Access",             match:{rule:"ACALL_001"}, tags:["android_collection"],                           confidence:55, tid:"T1432"     },
  { id:"ADR_009", name:"Android: Accessibility Service Abuse", match:{rule:"AACC_001" }, tags:["android_input","android_persist"],              confidence:85, tid:"T1411"     },
  { id:"ADR_010", name:"Android: Boot Receiver Registered",    match:{rule:"ABOOT_001"}, tags:["android_persistence"],                         confidence:60, tid:"T1624"     },
  { id:"ADR_011", name:"Android: Device Admin Activated",      match:{rule:"AADM_001" }, tags:["android_persist","android_da"],                confidence:90, tid:"T1626"     },
  { id:"ADR_012", name:"Android: Notification Listener",       match:{rule:"ANOT_001" }, tags:["android_collection"],                          confidence:45, tid:"T1517"     },
  { id:"ADR_013", name:"Android: Clipboard Access",            match:{rule:"ACLIP_001"}, tags:["android_collection"],                          confidence:40, tid:"T1409"     },
  { id:"ADR_014", name:"Android: Suspicious Outbound C2",      match:{rule:"ANET_001" }, tags:["android_c2"],                                  confidence:55, tid:"T1437"     },
  { id:"ADR_015", name:"Android: Encrypted C2 Channel",        match:{rule:"ANET_002" }, tags:["android_c2"],                                  confidence:60, tid:"T1521"     },
  { id:"ADR_016", name:"Android: Installed App Enumeration",   match:{rule:"AAPP_001" }, tags:["android_discovery"],                           confidence:35, tid:"T1418"     },
  { id:"ADR_017", name:"Android: Root / SU Access Attempt",    match:{rule:"AROOT_001"}, tags:["android_priv_esc"],                            confidence:90, tid:"T1626"     },
  { id:"ADR_018", name:"Android: Emulator/Debugger Detection", match:{rule:"AEMU_001" }, tags:["android_anti_analysis"],                       confidence:75, tid:"T1633"     },
  { id:"ADR_019", name:"Android: Screen Capture (MediaProj)",  match:{rule:"ASCR_001" }, tags:["android_collection","android_screen"],         confidence:65, tid:"T1513"     },
  { id:"ADR_020", name:"Android: External Storage Access",     match:{rule:"AFILE_001"}, tags:["android_collection"],                          confidence:30, tid:"T1533"     },
  { id:"ADR_021", name:"Android: Overlay Attack",              match:{rule:"AOVL_001" }, tags:["android_input"],                               confidence:80, tid:"T1411"     },
  { id:"ADR_022", name:"Android: Foreground Persistence Svc",  match:{rule:"AFGS_001" }, tags:["android_persistence"],                         confidence:45, tid:"T1541"     },
  { id:"ADR_023", name:"Android: APK Static Analysis Event",   match:{rule:"AAPK_001" }, tags:["android_discovery"],                           confidence:40, tid:"T1418"     },
];

// ── Correlation Rules ─────────────────────────────────────────────────────────

const CORRELATION_RULES = [
  { id:"COR_001", name:"RAT Deploy: Execution + Persistence + C2",
    description:"Suspicious process launched, autostart mechanism added, and C2 channel established — high-confidence implant deployment.",
    requires:["proc_suspicious","persistence","network_c2"], window_sec:300, confidence:90, severity:"critical" },
  { id:"COR_002", name:"Persistence + C2 Channel",
    description:"Autostart mechanism added alongside an active C2 connection — likely post-exploitation persistence.",
    requires:["persistence","network_c2"], window_sec:300, confidence:70, severity:"high" },
  { id:"COR_003", name:"Drop + Execute from Temp",
    description:"Executable written to Temp/AppData then launched — classic dropper pattern.",
    requires:["file_drop","proc_suspicious"], window_sec:180, confidence:75, severity:"high" },
  { id:"COR_004", name:"Drop + Autostart Persistence",
    description:"File dropped and an autostart key added — staged loader or dropper establishing persistence.",
    requires:["file_drop","persistence"], window_sec:300, confidence:65, severity:"high" },
  { id:"COR_005", name:"Suspicious Execution + Network Activity",
    description:"Process launched from suspicious path with outbound network connection — potential beaconing.",
    requires:["proc_suspicious","network_c2"], window_sec:180, confidence:60, severity:"medium" },
  { id:"COR_006", name:"Full Surveillance: Camera + Microphone + Screen",
    description:"Camera, microphone, and screen-capture events co-occurred — multi-modal surveillance profile.",
    requires:["av","audio","screenshot"], window_sec:300, confidence:95, severity:"critical" },
  { id:"COR_007", name:"Persistence + Collection Activity",
    description:"Autostart persistence established alongside data collection — classic RAT operational pattern.",
    requires:["persistence","collection"], window_sec:300, confidence:80, severity:"high" },
  { id:"COR_008", name:"Credential Access + C2 Exfiltration",
    description:"Credential store accessed alongside active C2 channel — likely credential exfiltration.",
    requires:["credential_access","network_c2"], window_sec:300, confidence:88, severity:"critical" },
  { id:"ACOR_001", name:"Android: Full Surveillance (Cam + Mic + Location)",
    description:"Camera, microphone, and location accessed together — full surveillance spyware profile.",
    requires:["android_av","android_audio","android_tracking"], window_sec:300, confidence:95, severity:"critical" },
  { id:"ACOR_002", name:"Android: SMS/Call Spy",
    description:"SMS read/send with call log access — SMS interceptor or stalkerware.",
    requires:["android_comms","android_collection"], window_sec:300, confidence:85, severity:"critical" },
  { id:"ACOR_003", name:"Android: Spyware Profile (Persistence + Collection + C2)",
    description:"Boot persistence, data collection, and active C2 — classic Android RAT/spyware deployment.",
    requires:["android_persistence","android_collection","android_c2"], window_sec:600, confidence:90, severity:"critical" },
  { id:"ACOR_004", name:"Android: Anti-Analysis + Privilege Escalation",
    description:"Sandbox/emulator checks co-occurred with root access attempt — evasive malware.",
    requires:["android_anti_analysis","android_priv_esc"], window_sec:120, confidence:80, severity:"high" },
  { id:"ACOR_005", name:"Android: Overlay Credential Theft",
    description:"Overlay attack (SYSTEM_ALERT_WINDOW) with accessibility service — credential phishing.",
    requires:["android_input","android_c2"], window_sec:300, confidence:90, severity:"critical" },
  { id:"ACOR_006", name:"Android: Device Admin Anti-Uninstall",
    description:"Device admin combined with persistence mechanism — anti-removal malware.",
    requires:["android_da","android_persistence"], window_sec:300, confidence:88, severity:"high" },
];

// ── Simulation Actions ────────────────────────────────────────────────────────

const SIMULATION_ACTIONS = [
  { id:"SA_001", name:"Process Enumeration",          rule:"PROC_001", desc:"Enumerate all running processes (no termination)",    phase:"Discovery",   tid:"T1057"     },
  { id:"SA_002", name:"Network Discovery",            rule:"NET_001",  desc:"Enumerate active TCP connections",                    phase:"Discovery",   tid:"T1049"     },
  { id:"SA_003", name:"File Metadata Collection",     rule:"FCOL_001", desc:"Walk directory tree, collect filenames/sizes only",   phase:"Collection",  tid:"T1005"     },
  { id:"SA_004", name:"Screenshot Simulation",        rule:"SCR_001",  desc:"Emit screenshot event; use pre-recorded image only",  phase:"Collection",  tid:"T1113"     },
  { id:"SA_005", name:"Camera Access Simulation",     rule:"CAM_001",  desc:"Emit camera event; no actual recording",              phase:"Collection",  tid:"T1125"     },
  { id:"SA_006", name:"Microphone Access Simulation", rule:"MIC_001",  desc:"Emit mic event; use pre-recorded WAV only",           phase:"Collection",  tid:"T1123"     },
  { id:"SA_007", name:"Registry Persistence Sim",     rule:"REG_001",  desc:"Write persistence registry key (test key only)",      phase:"Persistence", tid:"T1547.001" },
  { id:"SA_008", name:"Credential Access Simulation", rule:"CRED_001", desc:"Emit credential access event; no real extraction",    phase:"CredAccess",  tid:"T1555"     },
  { id:"ASA_001", name:"[Android] Camera Access",         rule:"ACAM_001",  desc:"Emit camera permission access event (no real recording)", platform:"android", phase:"Collection",  tid:"T1512" },
  { id:"ASA_002", name:"[Android] Microphone Access",     rule:"AMIC_001",  desc:"Emit mic permission access event (no live audio)",        platform:"android", phase:"Collection",  tid:"T1429" },
  { id:"ASA_003", name:"[Android] Location Tracking",     rule:"ALOC_001",  desc:"Emit GPS location access event",                          platform:"android", phase:"Collection",  tid:"T1430" },
  { id:"ASA_004", name:"[Android] SMS Intercept",         rule:"ASMS_001",  desc:"Emit SMS read event (no real messages read)",              platform:"android", phase:"Collection",  tid:"T1412" },
  { id:"ASA_005", name:"[Android] Accessibility Service", rule:"AACC_001",  desc:"Emit accessibility service bind event (no real UI access)",platform:"android", phase:"Collection",  tid:"T1411" },
  { id:"ASA_006", name:"[Android] Boot Persistence",      rule:"ABOOT_001", desc:"Emit boot receiver registration event",                   platform:"android", phase:"Persistence", tid:"T1624" },
  { id:"ASA_007", name:"[Android] Screen Capture",        rule:"ASCR_001",  desc:"Emit MediaProjection screen capture event (no real capture)",platform:"android",phase:"Collection", tid:"T1513" },
  { id:"ASA_008", name:"[Android] Overlay Attack",        rule:"AOVL_001",  desc:"Emit SYSTEM_ALERT_WINDOW overlay event (simulated)",      platform:"android", phase:"CredAccess",  tid:"T1411" },
];

// ── Known Techniques ──────────────────────────────────────────────────────────

const KNOWN_TECHNIQUES = [
  { tid:"T1547.001", name:"Registry Run Key Persistence",           phase:"Persistence"   },
  { tid:"T1543.003", name:"Service-Based Persistence",              phase:"Persistence"   },
  { tid:"T1204.002", name:"Malicious File Execution",               phase:"Execution"     },
  { tid:"T1571",     name:"Non-Standard Port C2",                   phase:"C2"            },
  { tid:"T1057",     name:"Process Discovery",                      phase:"Discovery"     },
  { tid:"T1049",     name:"Network Connections Discovery",          phase:"Discovery"     },
  { tid:"T1105",     name:"Ingress Tool Transfer",                  phase:"Collection"    },
  { tid:"T1113",     name:"Screen Capture",                         phase:"Collection"    },
  { tid:"T1125",     name:"Video Capture (Camera)",                 phase:"Collection"    },
  { tid:"T1123",     name:"Audio Capture (Microphone)",             phase:"Collection"    },
  { tid:"T1555",     name:"Credentials from Password Stores",       phase:"CredAccess"    },
  { tid:"T1005",     name:"Data from Local System",                 phase:"Collection"    },
  { tid:"T1055",     name:"Process Injection",                      phase:"Execution"     },
  { tid:"T1486",     name:"Data Encrypted for Impact",              phase:"Impact"        },
  { tid:"T1512",     name:"Video Capture (Android Camera)",         phase:"Collection",   platform:"android" },
  { tid:"T1429",     name:"Audio Capture (Android Microphone)",     phase:"Collection",   platform:"android" },
  { tid:"T1430",     name:"Location Tracking",                      phase:"Collection",   platform:"android" },
  { tid:"T1412",     name:"Capture SMS Messages",                   phase:"Collection",   platform:"android" },
  { tid:"T1432",     name:"Access Contact List",                    phase:"Collection",   platform:"android" },
  { tid:"T1411",     name:"Input Capture / Accessibility Service",  phase:"Collection",   platform:"android" },
  { tid:"T1517",     name:"Access Notifications",                   phase:"Collection",   platform:"android" },
  { tid:"T1513",     name:"Screen Capture (Android)",               phase:"Collection",   platform:"android" },
  { tid:"T1437",     name:"Application Layer Protocol (Android C2)",phase:"C2",           platform:"android" },
  { tid:"T1521",     name:"Encrypted C2 Channel (Android)",         phase:"C2",           platform:"android" },
  { tid:"T1418",     name:"Software Discovery / App Enumeration",   phase:"Discovery",    platform:"android" },
  { tid:"T1626",     name:"Abuse Elevation (Root / Device Admin)",  phase:"PrivEsc",      platform:"android" },
  { tid:"T1624",     name:"Boot Broadcast Receiver Persistence",    phase:"Persistence",  platform:"android" },
  { tid:"T1541",     name:"Foreground Service Persistence",         phase:"Persistence",  platform:"android" },
  { tid:"T1633",     name:"Virtualization/Sandbox Evasion",         phase:"DefenseEvasion",platform:"android"},
];

// ── Risk Scoring ──────────────────────────────────────────────────────────────

const RISK_SCORING = [
  { id:"RS_001", name:"Registry persistence",    desc:"Run key written outside standard paths",             score:25, check: b => b.events.some(e => e.rule==="REG_001"||e.rule==="REG_002") },
  { id:"RS_002", name:"Service persistence",     desc:"New Windows service created",                        score:25, check: b => b.events.some(e => e.rule==="SVC_001") },
  { id:"RS_003", name:"Suspicious C2 port",      desc:"Connection on known implant/shell port",             score:30, check: b => b.events.some(e => e.rule==="NET_002") },
  { id:"RS_004", name:"Automated beaconing",     desc:"Machine-regular poll interval (CV < 0.15)",         score:20, check: b => b.beaconStats?.flagged === true },
  { id:"RS_005", name:"Screenshot uploaded",     desc:"Screenshot file received by C2 server",             score:20, check: b => b.files.some(f => /\.(jpe?g|png|bmp)$/i.test(f)) },
  { id:"RS_006", name:"Suspicious process path", desc:"Process launched from Temp or AppData",             score:15, check: b => b.events.some(e => e.rule==="PROC_002"||e.rule==="PROC_003") },
  { id:"RS_007", name:"Executable dropped",      desc:"Executable written to Temp or AppData",             score:15, check: b => b.events.some(e => e.rule==="FILE_001") },
  { id:"RS_008", name:"Active correlated incident", desc:"High-confidence (≥65%) incident still open",     score:30, check: b => b.incidents.some(i => i.status==="open" && i.confidence>=65) },
  { id:"RS_009", name:"C2 network activity",     desc:"Bot established >5 outbound connections to C2",     score:10, check: b => b.netlog.length > 5 },
];

// ── Stub Builder Config ───────────────────────────────────────────────────────

const STUB_STRUCT = {
  botapi:         { off:   0, len: 128 },
  key:            { off: 128, len:  16 },
  chatid:         { off: 144, len: 128 },
  drop:           { off: 272, len: 128 },
  drop_run:       { off: 400, len:   1 },
  scheduler_name: { off: 401, len:  50 },
  scheduler_state:{ off: 451, len:   1 },
  autorun:        { off: 452, len: 128 },
  autorun_state:  { off: 580, len:   1 },
  client_delay:   { off: 581, len:  10 },
  auto_delete:    { off: 591, len:   1 },
  protector:      { off: 592, len:   1 },
  protectorName:  { off: 593, len:  50 },
};
const STUB_SETTINGS_SIZE = 643;
const STUB_MAGIC = Buffer.from([0xB4, 0x4B, 0xD4, 0x3E, 0x7A, 0x91, 0xC3, 0xF8]);

module.exports = {
  AUTH_KEY, ADMIN_PASS, PORT, CORS_ORIGIN, UPLOADS_DIR,
  MAX_EVENTS, MAX_DETECTIONS, MAX_INCIDENTS, MAX_NETLOG,
  DETECTION_RULES, CORRELATION_RULES, SIMULATION_ACTIONS, KNOWN_TECHNIQUES, RISK_SCORING,
  STUB_STRUCT, STUB_SETTINGS_SIZE, STUB_MAGIC,
};
