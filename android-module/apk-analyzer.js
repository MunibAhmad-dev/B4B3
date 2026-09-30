#!/usr/bin/env node
/**
 * B4DB4B3-RAT  APK Static Analyzer
 * ──────────────────────────────────
 * Performs static analysis on an Android APK without executing it.
 *
 * Analysis:
 *   • Parses AndroidManifest.xml (binary AXML format — string pool extraction)
 *   • Extracts and risk-scores declared permissions
 *   • Identifies suspicious components (services, receivers, activities)
 *   • Reads signing certificate (META-INF/*.RSA / *.DSA / *.EC)
 *   • Scans classes.dex for suspicious strings (URLs, IPs, C2 paths, tools)
 *   • Computes APK hash (SHA-256, MD5)
 *   • Generates a risk score and structured report
 *   • Optionally submits the report to the C2 server
 *
 * Dependencies: built-in Node.js only (zlib + crypto)
 *
 * Usage:
 *   node apk-analyzer.js --path app.apk [options]
 *
 * Options:
 *   --path      Path to APK file                    (required)
 *   --output    Save JSON report to this file
 *   --host      Submit to C2 server hostname
 *   --port      C2 server port                      (default: 443)
 *   --auth      C2 auth key                         (default: changeme)
 *   --botId     Bot ID for submission               (default: APK_<sha256[:8]>)
 *   --http      Use plain HTTP for submission
 *   --quiet     Print JSON only (no banner)
 */

"use strict";

const fs      = require("fs");
const path    = require("path");
const zlib    = require("zlib");
const crypto  = require("crypto");
const https   = require("https");
const http    = require("http");

// ── Argument parsing ──────────────────────────────────────────────────────────

const args = {};
process.argv.slice(2).forEach((a, i, arr) => {
  if (a.startsWith("--")) {
    const key = a.slice(2);
    const next = arr[i + 1];
    args[key] = (next && !next.startsWith("--")) ? next : true;
  }
});

if (!args.path) {
  console.error("Usage: node apk-analyzer.js --path <app.apk> [--output report.json] [--host <c2>]");
  process.exit(1);
}

const APK_PATH = args.path;
const QUIET    = args.quiet === true || args.quiet === "true";

// ── Permission risk catalogue ─────────────────────────────────────────────────

const PERM_RISK = {
  "android.permission.CAMERA":                       { score:20, sev:"HIGH",     desc:"Camera access — video/photo capture",         tid:"T1512" },
  "android.permission.RECORD_AUDIO":                 { score:20, sev:"HIGH",     desc:"Microphone — audio recording",                tid:"T1429" },
  "android.permission.ACCESS_FINE_LOCATION":         { score:20, sev:"HIGH",     desc:"Precise GPS location tracking",               tid:"T1430" },
  "android.permission.ACCESS_BACKGROUND_LOCATION":   { score:30, sev:"CRITICAL", desc:"Background GPS — tracks even when app closed", tid:"T1430" },
  "android.permission.READ_CONTACTS":                { score:15, sev:"HIGH",     desc:"Read full contact list",                      tid:"T1432" },
  "android.permission.WRITE_CONTACTS":               { score:10, sev:"MEDIUM",   desc:"Modify contact list",                         tid:"T1432" },
  "android.permission.READ_SMS":                     { score:25, sev:"CRITICAL", desc:"Read all SMS messages",                       tid:"T1412" },
  "android.permission.SEND_SMS":                     { score:25, sev:"CRITICAL", desc:"Send SMS without user interaction",           tid:"T1412" },
  "android.permission.RECEIVE_SMS":                  { score:20, sev:"HIGH",     desc:"Intercept incoming SMS (OTP bypass)",         tid:"T1412" },
  "android.permission.READ_CALL_LOG":                { score:20, sev:"HIGH",     desc:"Read call history",                           tid:"T1432" },
  "android.permission.PROCESS_OUTGOING_CALLS":       { score:20, sev:"HIGH",     desc:"Intercept and modify outgoing calls",         tid:"T1432" },
  "android.permission.BIND_ACCESSIBILITY_SERVICE":   { score:35, sev:"CRITICAL", desc:"Accessibility service — full UI interception + keylogging", tid:"T1411" },
  "android.permission.BIND_DEVICE_ADMIN":            { score:40, sev:"CRITICAL", desc:"Device admin — prevents uninstall",           tid:"T1626" },
  "android.permission.RECEIVE_BOOT_COMPLETED":       { score:15, sev:"MEDIUM",   desc:"Auto-start on reboot",                        tid:"T1624.001" },
  "android.permission.REQUEST_INSTALL_PACKAGES":     { score:25, sev:"HIGH",     desc:"Install other APKs (dropper capability)",     tid:"T1544" },
  "android.permission.SYSTEM_ALERT_WINDOW":          { score:20, sev:"HIGH",     desc:"Draw over other apps (overlay/phishing)",     tid:"T1411" },
  "android.permission.READ_EXTERNAL_STORAGE":        { score:10, sev:"MEDIUM",   desc:"Read files from SD card / shared storage",    tid:"T1533" },
  "android.permission.WRITE_EXTERNAL_STORAGE":       { score:10, sev:"MEDIUM",   desc:"Write files to shared storage",               tid:"T1533" },
  "android.permission.READ_PHONE_STATE":             { score:15, sev:"MEDIUM",   desc:"Read IMEI, SIM serial, phone number",         tid:"T1422" },
  "android.permission.INTERNET":                     { score: 5, sev:"LOW",      desc:"Internet access (required for C2)",           tid:"T1437" },
  "android.permission.ACCESS_WIFI_STATE":            { score: 5, sev:"LOW",      desc:"Wi-Fi network information",                   tid:"T1422" },
  "android.permission.CHANGE_NETWORK_STATE":         { score: 8, sev:"LOW",      desc:"Modify network settings",                     tid:"T1437" },
  "android.permission.FOREGROUND_SERVICE":           { score: 8, sev:"LOW",      desc:"Long-running foreground service",             tid:"T1541" },
  "android.permission.WAKE_LOCK":                    { score: 3, sev:"INFO",     desc:"Prevent device sleep",                        tid:"T1541" },
  "android.permission.DISABLE_KEYGUARD":             { score:20, sev:"HIGH",     desc:"Disable screen lock",                         tid:"T1626" },
  "android.permission.USE_BIOMETRIC":                { score:10, sev:"MEDIUM",   desc:"Biometric authentication access",             tid:null    },
  "android.permission.VIBRATE":                      { score: 0, sev:"INFO",     desc:"Device vibration",                            tid:null    },
  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": { score:15, sev:"MEDIUM", desc:"Read all app notifications",             tid:"T1517" },
  "android.permission.USE_CREDENTIALS":              { score:20, sev:"HIGH",     desc:"Use account credentials",                     tid:"T1555" },
  "android.permission.MANAGE_ACCOUNTS":              { score:20, sev:"HIGH",     desc:"Manage device accounts",                      tid:"T1555" },
  "android.permission.WRITE_SETTINGS":               { score:15, sev:"MEDIUM",   desc:"Modify system settings",                      tid:null    },
  "android.permission.CHANGE_WIFI_STATE":            { score: 5, sev:"LOW",      desc:"Connect/disconnect Wi-Fi",                    tid:null    },
  "android.permission.NFC":                          { score:10, sev:"MEDIUM",   desc:"NFC access — proximity data collection",      tid:null    },
  "android.permission.BLUETOOTH":                    { score: 5, sev:"LOW",      desc:"Bluetooth device discovery",                  tid:null    },
  "android.permission.BLUETOOTH_ADMIN":              { score: 8, sev:"LOW",      desc:"Modify Bluetooth settings",                   tid:null    },
};

// ── Suspicious string patterns ────────────────────────────────────────────────

const SUSPICIOUS_PATTERNS = [
  { re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,                                    cat:"ip",        desc:"Hardcoded IP address" },
  { re: /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,6}[^\s"'<>]{0,100}/gi,          cat:"url",       desc:"Hardcoded URL" },
  { re: /\/api\/(?:check|sync|poll|beacon|report|upload|cmd|result)/gi,     cat:"c2_path",   desc:"C2 endpoint path" },
  { re: /(?:su|superuser|magisk|kingroot|kingoroot)/gi,                     cat:"root",      desc:"Root tool reference" },
  { re: /frida|xposed|substrate|cydia|JustTrustMe/gi,                       cat:"hook",      desc:"Hooking framework reference" },
  { re: /BuildConfig\.DEBUG|isDebuggerConnected|Debug\.isDebuggerConnect/g, cat:"anti_dbg",  desc:"Debugger detection" },
  { re: /\/proc\/self\/status|TracerPid/g,                                  cat:"anti_dbg",  desc:"Linux tracer detection" },
  { re: /adb|adbd|ddms/gi,                                                  cat:"anti_adb",  desc:"ADB/debugger reference" },
  { re: /WRITE_SETTINGS|SYSTEM_ALERT_WINDOW|BIND_ACCESSIBILITY/gi,          cat:"perm_str",  desc:"High-risk permission string reference" },
  { re: /KeyEvent|AccessibilityEvent|onAccessibilityEvent/g,                cat:"a11y",      desc:"Accessibility event handling" },
  { re: /ClipboardManager|clipboardManager/g,                               cat:"clipboard", desc:"Clipboard access code" },
  { re: /MediaProjection|createVirtualDisplay|ImageReader/g,                cat:"screen",    desc:"Screen capture code" },
  { re: /AudioRecord|MediaRecorder/g,                                       cat:"audio",     desc:"Audio recording code" },
  { re: /Camera2|CameraDevice|CameraManager/g,                              cat:"camera",    desc:"Camera access code" },
  { re: /LocationManager|FusedLocationProvider/g,                           cat:"location",  desc:"Location API usage" },
  { re: /SmsManager|SmsMessage/g,                                           cat:"sms",       desc:"SMS API usage" },
  { re: /DevicePolicyManager|ComponentName.*admin/gi,                       cat:"da",        desc:"Device admin code" },
  { re: /AES|DES|RC4|Cipher\.getInstance/g,                                 cat:"crypto",    desc:"Encryption code" },
  { re: /Base64\.(?:encode|decode)/g,                                       cat:"obfusc",    desc:"Base64 encoding (possible obfuscation)" },
  { re: /Runtime\.exec|ProcessBuilder|cmd\.exe|\/bin\/sh/g,                 cat:"exec",      desc:"Shell command execution" },
  { re: /TrustManager|X509TrustManager|checkServerTrusted/g,                cat:"ssl_bypass",desc:"Custom TrustManager (SSL bypass)" },
  { re: /HostnameVerifier|ALLOW_ALL_HOSTNAME/g,                             cat:"ssl_bypass",desc:"Hostname verification bypass" },
];

// ── ZIP / APK reader ──────────────────────────────────────────────────────────
// Node.js has no built-in ZIP parser; this is a minimal implementation
// that reads the ZIP central directory to enumerate files and their offsets.

function readZipEntries(buf) {
  // Locate End of Central Directory (EOCD) signature 0x06054b50 from end
  const EOCD_SIG = 0x06054b50;
  let eocdOff = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) { eocdOff = i; break; }
  }
  if (eocdOff < 0) throw new Error("Not a valid ZIP file (EOCD not found)");

  const cdOffset = buf.readUInt32LE(eocdOff + 16);
  const cdEntries = buf.readUInt16LE(eocdOff + 10);

  const entries = [];
  let pos = cdOffset;
  const CD_SIG = 0x02014b50;

  for (let i = 0; i < cdEntries && pos + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(pos) !== CD_SIG) break;
    const method       = buf.readUInt16LE(pos + 10);
    const crc          = buf.readUInt32LE(pos + 16);
    const compSize     = buf.readUInt32LE(pos + 20);
    const uncompSize   = buf.readUInt32LE(pos + 24);
    const fnLen        = buf.readUInt16LE(pos + 28);
    const extraLen     = buf.readUInt16LE(pos + 30);
    const commentLen   = buf.readUInt16LE(pos + 32);
    const localOffset  = buf.readUInt32LE(pos + 42);
    const name         = buf.slice(pos + 46, pos + 46 + fnLen).toString("utf8");
    entries.push({ name, method, compSize, uncompSize, localOffset, crc });
    pos += 46 + fnLen + extraLen + commentLen;
  }
  return entries;
}

function readZipEntry(buf, entry) {
  // Local file header: sig(4) ver(2) flags(2) method(2) time(4) crc(4) comp(4) uncomp(4) fnLen(2) extraLen(2)
  const LOCAL_SIG = 0x04034b50;
  const pos = entry.localOffset;
  if (buf.readUInt32LE(pos) !== LOCAL_SIG) throw new Error(`Bad local header for ${entry.name}`);
  const fnLen    = buf.readUInt16LE(pos + 26);
  const extraLen = buf.readUInt16LE(pos + 28);
  const dataOff  = pos + 30 + fnLen + extraLen;
  const data     = buf.slice(dataOff, dataOff + entry.compSize);

  if (entry.method === 0) return data;          // STORED
  if (entry.method === 8) return zlib.inflateRawSync(data); // DEFLATE
  throw new Error(`Unsupported compression method ${entry.method} for ${entry.name}`);
}

// ── AXML string pool parser ───────────────────────────────────────────────────
// AndroidManifest.xml inside an APK is binary AXML (Android Binary XML).
// The string pool at the start of the file contains all element names and
// attribute values — including permissions, package names, components.

function parseAXMLStrings(buf) {
  if (buf.length < 32) return [];
  // Magic: file type=0x00080003, chunk size at [4..7]
  if (buf.readUInt32LE(0) !== 0x00080003) return [];

  // String pool chunk starts at offset 8
  // Chunk header: type(4) chunkSize(4) stringCount(4) styleCount(4) flags(4) stringsStart(4) stylesStart(4)
  const poolBase    = 8;
  if (poolBase + 28 > buf.length) return [];
  const poolType    = buf.readUInt32LE(poolBase);
  if ((poolType & 0x0000FFFF) !== 0x0001) return []; // must be string pool

  const strCount    = buf.readUInt32LE(poolBase + 8);
  const flags       = buf.readUInt32LE(poolBase + 16);
  const isUTF8      = (flags & 0x100) !== 0;
  const strStart    = buf.readUInt32LE(poolBase + 20); // offset from pool chunk base to string data

  const offsetsBase = poolBase + 28;                  // string offset array
  const dataBase    = poolBase + strStart;

  const strings = [];
  for (let i = 0; i < strCount && i < 5000; i++) {
    const arrOff = offsetsBase + i * 4;
    if (arrOff + 4 > buf.length) break;
    const strOff = dataBase + buf.readUInt32LE(arrOff);
    if (strOff + 2 > buf.length) continue;

    let str = "";
    try {
      if (isUTF8) {
        // UTF-8: varint char count, varint byte count, then bytes
        let p = strOff;
        const hi = buf[p]; p++;
        let charLen = hi;
        if (hi & 0x80) { charLen = ((hi & 0x7F) << 8) | buf[p]; p++; }
        const lo = buf[p]; p++;
        let byteLen = lo;
        if (lo & 0x80) { byteLen = ((lo & 0x7F) << 8) | buf[p]; p++; }
        if (p + byteLen <= buf.length) str = buf.slice(p, p + byteLen).toString("utf8");
      } else {
        // UTF-16LE: 2-byte char count, then chars, then null term
        const charLen = buf.readUInt16LE(strOff);
        const dataStart = strOff + 2;
        if (dataStart + charLen * 2 <= buf.length)
          str = buf.slice(dataStart, dataStart + charLen * 2).toString("utf16le");
      }
    } catch (_) {}
    if (str.length > 0) strings.push(str);
  }
  return strings;
}

// ── Certificate parser ────────────────────────────────────────────────────────
// Reads the signing certificate from META-INF/*.RSA (PKCS#7 DER blob).
// Extracts the embedded X.509 certificate's subject, issuer, and validity.

function parseCertInfo(derBuf) {
  // DER encoding: look for certificate serial by scanning for OID patterns.
  // Minimal approach: search for printable strings in the DER blob.
  const strings = [];
  let i = 0;
  while (i < derBuf.length - 3) {
    // PrintableString tag = 0x13, UTF8String = 0x0C, IA5String = 0x16, BMPString = 0x1E
    const tag = derBuf[i];
    if (tag === 0x13 || tag === 0x0C || tag === 0x16) {
      const len = derBuf[i + 1];
      if (len < 2 || len > 200) { i++; continue; }
      if (i + 2 + len <= derBuf.length) {
        const s = derBuf.slice(i + 2, i + 2 + len).toString(tag === 0x1E ? "utf16le" : "ascii");
        if (s.trim().length > 1) strings.push(s.trim());
        i += 2 + len;
        continue;
      }
    }
    i++;
  }
  // Deduplicate and filter noise
  const unique = [...new Set(strings)].filter(s => s.length > 2 && !/^[\x00-\x1F]+$/.test(s));

  // Extract subject-like fields (CN=, O=, OU=, etc.)
  const certFields = unique.filter(s => /^[A-Z]{1,3}=.+/.test(s) || s.includes("Android") || s.includes("Debug") || s.includes("CERT") || /[a-z]{3,}/.test(s));

  return {
    subject:   certFields.slice(0, 8),
    isDebug:   unique.some(s => /debug|Android Debug|testkey/i.test(s)),
    allStrings: unique.slice(0, 30),
  };
}

// ── DEX string scanner ────────────────────────────────────────────────────────

function scanDexStrings(dexBuf) {
  // DEX header: magic "dex\n035\0", string_ids_size at [56], string_ids_off at [60]
  if (dexBuf.length < 112) return [];
  const magic = dexBuf.slice(0, 8).toString("ascii");
  if (!magic.startsWith("dex\n")) return [];

  const strCount = dexBuf.readUInt32LE(56);
  const strOff   = dexBuf.readUInt32LE(60);

  const rawText = dexBuf.toString("utf8");
  const findings = [];

  for (const pat of SUSPICIOUS_PATTERNS) {
    pat.re.lastIndex = 0;
    const matches = [...rawText.matchAll(pat.re)]
      .map(m => m[0].trim())
      .filter(s => s.length > 4 && s.length < 200)
      .slice(0, 10);
    if (matches.length > 0)
      findings.push({ category: pat.cat, description: pat.desc, samples: matches });
  }
  return findings;
}

// ── Hash helpers ──────────────────────────────────────────────────────────────

function hashBuf(buf) {
  return {
    md5:    crypto.createHash("md5").update(buf).digest("hex"),
    sha1:   crypto.createHash("sha1").update(buf).digest("hex"),
    sha256: crypto.createHash("sha256").update(buf).digest("hex"),
  };
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

function scoreReport(permissions, certInfo, findings) {
  let score = 0;
  const breakdown = [];

  for (const p of permissions) {
    if (p.score > 0) {
      score += p.score;
      breakdown.push({ id: p.permission.split(".").pop(), score: p.score, reason: p.desc });
    }
  }

  // Debug certificate (test/debug key — never production)
  if (certInfo.isDebug) { score += 5; breakdown.push({ id:"DEBUG_CERT", score:5, reason:"Signed with debug/test key" }); }

  // Suspicious string findings
  const critCats = ["c2_path","ssl_bypass","hook","root","screen","audio","camera"];
  for (const f of findings) {
    if (critCats.includes(f.category)) { score += 15; breakdown.push({ id:f.category.toUpperCase(), score:15, reason:f.description }); }
    else                               { score +=  5; breakdown.push({ id:f.category.toUpperCase(), score:5,  reason:f.description }); }
  }

  return { score: Math.min(score, 300), breakdown };
}

// ── Report submission ─────────────────────────────────────────────────────────

function submitReport(report) {
  if (!args.host) return Promise.resolve();
  const USE_HTTP = args.http === true || args.http === "true";
  const transport = USE_HTTP ? http : https;
  const PORT_NUM = parseInt(args.port || "443", 10);
  const botId = args.botId || `APK_${report.hashes.sha256.slice(0, 8).toUpperCase()}`;

  return new Promise((resolve) => {
    // 1. Check-in
    const infoStr = encodeURIComponent(`ANDROID | APK | ${report.packageName} | ${report.hashes.sha256.slice(0, 8)}`);
    const opts1 = {
      hostname: args.host, port: PORT_NUM,
      path: `/checkin?id=${botId}&auth=${args.auth || "changeme"}&info=${infoStr}`,
      method: "GET", rejectUnauthorized: false,
    };
    const r1 = transport.request(opts1, () => {
      // 2. Submit as a single summary event
      const summaryEvent = {
        bot:         botId,
        platform:    "android",
        cat:         "apk_analysis",
        type:        "static_report",
        sev:         report.riskScore >= 100 ? "critical" : report.riskScore >= 60 ? "high" : "medium",
        rule:        "AAPK_001",
        ev:          `APK analysis: ${report.packageName} — risk score ${report.riskScore}`,
        pkg:          report.packageName,
        version:     report.versionName,
        sha256:      report.hashes.sha256,
        permissions: report.permissions.length,
        critical_perms: report.permissions.filter(p => p.sev === "CRITICAL").length,
        tid:         "T1418",
        tname:       "Software Discovery",
      };
      const body = JSON.stringify(summaryEvent);
      const opts2 = {
        hostname: args.host, port: PORT_NUM,
        path: `/event?id=${botId}&auth=${args.auth || "changeme"}`,
        method: "POST",
        headers: { "Content-Type":"application/json", "Content-Length":Buffer.byteLength(body) },
        rejectUnauthorized: false,
      };
      const r2 = transport.request(opts2, () => resolve());
      r2.on("error", () => resolve());
      r2.write(body);
      r2.end();
    });
    r1.on("error", () => resolve());
    r1.end();
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function analyze() {
  const HR = "─".repeat(64);

  if (!QUIET) {
    console.log(HR);
    console.log("B4DB4B3-RAT  APK Static Analyzer");
    console.log(HR);
    console.log(`File: ${APK_PATH}`);
    console.log("");
  }

  if (!fs.existsSync(APK_PATH)) {
    console.error(`File not found: ${APK_PATH}`);
    process.exit(1);
  }

  const apkBuf  = fs.readFileSync(APK_PATH);
  const hashes  = hashBuf(apkBuf);
  const size    = apkBuf.length;

  if (!QUIET) process.stdout.write("[1/5] Reading ZIP entries ...        ");
  let entries;
  try {
    entries = readZipEntries(apkBuf);
  } catch (e) {
    console.error(`\nFailed to parse APK: ${e.message}`);
    process.exit(1);
  }
  if (!QUIET) console.log(`${entries.length} files`);

  const fileList = entries.map(e => ({ name: e.name, size: e.uncompSize }));

  // ── Parse AndroidManifest.xml ──────────────────────────────────────────────
  if (!QUIET) process.stdout.write("[2/5] Parsing AndroidManifest.xml ...");
  let manifestStrings = [];
  let packageName     = "unknown";
  let versionName     = "?";
  let permissions     = [];
  let components      = { activities:[], services:[], receivers:[], providers:[] };

  const manifestEntry = entries.find(e => e.name === "AndroidManifest.xml");
  if (manifestEntry) {
    try {
      const manifestBuf = readZipEntry(apkBuf, manifestEntry);
      manifestStrings   = parseAXMLStrings(manifestBuf);

      // Extract package name (usually second or third string in the pool)
      // It looks like "com.example.app"
      const pkgCand = manifestStrings.find(s => /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,6}$/.test(s) && !s.startsWith("android.") && !s.startsWith("com.google.android"));
      if (pkgCand) packageName = pkgCand;

      // Extract version strings
      const verCand = manifestStrings.find(s => /^\d+\.\d+(\.\d+)?$/.test(s));
      if (verCand) versionName = verCand;

      // Extract permissions
      for (const s of manifestStrings) {
        if (s.startsWith("android.permission.") || s.startsWith("com.android.") || s.includes(".permission.")) {
          const known = PERM_RISK[s];
          permissions.push({
            permission: s,
            score:  known?.score ?? 0,
            sev:    known?.sev   ?? "INFO",
            desc:   known?.desc  ?? "Unknown permission",
            tid:    known?.tid   ?? null,
          });
        }
      }
      permissions = [...new Map(permissions.map(p => [p.permission, p])).values()];

      // Heuristic component extraction: strings ending in known component patterns
      for (const s of manifestStrings) {
        if (s.includes("Activity") && s.startsWith(packageName))  components.activities.push(s);
        else if (s.includes("Service") && s.startsWith(packageName)) components.services.push(s);
        else if (s.includes("Receiver") && s.startsWith(packageName)) components.receivers.push(s);
        else if (s.includes("Provider") && s.startsWith(packageName)) components.providers.push(s);
      }
    } catch (e) {
      if (!QUIET) console.log(` (parse error: ${e.message})`);
    }
  }
  if (!QUIET) console.log(` OK  (${permissions.length} permissions, pkg: ${packageName})`);

  // ── Certificate parsing ────────────────────────────────────────────────────
  if (!QUIET) process.stdout.write("[3/5] Reading signing certificate ... ");
  let certInfo = { subject:[], isDebug:false, allStrings:[] };
  let certFile  = null;

  const certEntry = entries.find(e => /^META-INF\/.*\.(RSA|DSA|EC)$/i.test(e.name));
  if (certEntry) {
    certFile = certEntry.name;
    try {
      const certBuf = readZipEntry(apkBuf, certEntry);
      certInfo = parseCertInfo(certBuf);
    } catch (_) {}
  }
  if (!QUIET) console.log(certFile ? `${certFile}${certInfo.isDebug ? "  ⚠ DEBUG CERT" : ""}` : "not found");

  // ── DEX string scan ────────────────────────────────────────────────────────
  if (!QUIET) process.stdout.write("[4/5] Scanning DEX strings ...       ");
  let dexFindings = [];
  const dexEntries = entries.filter(e => e.name.endsWith(".dex"));
  for (const de of dexEntries.slice(0, 3)) { // scan up to 3 DEX files
    try {
      const dexBuf = readZipEntry(apkBuf, de);
      dexFindings.push(...scanDexStrings(dexBuf));
    } catch (_) {}
  }
  // Deduplicate by category
  const catSeen = new Set();
  dexFindings = dexFindings.filter(f => { if (catSeen.has(f.category)) return false; catSeen.add(f.category); return true; });
  if (!QUIET) console.log(`${dexFindings.length} suspicious pattern(s) found`);

  // ── Risk scoring ───────────────────────────────────────────────────────────
  if (!QUIET) process.stdout.write("[5/5] Computing risk score ...        ");
  const { score: riskScore, breakdown: riskBreakdown } = scoreReport(permissions, certInfo, dexFindings);
  const riskLabel = riskScore >= 150 ? "CRITICAL" : riskScore >= 80 ? "HIGH" : riskScore >= 40 ? "MEDIUM" : "LOW";
  if (!QUIET) console.log(`${riskScore}  (${riskLabel})\n`);

  // ── Build report ───────────────────────────────────────────────────────────
  const criticalPerms = permissions.filter(p => p.sev === "CRITICAL");
  const highPerms     = permissions.filter(p => p.sev === "HIGH");

  const report = {
    meta: {
      analyzer:   "B4DB4B3-RAT APK Static Analyzer",
      generated:  new Date().toISOString(),
      apkPath:    path.basename(APK_PATH),
      sizeBytes:  size,
    },
    hashes,
    packageName,
    versionName,
    riskScore,
    riskLabel,
    riskBreakdown,
    signingCert: {
      file:    certFile,
      isDebug: certInfo.isDebug,
      subject: certInfo.subject,
    },
    permissions: permissions.sort((a,b) => b.score - a.score),
    summary: {
      totalPermissions:    permissions.length,
      criticalPermissions: criticalPerms.length,
      highPermissions:     highPerms.length,
      suspiciousPatterns:  dexFindings.length,
      fileCount:           entries.length,
    },
    components,
    suspiciousStrings: dexFindings,
    fileList: fileList.slice(0, 100),
    attackTechniques: [...new Set(permissions.filter(p=>p.tid).map(p=>p.tid))],
  };

  // ── Print console summary ──────────────────────────────────────────────────
  if (!QUIET) {
    console.log(HR);
    console.log(`APK Analysis Report`);
    console.log(HR);
    console.log(`Package      : ${packageName}  v${versionName}`);
    console.log(`SHA-256      : ${hashes.sha256}`);
    console.log(`Size         : ${(size/1024/1024).toFixed(2)} MB  |  Files: ${entries.length}`);
    console.log(`Risk Score   : \x1b[${riskScore>=150?31:riskScore>=80?33:32}m${riskScore}  (${riskLabel})\x1b[0m`);
    console.log(`Certificate  : ${certFile || "none"}${certInfo.isDebug ? "  ⚠ DEBUG/TEST KEY" : ""}`);
    console.log("");

    if (criticalPerms.length) {
      console.log("\x1b[31mCRITICAL permissions:\x1b[0m");
      criticalPerms.forEach(p => console.log(`  • ${p.permission}\n    ${p.desc}  [${p.tid||"—"}]`));
      console.log("");
    }
    if (highPerms.length) {
      console.log("\x1b[33mHIGH-risk permissions:\x1b[0m");
      highPerms.forEach(p => console.log(`  • ${p.permission}\n    ${p.desc}  [${p.tid||"—"}]`));
      console.log("");
    }
    if (dexFindings.length) {
      console.log("Suspicious patterns in DEX:");
      dexFindings.forEach(f => {
        console.log(`  • [${f.category.padEnd(12)}] ${f.description}`);
        f.samples.slice(0, 2).forEach(s => console.log(`    Sample: ${s.substring(0, 80)}`));
      });
      console.log("");
    }
    if (report.attackTechniques.length) {
      console.log("ATT&CK Mobile techniques implied:");
      report.attackTechniques.forEach(t => console.log(`  • ${t}`));
      console.log("");
    }
    console.log(HR);
  }

  // ── Save report ────────────────────────────────────────────────────────────
  if (args.output) {
    fs.writeFileSync(args.output, JSON.stringify(report, null, 2));
    if (!QUIET) console.log(`Report saved: ${args.output}`);
  } else {
    if (QUIET) console.log(JSON.stringify(report, null, 2));
  }

  // ── Submit to C2 ──────────────────────────────────────────────────────────
  if (args.host) {
    if (!QUIET) process.stdout.write("Submitting to C2 server ... ");
    await submitReport(report);
    if (!QUIET) console.log("done");
  }

  if (!QUIET) console.log(HR);
  return report;
}

analyze().catch(err => {
  console.error("Fatal:", err.message);
  process.exit(1);
});
