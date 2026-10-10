/*
  Exercise 01 — C2 Server: Core HTTP Routes (Node.js + Express)
  --------------------------------------------------------------
  Build the team-server side of a minimal C2 framework.
  The agent (implant) will POST to /beacon to check in and receive tasks.
  The operator (you) will POST to /task to queue commands.

  Protocol:
    POST /beacon  { agentId, hostname, username, os }
                  → returns { taskId, taskType, taskData } or {}
    POST /result  { agentId, taskId, output }
                  → stores result, returns { ok: true }
    POST /task    { agentId, taskType, taskData }  (operator API)
                  → queues a task, returns { taskId }
    GET  /agents  → list all registered agents + last seen
    GET  /results → list all completed results

  Tasks:
  1. Implement POST /beacon:
     - Register new agents (or update lastSeen).
     - Pop the oldest pending task for this agent (FIFO queue).
     - Return the task, or {} if nothing pending.
  2. Implement POST /result:
     - Store the output keyed by agentId + taskId.
     - Mark the task as completed.
  3. Implement POST /task:
     - Validate taskType is one of: shell, screenshot, upload, download, exit.
     - Assign a UUID task ID.
     - Push to the agent's pending queue.
  4. Implement GET /agents and GET /results.

  BONUS:
  - Add AES-256-GCM encryption for all request/response bodies.
    The agent and server share a key exchanged at registration.
  - Add a simple HTML operator panel (GET /) that lists agents and results.
  - Add rate limiting (max 1 beacon/second per agent).

  Run:
    npm install express uuid
    node ex01_c2_server_routes.js
  Test:
    curl -s -X POST http://localhost:4444/beacon \
         -H "Content-Type: application/json" \
         -d '{"agentId":"test-001","hostname":"WIN10","username":"user","os":"win"}'
*/

const express = require('express');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = 4444;

app.use(express.json());

// In-memory state
const agents  = {};  // agentId → { hostname, username, os, lastSeen, tasks: [] }
const results = {};  // taskId  → { agentId, output, completedAt }

const VALID_TASK_TYPES = ['shell', 'screenshot', 'upload', 'download', 'exit'];

// ---------- TODO 1: POST /beacon ----------
app.post('/beacon', (req, res) => {
    const { agentId, hostname, username, os } = req.body;
    if (!agentId) return res.status(400).json({ error: 'missing agentId' });

    // YOUR CODE HERE:
    // - If agentId not in agents, add it
    // - Update agents[agentId].lastSeen = new Date().toISOString()
    // - Pop agents[agentId].tasks.shift() (FIFO)
    // - If a task exists, return it; else return {}

    console.log(`[BEACON] ${agentId} @ ${hostname || '?'} (${username || '?'})`);
    (void)hostname; (void)username; (void)os;
    res.json({}); // replace: return task or {}
});

// ---------- TODO 2: POST /result ----------
app.post('/result', (req, res) => {
    const { agentId, taskId, output } = req.body;
    if (!agentId || !taskId) return res.status(400).json({ error: 'missing fields' });

    // YOUR CODE HERE:
    // - results[taskId] = { agentId, output, completedAt: new Date().toISOString() }

    console.log(`[RESULT] ${agentId}  task=${taskId}  output=${String(output).slice(0,80)}`);
    (void)output;
    res.json({ ok: true });
});

// ---------- TODO 3: POST /task ----------
app.post('/task', (req, res) => {
    const { agentId, taskType, taskData } = req.body;

    // YOUR CODE HERE:
    // - Validate agentId exists in agents
    // - Validate taskType is in VALID_TASK_TYPES
    // - const taskId = uuidv4()
    // - Push { taskId, taskType, taskData } to agents[agentId].tasks
    // - Return { taskId }

    (void)agentId; (void)taskType; (void)taskData;
    res.status(501).json({ error: 'not implemented' });
});

// ---------- TODO 4: GET /agents ----------
app.get('/agents', (req, res) => {
    // YOUR CODE HERE: return array of { agentId, hostname, username, os, lastSeen, pendingTasks }
    res.json(Object.entries(agents).map(([id, a]) => ({
        agentId: id,
        // fill in remaining fields
    })));
});

// ---------- GET /results ----------
app.get('/results', (req, res) => {
    res.json(Object.entries(results).map(([tid, r]) => ({ taskId: tid, ...r })));
});

app.listen(PORT, () => {
    console.log(`[C2] Team server listening on :${PORT}`);
    console.log(`  POST /beacon   (agent check-in)`);
    console.log(`  POST /result   (agent task output)`);
    console.log(`  POST /task     (operator queue command)`);
    console.log(`  GET  /agents   (list registered agents)`);
    console.log(`  GET  /results  (list completed results)`);
});
