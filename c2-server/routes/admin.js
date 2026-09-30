"use strict";

const fs      = require("fs");
const path    = require("path");
const express = require("express");

const { UPLOADS_DIR, SIMULATION_ACTIONS, KNOWN_TECHNIQUES, MAX_EVENTS } = require("../config/constants");
const { requireAdmin }         = require("../middleware/auth");
const { bots, coverageRuns }   = require("../state");
const { runDetection, computeRiskScore } = require("../controllers/detectionEngine");
const { extractIOCs, iocsToCSV, iocsToSTIX, iocsToMarkdown } = require("../controllers/iocController");

const router = express.Router();

// ── Bot list ──────────────────────────────────────────────────────────────────

router.get("/api/bots", requireAdmin, (_req, res) => {
  res.json(Object.values(bots).map(b => ({
    id:             b.id,
    lastSeen:       b.lastSeen,
    firstSeen:      b.firstSeen,
    hasPending:     !!b.pendingCmd,
    resultCount:    b.results.length,
    fileCount:      b.files.length,
    eventCount:     b.events.length,
    highEvents:     b.events.filter(e => e.sev === "high" || e.sev === "critical").length,
    incidentCount:  b.incidents.length,
    openIncidents:  b.incidents.filter(i => i.status === "open").length,
    maxConfidence:  b.incidents.reduce((m, i) => Math.max(m, i.confidence), 0),
    netlogCount:    b.netlog.length,
    beaconFlagged:  b.beaconStats?.flagged || false,
    beaconInterval: b.beaconStats?.intervalMs || null,
    riskScore:      b.riskScore || 0,
    blocked:        b.blocked || false,
  })));
});

// ── Bot detail ────────────────────────────────────────────────────────────────

router.get("/api/bot/:id", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  res.json(bot);
});

router.post("/api/bot/:id/cmd", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  const cmd = (req.body.cmd || "").trim();
  if (!cmd) return res.status(400).json({ error: "empty command" });
  bot.pendingCmd = cmd;
  console.log(`[admin]  cmd → bot=${req.params.id}: ${cmd}`);
  res.json({ ok: true });
});

router.delete("/api/bot/:id/results", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  bot.results = [];
  require("../persist").scheduleSave();
  res.json({ ok: true });
});

// ── Block / unblock a bot ─────────────────────────────────────────────────────

router.patch("/api/bot/:id/block", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  bot.blocked = !bot.blocked;
  if (bot.blocked) bot.pendingCmd = ""; // clear any queued command
  require("../persist").scheduleSave();
  console.log(`[admin]  bot=${req.params.id} blocked=${bot.blocked}`);
  res.json({ ok: true, blocked: bot.blocked });
});

// ── Delete a bot (removes from dashboard; data saved to disk) ────────────────

router.delete("/api/bot/:id", requireAdmin, (req, res) => {
  const id = req.params.id;
  if (!bots[id]) return res.status(404).json({ error: "not found" });
  delete bots[id];
  require("../persist").scheduleSave();
  console.log(`[admin]  bot=${id} deleted`);
  res.json({ ok: true });
});

router.delete("/api/bot/:id/events", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  bot.events = [];
  res.json({ ok: true });
});

router.delete("/api/bot/:id/incidents", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  bot.incidents  = [];
  bot.detections = [];
  res.json({ ok: true });
});

router.patch("/api/bot/:id/incident/:incId", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  const inc = bot.incidents.find(i => i.id === req.params.incId);
  if (!inc) return res.status(404).json({ error: "incident not found" });
  if (req.body.status) inc.status = req.body.status;
  res.json({ ok: true, incident: inc });
});

// ── IOC export ────────────────────────────────────────────────────────────────

router.get("/api/bot/:id/iocs", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  res.json(extractIOCs(bot));
});

router.get("/api/bot/:id/iocs.csv", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).send("not found");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="iocs_bot${req.params.id}.csv"`);
  res.send(iocsToCSV(extractIOCs(bot)));
});

router.get("/api/bot/:id/iocs.stix", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).send("not found");
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="iocs_bot${req.params.id}.stix.json"`);
  res.json(iocsToSTIX(bot, extractIOCs(bot)));
});

router.get("/api/bot/:id/report.md", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).send("not found");
  computeRiskScore(bot);
  res.setHeader("Content-Type", "text/markdown");
  res.setHeader("Content-Disposition", `attachment; filename="report_bot${req.params.id}.md"`);
  res.send(iocsToMarkdown(bot, extractIOCs(bot)));
});

router.get("/api/bot/:id/report.json", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  computeRiskScore(bot);

  const iocs = extractIOCs(bot);
  const now  = new Date();
  const firstMs    = bot.firstSeen ? new Date(bot.firstSeen).getTime() : now.getTime();
  const lastMs     = bot.lastSeen  ? new Date(bot.lastSeen).getTime()  : now.getTime();
  const durationSec = Math.round((lastMs - firstMs) / 1000);

  const regEvents  = bot.events.filter(e => e.cat === "registry").length;
  const procEvents = bot.events.filter(e => e.cat === "process").length;
  const techniques = [...new Set(bot.events.filter(e => e.tid).map(e => e.tid))];
  const highSev    = bot.incidents.filter(i => i.severity === "critical" || i.severity === "high").length;

  const PHASE_ORDER = ["Execution","Persistence","Discovery","Collection","C2","Exfiltration"];
  const observedTags = new Set(bot.detections.flatMap(d => d.tags));
  const tagToPhase   = { proc_suspicious:"Execution", discovery:"Discovery", file_drop:"Collection", persistence:"Persistence", network_c2:"C2", network:"C2" };
  const phasesPresent = new Set([...observedTags].map(t => tagToPhase[t]).filter(Boolean));
  const attackChain   = PHASE_ORDER.filter(p => phasesPresent.has(p));

  const MITRE_COVERAGE = [
    { technique:"T1547.001", name:"Registry Run Key Persistence",  detection:"DR_003/DR_004" },
    { technique:"T1543.003", name:"Malicious Service Creation",     detection:"DR_006"        },
    { technique:"T1204.002", name:"Malicious File Execution",       detection:"DR_001/DR_002" },
    { technique:"T1057",     name:"Process Discovery",              detection:"DR_009"        },
    { technique:"T1049",     name:"Network Connections Discovery",  detection:"DR_008"        },
    { technique:"T1571",     name:"Non-Standard Port C2",           detection:"DR_005"        },
    { technique:"T1105",     name:"Ingress Tool Transfer",          detection:"DR_007"        },
    { technique:"T1055",     name:"Process Injection",              detection:"Sigma rule"    },
    { technique:"T1113",     name:"Screen Capture",                 detection:"Sigma rule"    },
    { technique:"T1486",     name:"Data Encrypted for Impact",      detection:"Sigma rule"    },
  ];
  const defensiveCoverage = MITRE_COVERAGE.map(m => ({
    ...m, observed: techniques.includes(m.technique), detected: techniques.includes(m.technique),
  }));

  res.json({
    title:                 "B4DB4B3 Attack Simulation Report",
    generated:             now.toISOString(),
    host:                  bot.info ? bot.info.split("|")[0].trim() : bot.id,
    botId:                 bot.id,
    firstSeen:             bot.firstSeen || null,
    lastSeen:              bot.lastSeen  || null,
    durationSeconds:       durationSec,
    riskScore:             bot.riskScore,
    riskBreakdown:         bot.riskBreakdown,
    observedTechniques:    techniques.length,
    techniques,
    totalDetections:       bot.detections.length,
    totalIncidents:        bot.incidents.length,
    highSeverityIncidents: highSev,
    persistenceEvents:     regEvents,
    c2Protocol:            "Custom HTTPS",
    totalFiles:            bot.files.length,
    registryChanges:       regEvents,
    processEvents:         procEvents,
    totalNetworkRequests:  bot.netlog.length,
    beaconing:             bot.beaconStats || null,
    attackChain,
    defensiveCoverage,
    openIncidents:         bot.incidents.filter(i => i.status === "open"),
    iocs: {
      files:      [...iocs.files],
      ips:        [...iocs.ips],
      ports:      [...iocs.ports],
      registry:   [...iocs.registry],
      processes:  [...iocs.processes],
      services:   [...iocs.services],
      extensions: [...iocs.extensions],
    },
  });
});

// ── Task / Lab Console ────────────────────────────────────────────────────────

router.get("/api/simulation-actions", requireAdmin, (_req, res) => {
  res.json(SIMULATION_ACTIONS);
});

router.get("/api/bot/:id/tasks", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  res.json(bot.tasks);
});

router.post("/api/bot/:id/tasks", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });

  const sa = SIMULATION_ACTIONS.find(a => a.id === req.body.actionId);
  if (!sa) return res.status(400).json({ error: "unknown action id" });

  const task = {
    id:          `TASK_${Date.now()}`,
    botId:       req.params.id,
    actionId:    sa.id,
    action:      sa.name,
    phase:       sa.phase,
    tid:         sa.tid,
    rule:        sa.rule,
    requestedBy: "admin",
    timestamp:   new Date().toISOString(),
    approved:    false,
    executed:    false,
    result:      null,
    evidence:    null,
  };
  bot.tasks.unshift(task);
  if (bot.tasks.length > 200) bot.tasks.pop();
  console.log(`[task:created]  bot=${req.params.id}  action=${sa.name}`);
  res.status(201).json({ ok: true, task });
});

router.patch("/api/bot/:id/task/:taskId", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });
  const task = bot.tasks.find(t => t.id === req.params.taskId);
  if (!task) return res.status(404).json({ error: "task not found" });

  if (req.body.approved !== undefined) task.approved = Boolean(req.body.approved);
  if (req.body.result   !== undefined) task.result   = req.body.result;
  if (req.body.evidence !== undefined) task.evidence = req.body.evidence;

  if (req.body.execute && task.approved && !task.executed) {
    const sa = SIMULATION_ACTIONS.find(a => a.id === task.actionId);
    if (sa) {
      const simEv = {
        bot:      task.botId, cat: sa.phase.toLowerCase(), type: "simulation",
        sev:      "medium",   rule: sa.rule, ev: `[SIM] ${sa.name} — ${sa.desc}`,
        simulated: true,      tid: sa.tid,   tname: sa.name, received: new Date().toISOString(),
      };
      bot.events.push(simEv);
      if (bot.events.length > MAX_EVENTS) bot.events.splice(0, bot.events.length - MAX_EVENTS);
      runDetection(bot, simEv);
      computeRiskScore(bot);
      task.executed = true;
      task.result   = task.result || "Simulated — event injected into detection pipeline";
      task.evidence = `rule=${sa.rule}  tid=${sa.tid}`;
      console.log(`[task:executed] bot=${req.params.id}  action=${sa.name}`);
    }
  }
  res.json({ ok: true, task });
});

// ── Coverage ──────────────────────────────────────────────────────────────────

router.post("/api/coverage-run", (req, res) => {
  const { AUTH_KEY }   = require("../config/constants");
  const { adminAuthed } = require("../middleware/auth");
  if (req.query.auth !== AUTH_KEY && !adminAuthed(req)) return res.status(403).json({ error: "forbidden" });
  const run = req.body;
  if (!run || !run.runId) return res.status(400).json({ error: "bad payload" });
  coverageRuns.unshift(run);
  if (coverageRuns.length > 50) coverageRuns.pop();
  console.log(`[coverage] run=${run.runId}  coverage=${run.coveragePct}%  gaps=${run.gap}`);
  res.status(201).json({ ok: true });
});

router.get("/api/coverage-runs", requireAdmin, (_req, res) => {
  res.json(coverageRuns.map(r => ({
    runId: r.runId, timestamp: r.timestamp, botId: r.botId,
    total: r.total, pass: r.pass, partial: r.partial, gap: r.gap, coveragePct: r.coveragePct,
  })));
});

router.get("/api/coverage-run/:runId", requireAdmin, (req, res) => {
  const run = coverageRuns.find(r => r.runId === req.params.runId);
  if (!run) return res.status(404).json({ error: "not found" });
  res.json(run);
});

router.get("/api/bot/:id/coverage", requireAdmin, (req, res) => {
  const bot = bots[req.params.id];
  if (!bot) return res.status(404).json({ error: "not found" });

  const observedTids = new Set((bot.events     || []).filter(e => e.tid).map(e => e.tid));
  const detectedTids = new Set((bot.detections || []).filter(d => d.tid).map(d => d.tid));

  const techniques = KNOWN_TECHNIQUES.map(kt => {
    const observed = observedTids.has(kt.tid);
    const detected = detectedTids.has(kt.tid);
    const status   = detected ? "covered" : observed ? "gap" : "not_tested";
    return { ...kt, observed, detected, status };
  });

  const covered     = techniques.filter(t => t.status === "covered").length;
  const gapTechs    = techniques.filter(t => t.status === "gap");
  const notTested   = techniques.filter(t => t.status === "not_tested").length;
  const coveragePct = Math.round(covered / KNOWN_TECHNIQUES.length * 100);
  const latestRun   = coverageRuns.find(r => r.botId === req.params.id) || null;

  res.json({
    botId: req.params.id, computed: new Date().toISOString(),
    total: KNOWN_TECHNIQUES.length, covered, gaps: gapTechs.length, notTested, coveragePct,
    techniques, gapDetails: gapTechs, latestRun,
  });
});

// ── Uploads ───────────────────────────────────────────────────────────────────

router.get("/uploads/:filename", requireAdmin, (req, res) => {
  const file = path.join(UPLOADS_DIR, path.basename(req.params.filename));
  if (!fs.existsSync(file)) return res.status(404).send("not found");
  res.sendFile(file);
});

module.exports = router;
