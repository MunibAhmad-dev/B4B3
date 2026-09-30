"use strict";

const { MAX_NETLOG } = require("../config/constants");
const { bots }       = require("../state");
const { computeRiskScore } = require("./detectionEngine");

function getOrCreate(id) {
  if (!bots[id]) {
    bots[id] = {
      id,
      info:          "(no info yet)",
      firstSeen:     new Date().toISOString(),
      lastSeen:      new Date().toISOString(),
      pendingCmd:    "",
      results:       [],
      files:         [],
      events:        [],
      detections:    [],
      incidents:     [],
      netlog:        [],
      beaconStats:   null,
      riskScore:     0,
      riskBreakdown: [],
      tasks:         [],
    };
  }
  return bots[id];
}

function recordNetlog(bot, req, _res, bodyBytes) {
  const entry = {
    ts:       Date.now(),
    tsIso:    new Date().toISOString(),
    srcIp:    req.ip || req.socket?.remoteAddress || "unknown",
    method:   req.method,
    path:     req.path,
    query:    req.query,
    ua:       req.headers["user-agent"] || "",
    reqBytes: parseInt(req.headers["content-length"] || "0", 10) + (req.path.length + req.url.length),
    resBytes: bodyBytes || 0,
    port:     req.socket?.remotePort || 0,
    protocol: req.protocol || "https",
  };
  bot.netlog.push(entry);
  if (bot.netlog.length > MAX_NETLOG)
    bot.netlog.splice(0, bot.netlog.length - MAX_NETLOG);
  analyzeBeaconing(bot);
}

function analyzeBeaconing(bot) {
  const polls = bot.netlog.filter(e => e.path === "/cmd").map(e => e.ts);
  if (polls.length < 4) { bot.beaconStats = null; return; }

  const intervals = [];
  for (let i = 1; i < polls.length; i++) intervals.push(polls[i] - polls[i-1]);

  const mean     = intervals.reduce((s, v) => s + v, 0) / intervals.length;
  const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length;
  const stdev    = Math.sqrt(variance);
  const cv       = mean > 0 ? stdev / mean : 1;

  const regularity = cv < 0.05 ? "machine-regular" : cv < 0.15 ? "regular" : cv < 0.40 ? "semi-regular" : "irregular";

  bot.beaconStats = {
    pollCount:  polls.length,
    intervalMs: Math.round(mean),
    stdevMs:    Math.round(stdev),
    cv:         Math.round(cv * 1000) / 1000,
    regularity,
    flagged:    cv < 0.15,
    updated:    new Date().toISOString(),
  };
  computeRiskScore(bot);
}

module.exports = { getOrCreate, recordNetlog, analyzeBeaconing };
