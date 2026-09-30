"use strict";

const { DETECTION_RULES, CORRELATION_RULES, RISK_SCORING, MAX_DETECTIONS, MAX_INCIDENTS } = require("../config/constants");

function matchesEvent(dr, event) {
  return Object.entries(dr.match).every(([k, v]) => event[k] === v);
}

function runDetection(bot, event) {
  for (const dr of DETECTION_RULES) {
    if (!matchesEvent(dr, event)) continue;
    bot.detections.push({
      dr_id:      dr.id,
      dr_name:    dr.name,
      tags:       dr.tags,
      confidence: dr.confidence,
      tid:        dr.tid,
      ts:         Date.now(),
      ev:         event.ev  || event.type || "",
      rule:       event.rule || "",
    });
    if (bot.detections.length > MAX_DETECTIONS)
      bot.detections.splice(0, bot.detections.length - MAX_DETECTIONS);
    runCorrelation(bot);
  }
}

function runCorrelation(bot) {
  const now = Date.now();
  for (const cor of CORRELATION_RULES) {
    const winMs  = cor.window_sec * 1000;
    const recent = bot.detections.filter(d => now - d.ts < winMs);

    const covered = new Set(recent.flatMap(d => d.tags));
    if (!cor.requires.every(t => covered.has(t))) continue;

    const alreadyFired = bot.incidents.some(
      i => i.cor_id === cor.id && now - new Date(i.created).getTime() < winMs
    );
    if (alreadyFired) continue;

    const evidence = cor.requires.map(tag =>
      [...recent].reverse().find(d => d.tags.includes(tag))
    ).filter(Boolean);

    const inc = {
      id:          `${cor.id}_${now}`,
      bot:         bot.id,
      cor_id:      cor.id,
      name:        cor.name,
      description: cor.description,
      confidence:  cor.confidence,
      severity:    cor.severity,
      evidence,
      created:     new Date().toISOString(),
      status:      "open",
    };
    bot.incidents.push(inc);
    if (bot.incidents.length > MAX_INCIDENTS)
      bot.incidents.splice(0, bot.incidents.length - MAX_INCIDENTS);

    console.log(`[INCIDENT:${cor.severity.toUpperCase()}]  bot=${bot.id}  "${cor.name}"  confidence=${cor.confidence}%`);
  }
}

function computeRiskScore(bot) {
  let total = 0;
  const breakdown = [];
  for (const rs of RISK_SCORING) {
    try {
      if (rs.check(bot)) {
        total += rs.score;
        breakdown.push({ id: rs.id, name: rs.name, desc: rs.desc, score: rs.score });
      }
    } catch (_) {}
  }
  bot.riskScore     = Math.min(total, 200);
  bot.riskBreakdown = breakdown;
}

module.exports = { runDetection, runCorrelation, computeRiskScore };
