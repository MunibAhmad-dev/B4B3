"use strict";

const fs   = require("fs");
const path = require("path");

const DATA_DIR  = path.join(__dirname, "data");
const BOTS_FILE = path.join(DATA_DIR, "bots.json");

let _bots = null;
let _timer = null;

function init(botsRef) {
  _bots = botsRef;
}

// Debounced write — coalesces rapid saves into one write every 3s
function scheduleSave() {
  if (_timer) return;
  _timer = setTimeout(() => { _timer = null; flush(); }, 3000);
}

function flush() {
  if (!_bots) return;
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(BOTS_FILE, JSON.stringify(_bots, null, 2));
  } catch (e) {
    console.error("[persist] save failed:", e.message);
  }
}

function load() {
  try {
    if (!fs.existsSync(BOTS_FILE)) return;
    const data = JSON.parse(fs.readFileSync(BOTS_FILE, "utf8"));
    Object.assign(_bots, data);
    console.log(`[persist] loaded ${Object.keys(data).length} bots from disk`);
  } catch (e) {
    console.error("[persist] load failed:", e.message);
  }
}

module.exports = { init, scheduleSave, flush, load };
