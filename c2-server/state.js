"use strict";

// Shared in-memory state — imported by all routes and controllers
const bots = {};
const coverageRuns = [];
const MAX_COVERAGE_RUNS = 50;

// Stage 2 fetch tracking — each entry: { ts, ip, ua }
const stage2Fetches = [];
const MAX_STAGE2_FETCHES = 200;

module.exports = { bots, coverageRuns, MAX_COVERAGE_RUNS, stage2Fetches, MAX_STAGE2_FETCHES };
