"use strict";

// Shared in-memory state — imported by all routes and controllers
const bots = {};
const coverageRuns = [];
const MAX_COVERAGE_RUNS = 50;

module.exports = { bots, coverageRuns, MAX_COVERAGE_RUNS };
