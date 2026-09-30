"use strict";

const { AUTH_KEY } = require("../config/constants");

function botAuthed(req)   { return req.query.auth === AUTH_KEY; }
function adminAuthed(req) { return !!(req.session && req.session.admin); }

function requireAdmin(req, res, next) {
  if (adminAuthed(req)) return next();
  res.status(401).json({ error: "Not authenticated" });
}

module.exports = { botAuthed, adminAuthed, requireAdmin };
