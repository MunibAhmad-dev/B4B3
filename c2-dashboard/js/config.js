// ── C2 Backend URL ────────────────────────────────────────────────────────────
//
// Option A — Same origin (recommended):
//   Leave API_BASE as "" and open the dashboard from the backend itself:
//   http://localhost:4444/login.html
//
// Option B — Go Live / Live Server (different port):
//   Set API_BASE to the backend URL below, then start backend with:
//   CORS_ORIGIN=http://127.0.0.1:5500 node server.js   (Windows: set CORS_ORIGIN=... && node server.js)
//
// Option C — VPS deployment (frontend on separate domain):
//   Set API_BASE to your VPS address, start backend with CORS_ORIGIN=<your-frontend-domain>
//
const API_BASE = window.C2_API_BASE || "";
