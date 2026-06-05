const express = require("express");
const http = require("http");
const https = require("https");
const { URL } = require("url");

const router = express.Router();

// GET /api/net/fetch?url=...
router.get("/fetch", (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).json({ error: "url required" });

  // VULN: SSRF (CWE-918) — the server fetches any attacker-supplied URL with no
  // allowlist or private-range blocking, so it can reach internal services and
  // cloud metadata, e.g. `?url=http://169.254.169.254/latest/meta-data/`.
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return res.status(400).json({ error: "bad url" });
  }
  const client = parsed.protocol === "https:" ? https : http;
  client
    .get(raw, (upstream) => {
      let body = "";
      upstream.on("data", (c) => (body += c));
      upstream.on("end", () => res.json({ status: upstream.statusCode, body }));
    })
    .on("error", (e) => res.status(502).json({ error: e.message }));
});

// GET /api/net/webhook?callback=...
router.get("/webhook", (req, res) => {
  // VULN: blind SSRF (CWE-918) — fires a server-side request to any host,
  // usable for internal port scanning and reaching link-local addresses.
  const cb = req.query.callback;
  if (cb) http.get(cb, () => {}).on("error", () => {});
  res.json({ queued: true });
});

module.exports = router;
