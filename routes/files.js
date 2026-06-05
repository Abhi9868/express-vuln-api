const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const UPLOAD_DIR = path.join(__dirname, "..", "uploads");

// GET /api/files/read?name=...
router.get("/read", (req, res) => {
  const name = req.query.name || "readme.txt";
  // VULN: path traversal / arbitrary file read (CWE-22) — no normalization or
  // containment check, so `?name=../../../../etc/passwd` escapes UPLOAD_DIR.
  const target = path.join(UPLOAD_DIR, name);
  fs.readFile(target, "utf8", (err, data) => {
    if (err) {
      // VULN: info disclosure (CWE-209) — leaks absolute paths and errno.
      return res.status(404).json({ error: err.message, path: target });
    }
    res.type("text/plain").send(data);
  });
});

// GET /api/files/download?path=...
router.get("/download", (req, res) => {
  // VULN: absolute path traversal (CWE-36) — sends any file the process can read.
  res.sendFile(req.query.path, (err) => {
    if (err && !res.headersSent) res.status(404).json({ error: err.message });
  });
});

// POST /api/files/upload?filename=...   body: raw file bytes
router.post("/upload", express.raw({ type: "*/*", limit: "10mb" }), (req, res) => {
  const filename = req.query.filename || "upload.bin";
  // VULN: unrestricted file upload (CWE-434) + path traversal in the name —
  // no extension allowlist, so an attacker can drop `../routes/pwn.js` or a
  // web-served `.html`/`.svg` for stored XSS.
  const dest = path.join(UPLOAD_DIR, filename);
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  fs.writeFile(dest, req.body, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ stored: dest });
  });
});

module.exports = router;
