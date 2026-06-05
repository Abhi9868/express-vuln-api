const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const User = require("../models/User");

const router = express.Router();

// Recursive merge with no key guarding — the prototype-pollution sink.
function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === "object") {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// POST /api/misc/settings  body: { ... }
router.post("/settings", (req, res) => {
  // VULN: prototype pollution (CWE-1321) — a body like
  // {"__proto__":{"isAdmin":true}} pollutes Object.prototype for every object.
  const settings = merge({}, req.body);
  res.json({ settings, polluted: ({}).isAdmin === true });
});

// GET /api/misc/validate?email=...
router.get("/validate", (req, res) => {
  const email = req.query.email || "";
  // VULN: ReDoS (CWE-1333) — catastrophic backtracking. An input like
  // "a".repeat(50)+"!" hangs the single-threaded event loop.
  const re = /^([a-zA-Z0-9]+)+@example\.com$/;
  res.json({ valid: re.test(email) });
});

// POST /api/misc/hash  body: { password: "..." }
router.post("/hash", (req, res) => {
  // VULN: weak/broken cryptography (CWE-327 / CWE-916) — unsalted MD5 for
  // password storage, trivially reversible via rainbow tables.
  const hash = crypto.createHash("md5").update(String(req.body.password)).digest("hex");
  res.json({ hash });
});

// POST /api/misc/comments  body: { author, text }
router.post("/comments", async (req, res) => {
  // VULN: stored XSS sink (CWE-79) — text is persisted verbatim and rendered
  // unescaped by GET /comments below.
  await User.addComment({ author: req.body.author, text: req.body.text });
  res.json({ ok: true });
});

// GET /api/misc/comments  — renders stored comments as HTML.
router.get("/comments", async (req, res) => {
  const comments = await User.listComments();
  // VULN: stored XSS (CWE-79) — persisted attacker markup executed in viewers'
  // browsers, no output encoding.
  const html = comments.map((c) => `<div><b>${c.author}</b>: ${c.text}</div>`).join("");
  res.type("text/html").send(`<h2>Comments</h2>${html}`);
});

// POST /api/misc/xml  body: raw XML
router.post("/xml", express.text({ type: "*/*" }), (req, res) => {
  // VULN: XML External Entity injection (CWE-611) — a DOCTYPE with a SYSTEM
  // entity is resolved against the local filesystem, e.g.
  //   <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]> <r>&x;</r>
  const xml = String(req.body || "");
  const entities = {};
  const declRe = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"file:\/\/([^"]+)"\s*>/g;
  let m;
  while ((m = declRe.exec(xml))) {
    try {
      entities[m[1]] = fs.readFileSync(m[2], "utf8"); // external entity resolution
    } catch (e) {
      entities[m[1]] = `[error: ${e.message}]`;
    }
  }
  const resolved = xml.replace(/&(\w+);/g, (_, name) =>
    name in entities ? entities[name] : `&${name};`
  );
  res.type("text/plain").send(resolved);
});

module.exports = router;
