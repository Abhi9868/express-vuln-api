const express = require("express");
const User = require("../models/User");

const router = express.Router();

// GET /api/users/search?q=...
router.get("/search", async (req, res) => {
  const q = req.query.q || "";
  // VULN: reflected XSS (CWE-79) — user input echoed into HTML unescaped.
  res.send(`<h1>Results for ${q}</h1>`);
});

// GET /api/users/:id
router.get("/:id", async (req, res) => {
  // VULN: IDOR (CWE-639) — any user record returned, no authorization check.
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ error: "not found" });
  res.json(user);
});

// GET /api/users/go/redirect?url=...
router.get("/go/redirect", (req, res) => {
  // VULN: open redirect (CWE-601) — no allowlist on the destination.
  res.redirect(req.query.url || "/");
});

module.exports = router;
