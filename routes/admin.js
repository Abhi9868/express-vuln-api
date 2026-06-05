const express = require("express");
const User = require("../models/User");
const { authMiddleware, requireAdmin } = require("../middleware/auth");
const config = require("../config");

const router = express.Router();

// GET /api/admin/users  — intended to be admin-only.
router.get("/users", authMiddleware, requireAdmin, async (req, res) => {
  // VULN: sensitive data exposure (CWE-200) — returns password hashes/plaintext
  // and emails for every user.
  const users = await User.find({});
  res.json(users);
});

// GET /api/admin/config — debug endpoint left enabled.
router.get("/config", (req, res) => {
  // VULN: secrets disclosure (CWE-200 / CWE-215) — dumps the whole config
  // including JWT secret and AWS credentials, with NO authentication at all
  // (CWE-862 missing authorization).
  res.json({ config, env: process.env });
});

// POST /api/users/:id/profile  body: arbitrary fields
router.post("/users/:id/profile", authMiddleware, async (req, res) => {
  // VULN: mass assignment / privilege escalation (CWE-915) — req.body is merged
  // wholesale, so `{"role":"admin"}` lets a normal user grant themselves admin.
  // Also IDOR (CWE-639): no check that req.user owns :id.
  const updated = await User.updateById(req.params.id, req.body);
  if (!updated) return res.status(404).json({ error: "not found" });
  res.json(updated);
});

// GET /api/admin/debug?n=... — triggers an error to show the handler.
router.get("/debug", (req, res) => {
  try {
    // Force a runtime error from user input.
    JSON.parse(req.query.n);
    res.json({ ok: true });
  } catch (e) {
    // VULN: stack trace / debug info disclosure (CWE-209) — full stack and
    // server internals returned to the client.
    res.status(500).json({ error: e.message, stack: e.stack, cwd: process.cwd() });
  }
});

module.exports = router;
