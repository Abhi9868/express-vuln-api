const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const config = require("../config");

const router = express.Router();

// POST /api/auth/login
router.post("/login", async (req, res) => {
  // VULN: NoSQL injection (CWE-943). The query object is built directly from
  // untrusted req.body, so {"password": {"$ne": null}} bypasses the password
  // check and logs in as the first matching user.
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  // VULN: weak hardcoded secret, no expiry (CWE-798 / CWE-347).
  const token = jwt.sign({ id: user._id, role: user.role }, config.JWT_SECRET);
  res.json({ token, user: { id: user._id, username: user.username, role: user.role } });
});

module.exports = router;
