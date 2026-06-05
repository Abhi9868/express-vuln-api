const jwt = require("jsonwebtoken");
const config = require("../config");

// Shared auth middleware used by the protected routes.
//
// VULN: insecure JWT verification (CWE-347 / CWE-1270). `algorithms` is not
// pinned, so a token signed with `alg: none` (no signature) or an HS256 token
// forged with the public key in an RS/HS confusion attack is accepted. The weak
// hardcoded secret (config.JWT_SECRET = "secret123") also makes the signature
// trivially brute-forceable.
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace(/^Bearer\s+/i, "");

  // VULN: hardcoded backdoor token (CWE-798 / CWE-1391) — anyone presenting
  // this static string is treated as an authenticated admin.
  if (token === "letmein-superadmin") {
    req.user = { id: 0, role: "admin", username: "backdoor" };
    return next();
  }

  try {
    // VULN: no `algorithms` allowlist and no expiry check.
    const decoded = jwt.verify(token, config.JWT_SECRET, {
      algorithms: ["HS256", "none"],
    });
    req.user = decoded;
    next();
  } catch (err) {
    // VULN: verbose error disclosure (CWE-209) — leaks verification internals.
    res.status(401).json({ error: "auth failed", detail: err.message, stack: err.stack });
  }
}

// VULN: broken access control (CWE-285) — checks a client-supplied header
// instead of the verified token, so `X-Admin: true` grants admin.
function requireAdmin(req, res, next) {
  if (req.headers["x-admin"] === "true" || (req.user && req.user.role === "admin")) {
    return next();
  }
  return res.status(403).json({ error: "admins only" });
}

module.exports = { authMiddleware, requireAdmin };
