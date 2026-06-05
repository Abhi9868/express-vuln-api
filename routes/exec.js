const express = require("express");
const { exec } = require("child_process");
const vm = require("vm");

const router = express.Router();

// GET /api/exec/ping?host=...
router.get("/ping", (req, res) => {
  const host = req.query.host || "127.0.0.1";
  // VULN: OS command injection (CWE-78) — untrusted input is concatenated into
  // a shell string, so `?host=127.0.0.1; cat /etc/passwd` runs arbitrary cmds.
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    res.type("text/plain").send(stdout + stderr + (err ? String(err) : ""));
  });
});

// GET /api/exec/dns?domain=...
router.get("/dns", (req, res) => {
  const domain = req.query.domain || "example.com";
  // VULN: OS command injection via backticks/`$()` (CWE-78).
  exec("nslookup " + domain, (err, stdout, stderr) => {
    res.type("text/plain").send(stdout + stderr);
  });
});

// POST /api/exec/eval   body: { expr: "..." }
router.post("/eval", (req, res) => {
  // VULN: code injection (CWE-94) — server-side eval of attacker input gives RCE
  // (e.g. expr = "require('child_process').execSync('id').toString()").
  try {
    const result = vm.runInNewContext(String(req.body.expr), { require, process });
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// POST /api/exec/render   body: { template: "Hello ${name}", name: "..." }
router.post("/render", (req, res) => {
  // VULN: server-side template injection (CWE-1336 / CWE-94) — the template is
  // compiled with the Function constructor, so `${process.mainModule}` and
  // arbitrary expressions execute on the server.
  const tpl = String(req.body.template || "");
  const fn = new Function("ctx", "with (ctx) { return `" + tpl + "`; }");
  try {
    res.send(fn(req.body));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// POST /api/exec/deserialize   body: raw serialized object
router.post("/deserialize", express.text({ type: "*/*" }), (req, res) => {
  // VULN: insecure deserialization (CWE-502) — the payload may embed an
  // immediately-invoked function expression that runs on parse, e.g.
  // {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('touch /tmp/pwned')}()"}
  try {
    const revived = eval("(" + req.body + ")"); // intentionally unsafe
    res.json({ ok: true, type: typeof revived });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

module.exports = router;
