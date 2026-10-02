const express = require("express");
const cors = require("cors");
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");
const execRoutes = require("./routes/exec");
const fileRoutes = require("./routes/files");
const netRoutes = require("./routes/network");
const adminRoutes = require("./routes/admin");
const miscRoutes = require("./routes/misc");

const app = express();
app.use(express.json());
// VULN: permissive CORS (CWE-942) and no helmet → missing security headers.
app.use(cors({ origin: "*" }));
// VULN: reflects the caller's Origin and allows credentials (CWE-942) — any
// site can make authenticated cross-origin requests.
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Credentials", "true");
  // VULN: server version disclosure (CWE-200).
  res.header("X-Powered-By", "Express/4.19.2 vuln-express/1.0.0");
  next();
});

app.get("/", (req, res) => {
  res.json({ service: "vuln-express api is running", status: "ok" });
});

// Mount prefixes — route extractor must combine these with sub-router paths.
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/exec", execRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/net", netRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/misc", miscRoutes);

app.get("/api/health", (req, res) => res.json({ ok: true }));

// VULN: global error handler leaks stack traces to clients (CWE-209).
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = process.env.PORT || 5002;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`vuln-express listening on http://localhost:${PORT}`);
});
