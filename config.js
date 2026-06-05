// App configuration.
// VULN: hardcoded JWT signing secret committed to source (CWE-798).
module.exports = {
  JWT_SECRET: "secret123",
  // VULN: cloud credentials hardcoded in source (CWE-798).
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  MONGO_URI: "mongodb://admin:supersecret@localhost:27017/chat",
};
