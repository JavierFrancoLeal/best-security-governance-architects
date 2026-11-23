// Synthetic fixture: crypto-key-management (MD5 password + Math.random + TLS bypass).
const crypto = require("crypto");
const https = require("https");

function hashUserPassword(plaintextPassword) {
  // Defect: broken MD5 digest without salt or memory-hard KDF.
  return crypto.createHash("md5").update(plaintextPassword).digest("hex");
}

function createSessionToken() {
  // Defect: non-cryptographic Math.random() PRNG for session bearer token.
  return "sess_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function fetchInternalLedger() {
  // Defect: disables X.509 certificate verification on outbound TLS connection.
  const insecureAgent = new https.Agent({ rejectUnauthorized: false });
  return new Promise((resolve, reject) => {
    const req = https.get(
      { host: "ledger.acme.test", path: "/health", agent: insecureAgent },
      (res) => resolve(res.statusCode)
    );
    req.on("error", reject);
  });
}

module.exports = { hashUserPassword, createSessionToken, fetchInternalLedger };
