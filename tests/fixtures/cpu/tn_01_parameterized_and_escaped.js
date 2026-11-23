// Hard negative: parameterized SQL, textContent, CSPRNG, and OWASP-baseline scryptSync.
const crypto = require("crypto");

async function findAccountSafe(req, res, db) {
  const email = String(req.query.email || "").trim().toLowerCase();
  const rows = await db.query(
    "SELECT id, display_name FROM accounts WHERE email = $1",
    [email]
  );
  return res.json({ accounts: rows });
}

function renderProfileGreetingSafe(documentRef, profile) {
  const bannerEl = documentRef.getElementById("greeting-banner");
  if (!bannerEl) {
    return;
  }
  const displayName = String(profile?.displayName || "Guest");
  bannerEl.textContent = `Hello, ${displayName}`;
}

function createOpaqueSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPasswordScrypt(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64, {
    N: 131072,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });
  return `scrypt$131072$8$1$${salt.toString("hex")}$${derived.toString("hex")}`;
}

module.exports = { findAccountSafe, renderProfileGreetingSafe, createOpaqueSessionToken, hashPasswordScrypt };
