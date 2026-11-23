// Hard negative: __Host- cookie, exact CORS origin, verified RS256 JWT, and ownership check.
const jwt = require("jsonwebtoken");

const ALLOWED_ORIGINS = new Set(["https://app.acme.test"]);

function applyStrictCors(req, res, next) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
  next();
}

function issueHardenedCookie(res, opaqueSessionId) {
  res.cookie("__Host-sid", opaqueSessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 3600 * 1000,
  });
}

async function getOwnedProfile(req, res, db, publicKeyPem) {
  const token = String(req.headers.authorization || "").replace(/^Bearer\s+/, "");
  const claims = jwt.verify(token, publicKeyPem, {
    algorithms: ["RS256"],
    issuer: "https://auth.acme.test",
    audience: "profile-api",
  });
  req.user = { id: claims.sub };
  const record = await db.findProfileById(req.params.profileId);
  if (!record || record.ownerId !== req.user.id) {
    return res.status(403).json({ error: "forbidden" });
  }
  return res.status(200).json({ id: record.id, displayName: record.displayName });
}

module.exports = { applyStrictCors, issueHardenedCookie, getOwnedProfile };
