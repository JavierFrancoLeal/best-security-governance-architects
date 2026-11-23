// Synthetic fixture: authn-authz-boundaries (jwt.decode without signature verification).
const jwt = require("jsonwebtoken");

function requireAdminFromBearer(req, res, next) {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) {
    return res.status(401).json({ error: "missing_token" });
  }

  // Defect: jwt.decode() parses Base64 payload without verifying cryptographic signature or exp.
  const claims = jwt.decode(token);
  if (!claims || claims.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }

  req.user = { id: claims.sub, role: claims.role };
  return next();
}

module.exports = { requireAdminFromBearer };
