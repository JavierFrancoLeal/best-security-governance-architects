// Synthetic fixture: authn-authz-boundaries (insecure cookie + wildcard credentialed CORS).
function applyInsecureCors(req, res, next) {
  // Defect (BLOCKER): wildcard ACAO paired with Access-Control-Allow-Credentials: true.
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE");
  next();
}

function issueSessionCookie(res, sessionToken) {
  // Defect (MAJOR): session cookie omits HttpOnly, Secure, and SameSite protections.
  res.cookie("acme_sid", sessionToken, {
    httpOnly: false,
    secure: false,
    path: "/",
  });
  return res.status(200).json({ ok: true });
}

module.exports = { applyInsecureCors, issueSessionCookie };
