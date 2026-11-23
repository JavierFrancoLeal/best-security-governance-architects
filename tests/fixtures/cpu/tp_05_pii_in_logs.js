// Synthetic fixture: data-isolation-pii (credentials and PII written to stdout logs).
async function handlePasswordLogin(req, res, authService) {
  const authHeader = String(req.headers.authorization || "");
  const email = String(req.body.email || "");
  const password = String(req.body.password || "");
  const taxId = String(req.body.taxId || "");

  // Defect 1 (BLOCKER): logs raw Authorization header and plaintext password.
  console.log("Auth credential debug:", { authorization: authHeader, password: password });

  // Defect 2 (MAJOR): logs unredacted user email and government tax identifier (PII).
  console.log("Customer identity trace:", { email: email, taxId: taxId });

  const verified = await authService.verify(email, password);
  if (!verified) {
    return res.status(401).json({ error: "invalid_credentials" });
  }
  return res.status(200).json({ status: "authenticated" });
}

module.exports = { handlePasswordLogin };
