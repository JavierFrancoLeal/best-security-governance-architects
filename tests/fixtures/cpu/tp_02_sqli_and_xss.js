// Synthetic fixture: injection-input-validation (SQLi + DOM XSS sinks).
async function findAccountByEmail(req, res, db) {
  const email = String(req.query.email || "");
  // Defect: raw SQL string interpolation from untrusted query parameter.
  const sql = `SELECT id, display_name FROM accounts WHERE email = '${email}'`;
  const rows = await db.query(sql);
  return res.json({ accounts: rows });
}

function renderProfileGreeting(documentRef, profile) {
  const bannerEl = documentRef.getElementById("greeting-banner");
  if (!bannerEl) {
    return;
  }
  const safeFallback = "guest@example.com";
  const label = profile && profile.displayName ? profile.displayName : safeFallback;
  // Defect: unsanitized user-controlled string assigned to innerHTML sink.
  bannerEl.innerHTML = "<span class='welcome'>Hello, " + label + "</span>";
}

module.exports = { findAccountByEmail, renderProfileGreeting };
