// Semantic hard negative: auditor-authz-intent (tenant+owner isolation + CSRF + audit trail).
const crypto = require("crypto");

const TRUSTED_ORIGIN = "https://app.acme.test";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function verifyCsrfAndOrigin(req) {
  if (req.headers.origin !== TRUSTED_ORIGIN) {
    return false;
  }
  const provided = Buffer.from(String(req.headers["x-csrf-token"] || ""), "utf8");
  const expected = Buffer.from(String(req.session?.csrfToken || ""), "utf8");
  return expected.length >= 32 && provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}

function registerSafeInvoiceVoidRoute(router, requireAuth, db, auditSink) {
  router.post("/api/invoices/:id/void", requireAuth, async (req, res) => {
    if (!verifyCsrfAndOrigin(req)) {
      return res.status(403).json({ error: "csrf_validation_failed" });
    }
    const invoiceId = String(req.params.id || "");
    if (!UUID_RE.test(invoiceId)) {
      return res.status(400).json({ error: "invalid_invoice_id" });
    }
    const { rows } = await db.query(
      "UPDATE invoices SET status = 'void' WHERE id = $1 AND tenant_id = $2 AND owner_id = $3 RETURNING id, status",
      [invoiceId, req.user.tenantId, req.user.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "invoice_not_found" });
    }
    await auditSink.append({ action: "invoice.void", actorId: req.user.id, tenantId: req.user.tenantId, resourceId: invoiceId });
    return res.status(200).json({ invoice: rows[0] });
  });
}

module.exports = { registerSafeInvoiceVoidRoute };
