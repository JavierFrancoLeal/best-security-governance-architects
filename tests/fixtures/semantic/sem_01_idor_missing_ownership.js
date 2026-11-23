// Semantic PR diff fixture: auditor-authz-intent (BOLA / cross-tenant IDOR, SAST-evasive).
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function registerInvoiceRoutes(router, requireAuth, db) {
  router.get("/api/invoices/:id", requireAuth, async (req, res) => {
    const invoiceId = String(req.params.id || "");
    if (!UUID_RE.test(invoiceId)) {
      return res.status(400).json({ error: "invalid_invoice_id" });
    }

    const { rows } = await db.query(
      "SELECT id, amount_cents, currency, status, pdf_url FROM invoices WHERE id = $1",
      [invoiceId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "invoice_not_found" });
    }
    return res.status(200).json({ invoice: rows[0] });
  });
}

module.exports = { registerInvoiceRoutes };
