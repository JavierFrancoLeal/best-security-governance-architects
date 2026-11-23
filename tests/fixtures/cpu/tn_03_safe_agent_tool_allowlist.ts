// Hard negative: allowlisted agent tool runner with read-only default and HMAC approval.
import crypto from "crypto";

type AllowedTool = "read_ticket" | "create_draft";
interface ToolRequest { tool: AllowedTool; ticketId: string; draftBody?: string; approvalToken?: string }

const ALLOWED_TOOLS: ReadonlySet<AllowedTool> = new Set(["read_ticket", "create_draft"]);

function verifyApprovalToken(secret: Buffer, payload: string, tokenHex: string): boolean {
  const expected = crypto.createHmac("sha256", secret).update(payload).digest();
  const provided = Buffer.from(tokenHex, "hex");
  return expected.length === provided.length && crypto.timingSafeEqual(expected, provided);
}

export async function dispatchAgentTool(
  req: ToolRequest,
  env: Record<string, string | undefined>,
  approvalSecret: Buffer,
  sandboxStore: { readTicket: (id: string) => Promise<string>; saveDraft: (id: string, body: string) => Promise<void> }
): Promise<{ status: string; data?: string }> {
  if (!ALLOWED_TOOLS.has(req.tool) || !/^[A-Z]+-\d{1,6}$/.test(req.ticketId)) {
    throw new Error("Rejected by deterministic tool/schema allowlist");
  }
  if (!env.SANDBOX_DATABASE_URL || env.PROD_DATABASE_URL) {
    throw new Error("Agent runner restricted to isolated non-production environment");
  }
  if (req.tool === "read_ticket") {
    return { status: "ok", data: await sandboxStore.readTicket(req.ticketId) };
  }
  const body = String(req.draftBody || "").slice(0, 2000);
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  const canonicalPayload = `${req.tool}:${req.ticketId}:${digest}`;
  if (!req.approvalToken || !verifyApprovalToken(approvalSecret, canonicalPayload, req.approvalToken)) {
    throw new Error("Write blocked: valid deterministic human-approval token required");
  }
  await sandboxStore.saveDraft(req.ticketId, body);
  return { status: "draft_saved" };
}
