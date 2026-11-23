// Semantic hard negative: auditor-agentic-abuse (Dual-LLM quarantine + deterministic approval).
import crypto from "crypto";

interface QuarantinedSummary { topic: string; citationCount: number }
interface ExternalSendRequest { recipient: string; subject: string; body: string; approvalTokenHex: string }

const ALLOWED_RECIPIENTS = new Set(["digest@acme.test", "ops-review@example.com"]);

function verifyHumanApproval(secret: Buffer, req: ExternalSendRequest): boolean {
  const digest = crypto.createHash("sha256").update(`${req.recipient}|${req.subject}|${req.body}`).digest("hex");
  const expected = crypto.createHmac("sha256", secret).update(digest).digest();
  const provided = Buffer.from(req.approvalTokenHex, "hex");
  return expected.length === provided.length && crypto.timingSafeEqual(expected, provided);
}

export async function runIsolatedBriefingWorkflow(
  externalUrl: string,
  quarantinedReader: (untrustedHtml: string) => Promise<QuarantinedSummary>,
  fetchPublicPage: (url: string) => Promise<string>,
  sendEmail: (to: string, subject: string, body: string) => Promise<void>,
  approvalSecret: Buffer,
  pendingSend?: ExternalSendRequest
): Promise<{ summary: QuarantinedSummary; dispatched: boolean }> {
  const rawHtml = await fetchPublicPage(externalUrl);
  const summary = await quarantinedReader(rawHtml);
  if (typeof summary.topic !== "string" || !Number.isInteger(summary.citationCount)) {
    throw new Error("Quarantined reader output violated strict schema");
  }

  if (!pendingSend) {
    return { summary, dispatched: false };
  }
  if (!ALLOWED_RECIPIENTS.has(pendingSend.recipient) || !verifyHumanApproval(approvalSecret, pendingSend)) {
    throw new Error("External dispatch blocked: allowlist or deterministic human approval failed");
  }
  await sendEmail(pendingSend.recipient, pendingSend.subject, pendingSend.body);
  return { summary, dispatched: true };
}
