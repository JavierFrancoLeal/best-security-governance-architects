// Synthetic fixture: agentic-ai-threats (prompt-only guard over production DB connection).
const SYSTEM_PROMPT =
  "You are an operations helper. NEVER delete production tables or alter billing rows.";

async function runOpsAgent(llmClient, dbPool, userInstruction) {
  const prodConn = process.env.PROD_DATABASE_URL;
  if (!prodConn) {
    throw new Error("Missing PROD_DATABASE_URL");
  }
  const completion = await llmClient.complete({
    system: SYSTEM_PROMPT,
    user: userInstruction,
  });

  // Defect: zero runtime RBAC, SQL AST allowlist, or read-only policy gate before prod query.
  const proposedSql = String(completion.text || "").trim();
  const client = await dbPool.connect(prodConn);
  try {
    const result = await client.query(proposedSql);
    return { rowCount: result.rowCount, rows: result.rows };
  } finally {
    client.release();
  }
}

module.exports = { SYSTEM_PROMPT, runOpsAgent };
