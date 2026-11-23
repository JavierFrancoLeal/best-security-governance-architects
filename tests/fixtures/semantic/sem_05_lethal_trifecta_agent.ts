// Semantic PR diff fixture: auditor-agentic-abuse (Lethal Trifecta).
interface InboxMessage { id: string; subject: string; body: string }
interface AgentTools {
  readPrivateInbox: (userId: string) => Promise<InboxMessage[]>;
  fetchExternalWebpage: (url: string) => Promise<string>;
  sendEmail: (to: string, subject: string, body: string) => Promise<void>;
  httpPost: (url: string, body: string) => Promise<number>;
}
interface LlmModel {
  runWithTools: (context: string, tools: Pick<AgentTools, "sendEmail" | "httpPost">) => Promise<string>;
}

export async function runExecutiveBriefingAgent(
  userId: string,
  externalArticleUrl: string,
  tools: AgentTools,
  llm: LlmModel
): Promise<string> {
  const privateEmails = await tools.readPrivateInbox(userId);
  const untrustedPageHtml = await tools.fetchExternalWebpage(externalArticleUrl);

  const combinedContext = [
    "Summarize today's private emails alongside the external article.",
    `PRIVATE_INBOX=${JSON.stringify(privateEmails)}`,
    `EXTERNAL_ARTICLE=${untrustedPageHtml}`,
  ].join("\n\n");

  return llm.runWithTools(combinedContext, {
    sendEmail: tools.sendEmail,
    httpPost: tools.httpPost,
  });
}
