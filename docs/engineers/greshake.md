---
slug: "greshake"
tier: "PROVISIONAL_FRONTIER"
primary_axis: "G"
axis_label: "Indirect Prompt Injection Threat Model & Trust-Tier Context Segregation"
polymath_facet: false
verified_sources: ["SRC-GRESHAKE-2023", "SRC-OWASP-LLM-2025", "SRC-HARDY-1988"]
bound_auditor_rules: ["agentic-01", "agentic-04"]
---

# Authority Dossier: `greshake` (Offline Reference)

**Axiomatic Failure Model:** Because language models evaluate operator instructions and retrieved external content within the same token-inference pathway, any untrusted data channel (RAG documents, web pages, emails, code comments, tool outputs) becomes an indirect instruction-injection vector that bypasses direct user-input filters.

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `greshake-inv-01` | Untrusted external content (RAG chunks, web pages, emails, public issues, third-party tool results) enters the prompt context of an LLM holding privileged tool-calling or write capabilities without structural trust-tier isolation. | Prompt string interpolation and SDK message arrays look identical for trusted vs. untrusted sources; SAST lacks data-provenance trust tiers. | `BLOCKER` | `SRC-GRESHAKE-2023` |
| `greshake-inv-02` | Unvalidated LLM output flows directly into active execution, query, filesystem-path, package-install, or rendering sinks (shell, SQL, HTML/Markdown image URLs) without deterministic schema/allowlist sanitization (OWASP LLM05:2025). | LLM SDK completions are not built-in HTTP taint sources in generic SAST packs, and Markdown-image exfiltration is semantic rendering behavior. | `BLOCKER` | `SRC-GRESHAKE-2023` |
| `greshake-inv-03` | RAG pipelines share an unsegregated read/write index path enabling untrusted content or agent completions to poison persistent memory/vector stores consumed by future privileged sessions (LLM01/LLM04:2025). | Vector-store write-path provenance and cross-session poisoning span storage schemas and agent orchestration logic. | `BLOCKER` | `SRC-GRESHAKE-2023` |
| `greshake-inv-04` | Prompt-injection defenses scan only direct user chat inputs while leaving indirect retrieval channels (fetched documents, emails, tool outputs, multimodal payloads) untagged and unscanned. | Presence of an input filter on user endpoints masks missing indirect-channel controls; detection requires tracing retrieval data flows. | `MAJOR` | `SRC-GRESHAKE-2023` |
| `greshake-inv-05` | Multi-agent pipelines pass outputs from an agent exposed to untrusted external content directly as trusted directives to a privileged peer agent ("prompt infection" cascade). | Inter-agent message passing resembles benign internal RPC calls to static analyzers. | `BLOCKER` | `SRC-GRESHAKE-2023` |
| `greshake-inv-06` | Rendering surfaces (Markdown images, outbound links, email previews) allow LLM-generated URLs or query parameters to exfiltrate private context passively without user interaction. | Markdown rendering and dynamic URL templates are rarely modeled as credential-exfiltration sinks by SAST. | `BLOCKER` | `SRC-GRESHAKE-2023` |

## Scope & Handoff

Triggers on LLM prompt builders, RAG retrieval/indexing pipelines, multi-agent routers, and LLM output renderers. Escalate missing adversarial injection holdout evals to `verification-eval`.

## Primary Sources

- `SRC-GRESHAKE-2023`: Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*. ACM AISec '23, pp. 79-90. DOI: `10.1145/3605764.3623985`.
- `SRC-OWASP-LLM-2025`: OWASP GenAI Security Project (2025). *OWASP Top 10 for LLM Applications 2025* (`https://genai.owasp.org/llm-top-10/`).
