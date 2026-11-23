---
slug: "beurer-kellner"
tier: "PROVISIONAL_FRONTIER"
primary_axis: "G"
axis_label: "Agentic Security Design Patterns, MCP Tool Poisoning & Toxic Flow Governance"
polymath_facet: false
verified_sources: ["SRC-BEURER-KELLNER-2025A", "SRC-BEURER-KELLNER-2025B", "SRC-BEURER-KELLNER-2025C", "SRC-BEURER-KELLNER-2025D", "SRC-DEBENEDETTI-2024", "SRC-DEBENEDETTI-2025", "SRC-WILLISON-2023", "SRC-WILLISON-2025"]
bound_auditor_rules: ["agentic-03", "agentic-06", "agentic-07"]
---

# Authority Dossier: `beurer-kellner` (Offline Reference)

**Axiomatic Failure Model:** Because probabilistic prompt guardrails remain susceptible to adversarial bypasses, agent security requires deterministic architectural patterns (Action-Selector, Plan-Then-Execute, Dual LLM, Context-Minimization, CaMeL capability separation), cryptographic tool-description pinning against rug pulls, and toxic-flow partitioning breaking the Lethal Trifecta. *(Secondary 2026 empirical figures such as `arXiv:2611.03555v1` and `AAAI-26 pp. 35811` MCPTox are tagged `UNVERIFIED_SOURCE` pending live verification.)*

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `beurer-kellner-inv-01` | MCP client/host code injects external server tool descriptions verbatim into LLM prompts without cryptographic hash pinning (rug-pull detection) and cross-server instruction/shadowing inspection (OWASP MCP03:2025). | Standard SAST/SCA treats MCP schema loading as benign configuration data and ignores natural-language prompt payloads inside tool metadata. | `BLOCKER` | `SRC-BEURER-KELLNER-2025B` |
| `beurer-kellner-inv-02` | An agent session mounts tools simultaneously providing (1) private/sensitive data access, (2) untrusted external content ingestion, and (3) external communication or public write sinks (Lethal Trifecta) without deterministic runtime flow partitioning. | Each individual tool (read repo, list issues, create PR) is benign alone; the toxic flow exists only in the composed runtime tool graph. | `MAJOR` | `SRC-BEURER-KELLNER-2025C` |
| `beurer-kellner-inv-03` | An agent relies exclusively on system-prompt admonitions or ML guardrail classifiers instead of structural control-data isolation (Action-Selector, Plan-Then-Execute, Dual LLM with reference-only memory, Context-Minimization), or feeds quarantined outputs back into a privileged LLM. | Structural control-flow vs. data-flow separation across Dual-LLM/CaMeL components cannot be audited via regex or single-file AST patterns. | `MAJOR` | `SRC-BEURER-KELLNER-2025A` |
| `beurer-kellner-inv-04` | Tool confirmation UIs or logs truncate, hide, or summarize tool call arguments (e.g., auxiliary sidenote fields), concealing exfiltrated secrets from the approving human operator. | UI serialization and truncation look benign to static scanners; detecting semantic argument omission requires tracing handler-to-UI bindings. | `MAJOR` | `SRC-BEURER-KELLNER-2025B` |
| `beurer-kellner-inv-05` | Multi-server MCP configurations allow an untrusted server's tool description to reference or override invocation semantics of tools exposed by separate trusted servers (cross-origin tool shadowing). | Cross-server instruction-namespace isolation is an orchestration boundary outside standard SAST/IaC policies. | `BLOCKER` | `SRC-BEURER-KELLNER-2025D` |
| `beurer-kellner-inv-06` | Agent tool wrappers expose open-ended execution primitives (arbitrary shell, arbitrary SQL, arbitrary URL fetch) instead of narrow, parameterized task-specific actions (LLM06:2025 excessive functionality). | Open-ended tool schemas compile cleanly as valid code unless evaluated against least-functionality design patterns. | `BLOCKER` | `SRC-BEURER-KELLNER-2025A` |

## Scope & Handoff

Triggers on MCP client/server manifests, agent tool registries, LLM orchestrators, and runtime guardrail policies. Escalate dynamic prompt-injection evaluation gaps (AgentDojo-style suites) to `verification-eval` and obfuscated confirmation-dialog UX to `ui-ux`.

## Primary Sources

- `SRC-BEURER-KELLNER-2025A`: Beurer-Kellner, L., et al. (2025). *Design Patterns for Securing LLM Agents against Prompt Injections*. DOI: `10.48550/arXiv.2506.08837`.
- `SRC-BEURER-KELLNER-2025B`: Beurer-Kellner, L., & Fischer, M. (2025). *MCP Security Notification: Tool Poisoning Attacks* (`https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks`).
- `SRC-BEURER-KELLNER-2025C`: Invariant Labs (2025). *Toxic Flow Analysis* (`https://invariantlabs.ai/blog/toxic-flow-analysis`).
- `SRC-BEURER-KELLNER-2025D`: Invariant Labs (2025). *GitHub MCP Exploited: Toxic Agent Flows* (`https://invariantlabs.ai/blog/mcp-github-vulnerability`).
- `SRC-DEBENEDETTI-2024`: Debenedetti, E., et al. (2024). *AgentDojo*. NeurIPS 2024. DOI: `10.48550/arXiv.2406.13352`.
- `SRC-DEBENEDETTI-2025`: Debenedetti, E., et al. (2025). *Defeating Prompt Injections by Design (CaMeL)*. DOI: `10.48550/arXiv.2503.18813`.
