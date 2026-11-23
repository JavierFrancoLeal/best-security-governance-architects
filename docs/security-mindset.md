# Security Governance Lineage Matrix (`best-security-governance-architects`)

Contract: `ECOSYSTEM_CONTRACT v1.2.0` | Suite: `security-governance` | Synthesis: `conjunctive_gate` (`score_heuristic: null`, `regimes: 0`) | Precedence: Rank 1 (`security-governance` > `verification-eval` > `systems-harness` > `spec-context` > `ui-ux`).

> Stored offline on disk (`<= 6 KB`) and excluded from default operational context (`<= 25,600 B`). Zero persona roleplay; authorities anchor falsifiable non-SAST invariants only.

## 1. Blind-Curated 8-Member Canon & Axis-to-Rule Matrix

| Axis | Authority (`slug`) | Tier (Anchor) | Core Security Axiom | Structural Failure Mode Prevented | Bound Rules |
|---|---|---|---|---|---|
| A | Saltzer & Schroeder (`saltzer-schroeder`) | LINDY_CANON (1972/75) | Complete mediation, fail-safe defaults, protection rings, capability scoping | IDOR/BOLA (API1), BFLA (API5), ambient confused-deputy authority (LLM06) | `authz-01`, `authz-02`, `agentic-02` |
| B | Ross Anderson (`anderson`) | LINDY_CANON (1994/01/20) | Aligned liability incentives, authoritative bookkeeping, non-composable APIs | Cross-tenant leakage, client-trusted billing, multi-step API sequence abuse | `authz-04`, `authz-07` |
| C | Adam Shostack (`shostack`) | LINDY_CANON (2008/14/20) | Pre-merge DFD trust-boundary decomposition & explicit property projection | Mass assignment / excessive data exposure (API3), unsafe 3rd-party trust | `authz-03` |
| D | Nancy Leveson (`leveson-sec`) | LINDY_CANON (2011/14) | Security as hierarchical control constraints & process-model fidelity (STAMP) | Unconstrained agent actuation, fail-open fallback, builder self-auditing | `agentic-05` |
| E | Daniel J. Bernstein (`bernstein-sec`) | LINDY_CANON (2005-12) | Misuse-resistant AEAD APIs, constant-time execution, UID compartmentalization | Decrypt-before-MAC doom, timing leaks, nonce reuse, privileged parsers | `authz-05` |
| F | Michal Zalewski (`zalewski-sec`) | LINDY_CANON (2005/11) | Strict origin/renderer isolation & single-grammar parser equivalence | Electron `senderFrame` bypass, JSON/HTTP/URL parser differentials | `authz-06` |
| G1 | Kai Greshake et al. (`greshake`) | PROVISIONAL_FRONTIER (2023) | Indirect prompt injection collapses data/instruction boundary via retrieval | Untrusted RAG/web/email steering privileged tools (LLM01), raw LLM sinks | `agentic-01`, `agentic-04` |
| G2 | Luca Beurer-Kellner et al. (`beurer-kellner`) | PROVISIONAL_FRONTIER (2024-25) | Deterministic agent patterns, cryptographic MCP pinning, toxic-flow graphs | MCP tool poisoning/rug pulls (MCP03), Lethal Trifecta, prompt-only guards | `agentic-03`, `agentic-06`, `agentic-07` |

## 2. Elimination Ledger (8 Rejected Candidates)

| # | Candidate | Primary Basis for Elimination | Disposition |
|---|---|---|---|
| 1 | Norm Hardy (1988) | Axis A overlap with `saltzer-schroeder`; standalone 3-page paper yields <5 invariants | Retained (`SRC-HARDY-1988`) in `saltzer-schroeder` |
| 2 | Moxie Marlinspike (2011/16) | Redundant on Axis E with `bernstein-sec` (AEAD + UID isolation) | Retained (`SRC-MARLINSPIKE-2011`) in `authz-05` |
| 3 | Sassaman, Patterson & Bratus (LangSec, 2013) | Overlaps Axis F parser differentials with `zalewski-sec`; build-tool scope -> `systems-harness` | Retained (`SRC-SASSAMAN-2013`) in `zalewski-sec` |
| 4 | Rogaway & Bellare (2000/02) | Formal reduction theory rather than shipped end-to-end engineering stacks; overlaps Axis E | Retained (`SRC-ROGAWAY-2002`) as AEAD ref |
| 5 | Diffie & Hellman (1976) | Foundational public-key math, not pre-merge code governance; <5 non-SAST PR predicates | Indexed (`SRC-DIFFIE-1976`) as exclusion record |
| 6 | Robert C. Seacord (CERT C, 2009) | Fails Gate 4: C memory-safety rules are mechanical CPU/compiler/SAST checks | Indexed (`SRC-SEACORD-CERTC`) as SAST boundary |
| 7 | James Kettle (2019/25) | Fails Gate 2 bracket (<10 yr Lindy floor, pre-2022); overlaps Axis F with `zalewski-sec` | Retained (`SRC-KETTLE-2019`) in `zalewski-sec` |
| 8 | Simon Willison (2023/25) | Frontier slot cap (max 2); `greshake` & `beurer-kellner` formalize Dual LLM & Lethal Trifecta | Retained (`SRC-WILLISON-2023/2025`) in Axis G |

## 3. Lindy-to-Frontier Continuity & Polymath Boundaries

- **Confused Deputy (Axis A -> G):** Complete mediation (`saltzer-schroeder`) explains why an LLM holding ambient operator credentials fails under Indirect Prompt Injection (`greshake`): enforcement MUST move outside the model into attenuated capabilities (`agentic-02`) and Dual-LLM quarantine (`agentic-01`).
- **Parser Differentials (Axis F -> G):** Origin/parser mismatches (`zalewski-sec`) mirror MCP tool poisoning (`beurer-kellner`), where human approval UIs and execution engines parse different meanings (`agentic-03`, `authz-06`).
- **Control Loops & Anti-Self-Auditing (Axis D -> G):** STAMP/STPA-Sec (`leveson-sec`) mandates hierarchical control constraints and Separation of Powers: autonomous agents MUST NOT hold write permissions over their own `tests/`, `evals/`, `rules.yaml`, policy files, or audit logs (`agentic-05`).
- **Polymath Facets (`-sec`):** `leveson-sec` (non-adversarial coupling -> `systems-harness`), `bernstein-sec` (test vectors -> `verification-eval`), `zalewski-sec` (fuzzing -> `verification-eval`, UX -> `ui-ux`).

## 4. Citation Hygiene Note

Secondary/unverified 2026 metrics (such as `arXiv:2611.03555v1`, `AAAI-26 pp. 35811` MCPTox, and the 126-repo 2026 multi-scanner study) are explicitly tagged `UNVERIFIED_SOURCE` pending live verification and are never used as sole gating justifications.
