# Security Governance Bootstrap Rule (`security-governance`, v1.2.0)

Before approving or merging changes touching authentication, authorization, input/parser sinks, cryptography, secrets, dependencies, IaC, PII, LLM/MCP agents, or CI/governance files:

1. **Step 0 — CPU-First Pre-Scanner (Mandatory):**
   Run `python3 .agents/skills/security-director/tools/sec_cpu_scanner.py --root . --format json` and normalize Tier B SARIF reports (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) with `python3 .agents/skills/security-director/tools/sarif_ingest.py`.
   If any required scanner is unavailable, emit `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`) and prohibit `SHIP` (`verdict: ITERATE`).
2. **Step 1 — STRIDE x Attack Surface Routing:**
   Consult `.agents/skills/security-director/references/control-matrix.yaml` and load ONLY active module `BRIEF.md` files (`<= 25,600 B` total active budget).
3. **Step 2 — Clean-Room Cross-Model Separation:**
   For Tier 2/3 surfaces, run `auditor-authz-intent` and/or `auditor-agentic-abuse` in a fresh stateless cross-model session (`clean_room_required: true`) with zero builder chain-of-thought.
4. **Step 3 — Anti-Self-Auditing & Conjunctive Verdict:**
   Builder agents MUST NOT edit `tests/`, `evals/`, `rules.yaml`, `validators/`, or audit logs. Emit Verdict Envelope `v1.2.0` (`BLOCKER >= 1 -> REJECT`, `MAJOR >= 1 -> ITERATE`, else `SHIP`).
