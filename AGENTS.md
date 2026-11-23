# AGENTS.md — best-security-governance-architects

<!-- BEGIN best-security-governance-architects -->
## Security & Governance Pre-Merge Gate (`best-security-governance-architects`, `suite_id: security-governance`, v1.2.0)

- **Precedence & Synthesis:** Rank 1 (`security-governance` > `verification-eval` > `systems-harness` > `spec-context` > `ui-ux`). Strict `conjunctive_gate` (`BLOCKER >= 1 -> REJECT`, `MAJOR >= 1 -> ITERATE`, else `SHIP`; `score_heuristic: null`, `regimes: 0`).
- **Step 0 (CPU-First, Fail-Closed):** Run `python3 tools/sec_cpu_scanner.py --root . --format json` and ingest Tier B SARIF reports (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 tools/sarif_ingest.py`. Missing required tool evidence emits `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`) and prohibits `SHIP`.
- **Step 1 (STRIDE x Attack Surface Routing):** Consult `committee/security-director/control-matrix.yaml` and load only active `modules/<slug>/BRIEF.md` briefs (`<= 2,600 B` each; total active operational context `<= 25,600 B`).
- **Step 2 (Clean-Room Separation of Powers):** Invoke `committee/auditors/auditor-authz-intent` and/or `committee/auditors/auditor-agentic-abuse` in a fresh stateless cross-model session (`clean_room_required: true`) receiving ONLY the sanitized unified diff, normalized CPU/SARIF JSON, and serialized `verdict_envelope` YAML — never the builder's chain-of-thought.
- **Anti-Self-Auditing Invariant:** Builder agents MUST NOT edit `tests/`, `evals/`, `rules.yaml`, `validators/`, or audit logs to self-certify `SHIP`.
- **Honest Scope:** Contributes pre-merge technical evidence toward EU DORA Art. 9, EU AI Act Art. 12/14/15, ISO/IEC 42001, NIST AI RMF/SSDF, SLSA, and SPDX. Formal legal certification and safety-critical regimes (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA`) are explicitly `OUT_OF_SCOPE`.
<!-- END best-security-governance-architects -->
