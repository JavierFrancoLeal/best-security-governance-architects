---
module_id: data-isolation-pii
suite_id: security-governance
max_bytes: 2600
synthesis_mode: conjunctive_gate
auditor_refs: [auditor-authz-intent]
handoff_targets: [spec-context]
---

# BRIEF: `data-isolation-pii`

**Scope & Triggers:** logging/telemetry, error handlers, diagnostic exports, frontend storage, outbound LLM/analytics clients, ORM DTOs, Redis/vector-DB caches.

**Mandatory CPU Gate (Fail-Closed):**
- Run `python3 ./tools/sec_cpu_scanner.py --root . --format json` + Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 ./tools/sarif_ingest.py`.
- Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`).

**Conjunctive Gate Checklist:**
- [BLOCKER] `SEC-DATA-LOG-001`: Zero raw `Authorization` headers, passwords, tokens, or `process.env` in logs/telemetry (`sec_cpu_scanner` + `semgrep`).
- [MAJOR] `SEC-DATA-PII-001`: Zero unredacted PII (`email`, `ssn`/`taxId`, `dob`, `phone`) in stdout logs or diagnostic dumps (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEM-DPI-01`: Scrub PII before external LLM egress; enforce `tenant_id` partitioning on shared Redis/RAG/vector stores; default privacy settings to maximum confidentiality.

**Deduplication & Boundaries:**
- Count each root cause at `(file, line, data-isolation-pii)` once at highest severity.
- Escalate cross-suite defects cleanly (`handoff_targets: [spec-context]`) without duplicating sibling rules.
