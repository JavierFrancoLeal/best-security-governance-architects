---
module_id: systemic-governance-audit
suite_id: security-governance
max_bytes: 2600
synthesis_mode: conjunctive_gate
auditor_refs: [auditor-agentic-abuse, auditor-authz-intent]
handoff_targets: [systems-harness]
---

# BRIEF: `systemic-governance-audit`

**Scope & Triggers:** `.github/workflows/**`, `k8s/**`, `Dockerfile*`, `*.tf`, `policy/**`, `CODEOWNERS`, `.security*`, `migrations/**`.

**Mandatory CPU Gate (Fail-Closed):**
- Run `python3 ./tools/sec_cpu_scanner.py --root . --format json` + Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 ./tools/sarif_ingest.py`.
- Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`).

**Conjunctive Gate Checklist:**
- [BLOCKER] `SEC-INFRA-PRIV-001`: Zero `privileged: true` containers or host-socket mounts (`sec_cpu_scanner` + `trivy`).
- [MAJOR] `SEC-INFRA-ROOT-001`: Zero `runAsUser: 0` or `allowPrivilegeEscalation: true` (`sec_cpu_scanner` + `trivy`).
- [BLOCKER] `SEC-GOV-SELFAUDIT-001` / `SEM-SELFAUDIT-001`: Block builder self-auditing loops (write access to `tests/`, `evals/`, `rules.yaml`, policy, or audit logs; `continue-on-error: true` on security jobs).
- [MAJOR] Escalate destructive SQL/ORM DDL migrations to `systems-harness`; audit DORA Art. 9(4)(e) change-traceability only.
- [BLOCKER] Reject any formal certification claim for `DO-178C`, `ISO 26262`, `ASPICE 4.0`, or `FDA CSA` (`OUT_OF_SCOPE`).

**Deduplication & Boundaries:**
- Count each root cause at `(file, line, systemic-governance-audit)` once at highest severity.
- Escalate cross-suite defects cleanly (`handoff_targets: [systems-harness]`) without duplicating sibling rules.
