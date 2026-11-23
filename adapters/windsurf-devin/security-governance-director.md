# Security Director Rule (`security-governance`, v1.2.0)

- **CPU-First Gate:** Run `python3 .windsurf/skills/security-director/tools/sec_cpu_scanner.py --root . --format json` and normalize Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `sarif_ingest.py`. Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`ITERATE`, never `SHIP`).
- **Scoped Briefs:** Route via `.windsurf/skills/security-director/references/control-matrix.yaml` and load active `BRIEF.md` files (`<= 25,600 B` budget).
- **Clean-Room Separation:** Run `auditor-authz-intent` and `auditor-agentic-abuse` in a fresh cross-model session; forbid builder edits to `tests/`, `evals/`, `rules.yaml`, `validators/`, or audit logs.
- **Conjunctive Gate:** `BLOCKER >= 1 -> REJECT`, `MAJOR >= 1 -> ITERATE`, else `SHIP`; emit `Verdict Envelope v1.2.0`.
