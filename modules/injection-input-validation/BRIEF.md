---
module_id: injection-input-validation
suite_id: security-governance
max_bytes: 2600
synthesis_mode: conjunctive_gate
auditor_refs: [auditor-authz-intent]
handoff_targets: [verification-eval]
---

# BRIEF: `injection-input-validation`

**Scope & Triggers:** backend handlers, DB/ORM queries, DOM/template renderers, XML/YAML/binary parsers, file upload/archive handlers, outbound HTTP clients.

**Mandatory CPU Gate (Fail-Closed):**
- Run `python3 ./tools/sec_cpu_scanner.py --root . --format json` + Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 ./tools/sarif_ingest.py`.
- Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`).

**Conjunctive Gate Checklist:**
- [BLOCKER] `SEC-INJ-SQLI-001`: Zero SQL/NoSQL string interpolation; bind all parameters via prepared statements (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEC-INJ-XSS-001`: Zero unsanitized DOM/HTML sinks (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`) (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEC-INJ-CMD-001`: Zero OS shell execution (`shell=True`, `os.system`, `child_process.exec`) on untrusted input (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEC-INJ-SSRF-001`: Zero unvalidated outbound URL fetch; enforce host allowlist + post-DNS IP block + manual redirects (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEC-INJ-DESER-001`: Zero `pickle.loads`, unsafe `yaml.load`, XXE, `eval`, or uncanonicalized path traversal (`semgrep` + `sec_cpu_scanner`).
- [BLOCKER] `SEM-SSRFDIFF-001`: Eliminate URL/IPv6 parser differentials between validators and HTTP clients (`auditor-authz-intent`).

**Deduplication & Boundaries:**
- Count each root cause at `(file, line, injection-input-validation)` once at highest severity.
- Escalate cross-suite defects cleanly (`handoff_targets: [verification-eval]`) without duplicating sibling rules.
