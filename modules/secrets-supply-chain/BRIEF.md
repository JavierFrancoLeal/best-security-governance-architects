---
module_id: secrets-supply-chain
suite_id: security-governance
max_bytes: 2600
synthesis_mode: conjunctive_gate
auditor_refs: [none]
handoff_targets: [none]
---

# BRIEF: `secrets-supply-chain`

**Scope & Triggers:** source code, `.env*`, `*.pem/*.key`, lockfiles (`package-lock.json`, `uv.lock`, `go.sum`), `Dockerfile*`, `.github/workflows/**`.

**Mandatory CPU Gate (Fail-Closed):**
- Run `python3 ./tools/sec_cpu_scanner.py --root . --format json` + Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 ./tools/sarif_ingest.py`.
- Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`).

**Conjunctive Gate Checklist:**
- [BLOCKER] `SEC-CRED-001`: Zero hardcoded secrets, cloud/API keys, or canary tokens in diff/commits (`sec_cpu_scanner` + `gitleaks`).
- [BLOCKER] `SEC-CRED-002`: Zero PEM/private-key blocks or tracked `.env`/keystore files (`gitleaks` + `sec_cpu_scanner`).
- [MAJOR] `SEC-CRED-003`: Zero raw `.env` file reads exposed into HTTP/diagnostic responses (`sec_cpu_scanner`).
- [BLOCKER] `SEC-SUP-CVE-001`: Zero unwaived HIGH/CRITICAL (CVSS >= 7.0) CVEs with fixed versions (`osv-scanner` + `trivy`).
- [MAJOR] `SEC-SUP-TAG-001`: Pin 3rd-party GitHub Actions to 40-char SHA, container images to `@sha256:`, and commit lockfiles (`sec_cpu_scanner` + optional `zizmor`).
- [MAJOR] `SEC-SUP-LIC-001`: Zero forbidden/incompatible or `UNKNOWN` SPDX licenses (`trivy` + `sec_cpu_scanner`).
- [MAJOR] `SEM-SSC-01`: Release workflows emit signed SLSA v1.2 Build L2+ provenance and SPDX/CycloneDX SBOM.

**Deduplication & Boundaries:**
- Count each root cause at `(file, line, secrets-supply-chain)` once at highest severity.
- Escalate cross-suite defects cleanly (`handoff_targets: [none]`) without duplicating sibling rules.
