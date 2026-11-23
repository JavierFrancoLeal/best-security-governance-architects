---
name: authn-authz-boundaries
description: Functional pre-merge security control module for Authentication, JWT/Sessions, CORS/CSRF, Object/Function AuthZ & Tenant Isolation under security-governance v1.2.0.
license: MIT
metadata:
  schema_version: "1.2.0"
  judgment_schema: "SEC.md"
  suite_id: "security-governance"
  author: "best-security-governance-architects"
---

# Module Profile: `authn-authz-boundaries`

## When To Use
- Activate when a PR modifies routers, controllers, GraphQL/RPC resolvers, Electron preloads/IPC, auth middleware, JWT/OIDC, cookie/CORS/CSRF configs, RBAC policies.

## Do Not Use When
- Changes touch zero in-scope surfaces for `authn-authz-boundaries`, or belong to sibling suites (`systems-harness`, `verification-eval`, `spec-context`, `ui-ux`) or `OUT_OF_SCOPE` runtime/certification regimes.

## Required Inputs
- Unified PR diff, Tier A `tools/sec_cpu_scanner.py` JSON output, and Tier B normalized `tools/sarif_ingest.py` SARIF summary (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`).

## Execution & Audit Workflow
1. Run deterministic CPU scanners first (`TOOL_VERIFIED`); fail closed (`UNVERIFIED_MISSING_TOOL`) if any required scanner is absent.
2. Load `./BRIEF.md` for operational rules and `./SEC.md` on demand for deep CWE/evidence mappings.
3. Delegate non-SAST semantic invariants to Clean-Room cross-model auditors (auditor-authz-intent).

## Verdict & Severity Criteria
- Strict `conjunctive_gate` (`score_heuristic: null`): `BLOCKER >= 1 -> REJECT`; `MAJOR >= 1` or missing required tool -> `ITERATE`; else `SHIP`.
- Deduplicate findings per `(file, line, authn-authz-boundaries)` at highest severity.

## Guardrails
- Never emit `SHIP` on `UNVERIFIED_MISSING_TOOL`.
- Never claim formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA`).
