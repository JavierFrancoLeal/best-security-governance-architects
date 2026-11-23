---
name: injection-input-validation
description: Functional pre-merge security control module for SQL/NoSQL, XSS/DOM, SSTI/Eval, OS Command, SSRF, Path Traversal & Deserialization under security-governance v1.2.0.
license: MIT
metadata:
  schema_version: "1.2.0"
  judgment_schema: "SEC.md"
  suite_id: "security-governance"
  author: "best-security-governance-architects"
---

# Module Profile: `injection-input-validation`

## When To Use
- Activate when a PR modifies backend handlers, DB/ORM queries, DOM/template renderers, XML/YAML/binary parsers, file upload/archive handlers, outbound HTTP clients.

## Do Not Use When
- Changes touch zero in-scope surfaces for `injection-input-validation`, or belong to sibling suites (`systems-harness`, `verification-eval`, `spec-context`, `ui-ux`) or `OUT_OF_SCOPE` runtime/certification regimes.

## Required Inputs
- Unified PR diff, Tier A `tools/sec_cpu_scanner.py` JSON output, and Tier B normalized `tools/sarif_ingest.py` SARIF summary (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`).

## Execution & Audit Workflow
1. Run deterministic CPU scanners first (`TOOL_VERIFIED`); fail closed (`UNVERIFIED_MISSING_TOOL`) if any required scanner is absent.
2. Load `./BRIEF.md` for operational rules and `./SEC.md` on demand for deep CWE/evidence mappings.
3. Delegate non-SAST semantic invariants to Clean-Room cross-model auditors (auditor-authz-intent).

## Verdict & Severity Criteria
- Strict `conjunctive_gate` (`score_heuristic: null`): `BLOCKER >= 1 -> REJECT`; `MAJOR >= 1` or missing required tool -> `ITERATE`; else `SHIP`.
- Deduplicate findings per `(file, line, injection-input-validation)` at highest severity.

## Guardrails
- Never emit `SHIP` on `UNVERIFIED_MISSING_TOOL`.
- Never claim formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA`).
