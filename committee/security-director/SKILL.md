---
name: security-director
description: Orchestrates CPU-first pre-merge security and governance gates using SAST/SCA/secret/IaC scanners, STRIDE x attack-surface control briefs, and Clean-Room cross-model auditors to emit Verdict Envelope v1.2.0.
license: MIT
compatibility: agentskills.io coding agents and CI (Python 3.9+ stdlib, SARIF 2.1.0).
allowed-tools: Bash(python3 ./tools/sec_cpu_scanner.py:*) Bash(python3 ./tools/sarif_ingest.py:*) Read Grep Glob
metadata:
  schema_version: "1.2.0"
  suite_id: "security-governance"
  author: "best-security-governance-architects"
  routing_matrix: "./references/control-matrix.yaml"
  pre_scanner: "./tools/sec_cpu_scanner.py"
---

# Security Director (`security-director`)

## When To Use
- Pre-merge security/governance review (`plan`, `design`, `build`, `verify`, `secure`) on auth, input/parser, crypto, secrets, supply-chain, IaC, PII, agentic/MCP, or CI policy diffs.

## Do Not Use When
- Live pentesting, runtime WAF/SIEM/SRE, cloud FinOps, formal legal certification, or safety-critical standards (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA`).
- Structural DB DDL lock-safety (`systems-harness`), test/mutation coverage (`verification-eval`), or UI ergonomics (`ui-ux`).

## Required Inputs
- PR diff/file slice and commit SHA.
- Tier A JSON from `python3 ./tools/sec_cpu_scanner.py --root . --format json` and Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) normalized via `python3 ./tools/sarif_ingest.py`.
- Upstream `verdict_envelope` YAML when escalated.

## Orchestration Protocol
1. **CPU-First Fail-Closed:** Run `./tools/sec_cpu_scanner.py` + `./tools/sarif_ingest.py`. Missing required tool -> `UNVERIFIED_MISSING_TOOL`, `security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`.
2. **STRIDE Routing (`regimes: 0`):** Match paths in `./references/control-matrix.yaml`; load ONLY active `./references/modules/<slug>/BRIEF.md` (`<= 25,600 B` total active load). Keep `SEC.md` and `docs/engineers/*.md` lazy on disk.
3. **Clean-Room Audit (`clean_room_required: true`):** On Tier 2/3 surfaces, run `./references/auditors/auditor-authz-intent/AUDITOR.md` and/or `auditor-agentic-abuse/AUDITOR.md` in a fresh cross-model session with zero builder reasoning.
4. **Conjunctive Gate:** Deduplicate per `(file, line, module_id)`. `BLOCKER >= 1 -> REJECT`; `MAJOR >= 1` or pending Tier 3 `human_signoff` -> `ITERATE`; else `SHIP` (`score_heuristic: null`).

## Mandatory Closing Output
```yaml
verdict_envelope:
  envelope_version: "1.2.0"
  envelope_id: "<run-id>"
  trace_id: "<trace-id>"
  suite_id: "security-governance"
  director_slug: "security-director"
  artifact_ref: "<pr-or-files>"
  sdlc_stage: "secure"
  regime: "stride_x_attack_surface"
  synthesis_mode: "conjunctive_gate"
  evidence_tier: "<TOOL_VERIFIED | STATIC_LLM_INFERRED | UNVERIFIED_MISSING_TOOL>"
  evidence:
    - { tool: "sec_cpu_scanner", command_or_ref: "python3 ./tools/sec_cpu_scanner.py --root . --format json", exit_code: 0, format: "json", summary: "<counts>" }
  verdict: "<SHIP | ITERATE | REJECT>"
  counts: { blocker: 0, major: 0, minor: 0 }
  score_heuristic: null
  blocking_ids: []
  clean_room_required: true
  hop_count: 0
  max_hops: 2
  visited_suites: ["security-governance"]
  escalations: []
  domain_extensions:
    threat_surfaces_touched: []
    risk_gate_tier: "AUTO_PASS_ON_CLEAN_CPU"
    cross_model_auditor_verified: false
    human_signoff: { required: false, approver_role: null, approver_id: null, status: "NOT_REQUIRED", signed_off_at: null }
    evidence_contribution_toward: []
```

## Guardrails
- Never emit `SHIP` on `UNVERIFIED_MISSING_TOOL` or `human_signoff.status == "PENDING"`.
- Never escalate to a suite in `visited_suites` or when `hop_count >= max_hops`.
- Block builder edits to `tests/`, `evals/`, `rules.yaml`, `validators/`, or audit logs.
- Governance tags represent pre-merge evidence contribution only, never legal certification.
