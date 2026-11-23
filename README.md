# `best-security-governance-architects`

[![ECOSYSTEM_CONTRACT v1.2.0](https://img.shields.io/badge/ECOSYSTEM__CONTRACT-v1.2.0-blue.svg)](suite.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**CPU-first pre-merge security and governance suite** (`suite_id: security-governance`, `director_slug: security-director`, `judgment_file: SEC.md`) for `agentskills.io`-compatible coding agents and CI pipelines.

- **Synthesis Mode:** Strict `conjunctive_gate` (`BLOCKER >= 1 -> REJECT`, `MAJOR >= 1 -> ITERATE`, else `SHIP`; `score_heuristic: null`, `regimes: 0`).
- **Conflict Precedence:** Rank 1 (`security-governance` > `verification-eval` > `systems-harness` > `spec-context` > `ui-ux`).
- **Fail-Closed Deterministic Tooling:** Required Tier B scanners (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) plus bundled Tier A zero-dependency Python 3.9+ stdlib pre-scanner (`tools/sec_cpu_scanner.py`). Missing required tools emit `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`) and prohibit `SHIP`.
- **Clean-Room Cross-Model Separation of Powers:** `auditor-authz-intent` and `auditor-agentic-abuse` run read-only in fresh cross-model sessions (`clean_room_required: true`) with zero builder chain-of-thought. Builder agents are strictly blocked from editing `tests/`, `evals/`, `rules.yaml`, `validators/`, or audit logs.
- **Operational Context Budget:** Active default load stays strictly `<= 25,600 B` (`~20.2 KB` measured); 8 authority dossiers (`docs/engineers/*.md`, 48 non-SAST invariants) and `docs/security-mindset.md` (`<= 6 KB`) remain offline on disk.

---

## Quickstart

### 1. Run Deterministic CPU Pre-Scanner & Benchmark
```bash
# Tier A zero-dependency pre-scanner (exit 0 = 0 BLOCKER, 2 = >=1 BLOCKER, 3 = error)
python3 tools/sec_cpu_scanner.py --root . --format json

# Two-layer benchmark + evals.json schema verification
python3 tools/run_sec_benchmark.py --layer all --validate-evals

# Full repository & ECOSYSTEM_CONTRACT v1.2.0 conformance validation
python3 validators/validate_repo.py
```

### 2. Install into Your Workspace (Multi-Suite Safe)
```bash
# Default safe mode: registers strictly 1 active SKILL.md (security-director)
bash adapters/install.sh --target all --mode director-only --scope workspace --dest /path/to/your-repo
```
Supports `--target antigravity | deepseek | claude | codex | cursor | windsurf | all` without clobbering sibling suites (`best-ui-ux-designers`, etc.) or existing `AGENTS.md` / `CLAUDE.md` instructions.

---

## Repository Architecture

| Path | Role |
|---|---|
| `suite.yaml` | Root `ECOSYSTEM_CONTRACT v1.2.0` manifest |
| `committee/security-director/` | Sole indexed `SKILL.md`, STRIDE x attack-surface `control-matrix.yaml`, director `evals/evals.json` |
| `committee/auditors/` | Read-only Clean-Room auditors (`auditor-authz-intent`, `auditor-agentic-abuse`) with canonical v1.2.0 `rules.yaml` |
| `modules/` | 7 functional control modules (`secrets-supply-chain`, `injection-input-validation`, `authn-authz-boundaries`, `crypto-key-management`, `data-isolation-pii`, `agentic-ai-threats`, `systemic-governance-audit`), each with `PROFILE.md`, `BRIEF.md <= 2.6 KB`, `SEC.md`, and `evals/evals.json` |
| `docs/engineers/` & `docs/security-mindset.md` | Offline lineage matrix (`<= 6 KB`) and 8 non-biographical dossiers (48 non-SAST invariants) |
| `tools/` | `sec_cpu_scanner.py` (Tier A JSON + SARIF 2.1.0), `sarif_ingest.py` (Tier B normalizer + fail-closed gate + human-signoff verifier), `run_sec_benchmark.py` (22-fixture benchmark) |
| `validators/` | Immutable `ecosystem_core_validator.py` + `CORE_VALIDATOR.sha256` pin, `schema_sec.json` (Draft 2020-12), `validate_repo.py` |
| `adapters/` | Nested harness adapters (`antigravity`, `claude-code`, `codex-chatgpt`, `cursor`, `deepseek-harness`, `windsurf-devin`) + idempotent `install.sh` |
| `tests/fixtures/` | 14 Layer 1 CPU fixtures (10 TP + 4 Hard Negatives) and 8 Layer 2 SAST-evasive semantic fixtures (6 TP + 2 Hard Negatives) |

---

## Calibration Scope & Honest Labeling (`ECOSYSTEM_CONTRACT` §5.1.5)

Passing `tools/run_sec_benchmark.py` (`Recall == 1.00` on 10 TP, `FPR == 0.00` on 4 Hard Negatives, 0 Layer 1 BLOCKERs on 8 semantic diffs) is explicitly labeled a **synthetic fixture regression floor** — not a claim of universal production accuracy. Empirical production calibration with stratified holdout sets (`m >= 50-100`/class) and Rogan-Gladen prevalence debiasing is escalated via `Verdict Envelope v1.2.0` to `verification-eval`.

---

## Explicit Scope Boundaries and Non-Goals

| Domain / Assurance Capability | v1 Status | Pre-Merge Technical Boundary | Authoritative Owner |
|---|---|---|---|
| Pre-merge SAST, secret detection, SCA, IaC static scanning | `IN_SCOPE (TOOL_VERIFIED)` | Runs Tier A `sec_cpu_scanner.py` + Tier B `semgrep`, `gitleaks`, `osv-scanner`, `trivy`; fails closed if any required tool is absent | `security-governance` |
| Pre-merge AuthZ/IDOR & agentic tool-abuse semantic auditing | `IN_SCOPE (STATIC_LLM_INFERRED)` | Clean-Room cross-model review (`auditor-authz-intent`, `auditor-agentic-abuse`) over diffs and normalized SARIF | `security-governance` |
| Pre-merge governance evidence assembly (EU DORA Art. 9, EU AI Act Art. 12/14/15, ISO/IEC 42001, NIST AI RMF/SSDF, SLSA, SPDX) | `IN_SCOPE (Evidence Contribution Only)` | Produces SARIF 2.1.0 bundles, Verdict Envelope v1.2.0 records, and `human_signoff` hooks contributing technical evidence — never standalone legal compliance | Organizational GRC, Internal Audit, Accredited Auditors |
| Destructive database/schema migration structural safety | `OUT_OF_SCOPE (Escalated)` | Audits DORA Art. 9(4)(e) change-traceability only; lock-safety and rollback DDL belong to `systems-harness` | `systems-harness` |
| Executable test/mutation coverage & holdout LLM/RAG evals | `OUT_OF_SCOPE (Escalated)` | Escalated via `verdict_envelope.escalations[]` | `verification-eval` |
| Live penetration testing, red-teaming, DORA TLPT | `OUT_OF_SCOPE` | Pre-merge static/diff analysis cannot test live deployed infrastructure | Qualified Pentesters / Red Team |
| Runtime WAF, RASP, EDR, SIEM, SRE observability & cloud FinOps | `OUT_OF_SCOPE` | Explicitly excluded from v1 Pre-Merge Change Governance (`ECOSYSTEM_CONTRACT` §1) | SecOps / SOC / SRE |
| Safety-critical certification (`DO-178C`/`DO-330`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA`) | `OUT_OF_SCOPE` | Requires formal tool qualification and full lifecycle certification outside unqualified pre-merge scanners and LLMs | Qualified Safety Toolchains, DERs, Notified Bodies |
| Formal legal counsel, CE marking & statutory compliance sign-off | `OUT_OF_SCOPE` | Neither static scanners nor LLM auditors render legal opinions or conformity assessments | Legal Counsel, DPO, Certification Bodies |

---

## Open-Source Agent Governance & Companion Suites

| Repository | Role | Status |
| :--- | :--- | :--- |
| **[`casebook`](https://github.com/JavierFrancoLeal/casebook)** | Bounded-entropy 4-tier constitutional memory, Open Symptoms Radar & 5-to-1 compaction oracle | **`v1.0.1` Live** |
| **[`dual-brain-guard`](https://github.com/JavierFrancoLeal/dual-brain-guard)** | Harness-agnostic mechanical Proposer != Verifier cross-model guard (`CLI + MCP + hooks`) | **`v1.1.1` Live** |
| **[`autonomy-ladder`](https://github.com/JavierFrancoLeal/autonomy-ladder)** | Evidence-based Traffic-Light autonomy grader (`🟢 / ⚑ / 🟡 / 🔴` & `A/B/C/D` trust scores) | **`v1.0.2` Live** |
| **[`governed-browser`](https://github.com/JavierFrancoLeal/governed-browser)** | Constitutional commit-click brake (`🛑 RED` on Send/Pay/Delete) & SHA-256 hash-chained audit trail | **`v1.0.1` Live** |
| **[`forensic-contracts`](https://github.com/JavierFrancoLeal/forensic-contracts)** | 5-line `@forensic-contract` linter, `@blast-radius` cage enforcer & literal `sourcePin` verifier | **`v1.0.1` Live** |
| **[`agent-governance`](https://github.com/JavierFrancoLeal/agent-governance)** | Complete 26-plugin DeepSeek Harness governance suite (mother repository) | **`v1.0.0` Live** |
| **[`best-ui-ux-designers`](https://github.com/JavierFrancoLeal/best-ui-ux-designers)** | Adversarial UI/UX design judgment suite — 12 Barbell design minds & 4 Via Negativa auditors | **`v1.2.0` Live** |

---

## License

Released under the [MIT License](LICENSE).
