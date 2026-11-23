---
schema_version: 1.2.0
module_identity:
  slug: systemic-governance-audit
  domain: Container/IaC Isolation, Anti-Self-Auditing, Clean-Room Evidence & Governance Tags
  stride_categories:
  - Elevation of Privilege
  - Repudiation
  - Tampering
  standard_anchors:
  - "ECOSYSTEM_CONTRACT v1.2.0 (\xA74, \xA77, \xA78)"
  - Kubernetes Pod Security Standards (Baseline & Restricted)
  - EU DORA Art. 9(4)(e) & RTS (EU) 2024/1774 Art. 17
  - EU AI Act Art. 11/12/14/50 & ISO/IEC 42001:2023
cpu_rules:
- rule_id: SEC-INFRA-PRIV-001
  canonical_id: security-governance:systemic-governance-audit:SEC-INFRA-PRIV-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-INFRA-PRIV-001
  severity: BLOCKER
  cwe_ids:
  - CWE-250
  - CWE-732
  sarif_security_severity_min: 9.0
  source_id: SRC-K8S-PSS
- rule_id: SEC-INFRA-ROOT-001
  canonical_id: security-governance:systemic-governance-audit:SEC-INFRA-ROOT-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-INFRA-ROOT-001
  severity: MAJOR
  cwe_ids:
  - CWE-250
  sarif_security_severity_min: 6.5
  source_id: SRC-K8S-PSS
- rule_id: SEC-GOV-SELFAUDIT-001
  canonical_id: security-governance:systemic-governance-audit:SEC-GOV-SELFAUDIT-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-GOV-SELFAUDIT-001
  severity: BLOCKER
  cwe_ids:
  - CWE-284
  - CWE-778
  sarif_security_severity_min: 9.0
  source_id: SRC-EU-DORA-RTS-2024
semantic_invariants:
- invariant_id: SEM-SELFAUDIT-001
  canonical_id: security-governance:systemic-governance-audit:SEM-SELFAUDIT-001
  severity: BLOCKER
  cwe_ids:
  - CWE-284
  - CWE-778
  diff_check: Verify autonomous builder agents cannot write to tests/, evals/, rules.yaml, policy files, validators/, or audit
    logs, and cannot self-certify SHIP in the same session (delegated to auditor-agentic-abuse agentic-05).
  false_positive_exemption: Exempt read-only isolated Clean-Room auditor runs consuming immutable diffs and external append-only
    audit sinks.
  requires_cross_model_auditor: true
  source_id: SRC-EU-DORA-RTS-2024
evidence_contribution_mappings:
- framework: eu_dora_art9
  control_ref: Regulation (EU) 2022/2554 Art. 9(4)(e); RTS (EU) 2024/1774 Art. 17(1)(a)-(d)
  contribution_scope: contributes pre-merge evidence toward ICT change verification, author-vs-approver separation, and documented
    change traceability.
  evidence_artifact: Verdict Envelope v1.2.0 + SARIF 2.1.0 bundle + named human_signoff record
  source_id: SRC-EU-DORA-RTS-2024
- framework: iso_42001
  control_ref: ISO/IEC 42001:2023 Annex A.6.2.4, A.6.2.5, A.6.2.8, A.9.2-A.9.4
  contribution_scope: contributes pre-merge evidence toward AI system lifecycle V&V, deployment gating, and event-log recording
    controls.
  evidence_artifact: Verdict Envelope v1.2.0 linked to commit SHA and immutable CI SARIF reports
  source_id: SRC-ISO-42001-2023
primary_sources:
- source_id: SRC-K8S-PSS
  title: Kubernetes Pod Security Standards (Baseline & Restricted)
  publisher: Cloud Native Computing Foundation (Kubernetes)
  version_or_date: v1.30+
  identifier_type: official_url
  url_or_doi: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- source_id: SRC-EU-DORA-RTS-2024
  title: Commission Delegated Regulation (EU) 2024/1774 (ICT Risk Management RTS)
  publisher: European Union (EUR-Lex)
  version_or_date: '2024-03-13'
  identifier_type: eur_lex_celex
  url_or_doi: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774
- source_id: SRC-ISO-42001-2023
  title: "ISO/IEC 42001:2023 Information technology \u2014 Artificial intelligence \u2014 Management system"
  publisher: ISO/IEC JTC 1/SC 42
  version_or_date: 2023-12
  identifier_type: official_url
  url_or_doi: https://www.iso.org/standard/81230.html
---

# Container/IaC Isolation, Anti-Self-Auditing, Clean-Room Evidence & Governance Tags (`systemic-governance-audit`, Lazy On-Demand Reference)

## Exploit Mechanics & Threat Model
- STRIDE coverage: Elevation of Privilege, Repudiation, Tampering.
- Standard anchors: ECOSYSTEM_CONTRACT v1.2.0 (§4, §7, §8), Kubernetes Pod Security Standards (Baseline & Restricted), EU DORA Art. 9(4)(e) & RTS (EU) 2024/1774 Art. 17, EU AI Act Art. 11/12/14/50 & ISO/IEC 42001:2023.

## Deterministic CPU vs. Clean-Room Semantic Split
- Deterministic CPU rules (`TOOL_VERIFIED`): security-governance:systemic-governance-audit:SEC-INFRA-PRIV-001, security-governance:systemic-governance-audit:SEC-INFRA-ROOT-001, security-governance:systemic-governance-audit:SEC-GOV-SELFAUDIT-001.
- Clean-Room semantic invariants (`STATIC_LLM_INFERRED`): security-governance:systemic-governance-audit:SEM-SELFAUDIT-001.

## Scope & Governance Boundary
- Findings contribute pre-merge technical evidence only and do not constitute formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA` are `OUT_OF_SCOPE`).
