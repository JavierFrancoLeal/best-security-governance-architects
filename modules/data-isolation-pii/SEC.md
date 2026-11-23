---
schema_version: 1.2.0
module_identity:
  slug: data-isolation-pii
  domain: PII & Credential Log Isolation, Client Storage, LLM Egress Redaction & Privacy Defaults
  stride_categories:
  - Information Disclosure
  - Tampering
  standard_anchors:
  - OWASP Top 10:2025 (A01, A04, A09)
  - OWASP ASVS 5.0.0 (V14, V15, V16)
  - OWASP LLM02:2025 / LLM08:2025
  - EU GDPR Art. 5/25/32 & Quebec Law 25 (P-39.1)
cpu_rules:
- rule_id: SEC-DATA-LOG-001
  canonical_id: security-governance:data-isolation-pii:SEC-DATA-LOG-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-DATA-LOG-001
  severity: BLOCKER
  cwe_ids:
  - CWE-532
  - CWE-312
  sarif_security_severity_min: 8.5
  source_id: SRC-OWASP-ASVS-5
- rule_id: SEC-DATA-PII-001
  canonical_id: security-governance:data-isolation-pii:SEC-DATA-PII-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-DATA-PII-001
  severity: MAJOR
  cwe_ids:
  - CWE-359
  - CWE-532
  sarif_security_severity_min: 6.4
  source_id: SRC-GDPR-2016
semantic_invariants:
- invariant_id: SEM-DPI-01
  canonical_id: security-governance:data-isolation-pii:SEM-DPI-01
  severity: BLOCKER
  cwe_ids:
  - CWE-359
  - CWE-200
  - CWE-284
  diff_check: Verify outbound external LLM payloads scrub PII/secrets prior to egress, and shared caches/vector-DB RAG queries
    inject verified tenant_id + ACL namespace filters.
  false_positive_exemption: Exempt VPC-isolated self-hosted LLM endpoints with zero external egress or single-tenant deployments
    declared in manifest.
  requires_cross_model_auditor: true
  source_id: SRC-GDPR-2016
evidence_contribution_mappings:
- framework: nist_ai_rmf
  control_ref: NIST AI 100-1 (MAP 1, MEASURE 2) & NIST AI 600-1
  contribution_scope: contributes pre-merge evidence toward preventing PII/credential disclosure in logs, vector stores, and
    external LLM egress.
  evidence_artifact: tools/sec_cpu_scanner.py JSON + semgrep SARIF + Clean-Room audit report
  source_id: SRC-NIST-AI-RMF
primary_sources:
- source_id: SRC-OWASP-ASVS-5
  title: OWASP Application Security Verification Standard (ASVS) 5.0.0
  publisher: OWASP Foundation
  version_or_date: '2025-05-30'
  identifier_type: official_url
  url_or_doi: https://asvs.owasp.org/
- source_id: SRC-GDPR-2016
  title: Regulation (EU) 2016/679 (General Data Protection Regulation)
  publisher: European Union (EUR-Lex)
  version_or_date: '2016-04-27'
  identifier_type: eur_lex_celex
  url_or_doi: https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32016R0679
- source_id: SRC-NIST-AI-RMF
  title: 'NIST AI 100-1: Artificial Intelligence Risk Management Framework (AI RMF 1.0)'
  publisher: NIST
  version_or_date: 2023-01
  identifier_type: doi
  url_or_doi: https://doi.org/10.6028/NIST.AI.100-1
---

# PII & Credential Log Isolation, Client Storage, LLM Egress Redaction & Privacy Defaults (`data-isolation-pii`, Lazy On-Demand Reference)

## Exploit Mechanics & Threat Model
- STRIDE coverage: Information Disclosure, Tampering.
- Standard anchors: OWASP Top 10:2025 (A01, A04, A09), OWASP ASVS 5.0.0 (V14, V15, V16), OWASP LLM02:2025 / LLM08:2025, EU GDPR Art. 5/25/32 & Quebec Law 25 (P-39.1).

## Deterministic CPU vs. Clean-Room Semantic Split
- Deterministic CPU rules (`TOOL_VERIFIED`): security-governance:data-isolation-pii:SEC-DATA-LOG-001, security-governance:data-isolation-pii:SEC-DATA-PII-001.
- Clean-Room semantic invariants (`STATIC_LLM_INFERRED`): security-governance:data-isolation-pii:SEM-DPI-01.

## Scope & Governance Boundary
- Findings contribute pre-merge technical evidence only and do not constitute formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA` are `OUT_OF_SCOPE`).
