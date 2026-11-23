---
schema_version: 1.2.0
module_identity:
  slug: injection-input-validation
  domain: SQL/NoSQL, XSS/DOM, SSTI/Eval, OS Command, SSRF, Path Traversal & Deserialization
  stride_categories:
  - Tampering
  - Elevation of Privilege
  - Denial of Service
  standard_anchors:
  - OWASP Top 10:2025 (A01, A05, A08)
  - OWASP API Security Top 10:2023 (API7)
  - OWASP ASVS 5.0.0 (V1, V5, V15)
cpu_rules:
- rule_id: SEC-INJ-SQLI-001
  canonical_id: security-governance:injection-input-validation:SEC-INJ-SQLI-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-INJ-SQLI-001
  severity: BLOCKER
  cwe_ids:
  - CWE-89
  - CWE-943
  sarif_security_severity_min: 9.4
  source_id: SRC-MITRE-CWE-89
- rule_id: SEC-INJ-XSS-001
  canonical_id: security-governance:injection-input-validation:SEC-INJ-XSS-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-INJ-XSS-001
  severity: BLOCKER
  cwe_ids:
  - CWE-79
  sarif_security_severity_min: 7.5
  source_id: SRC-OWASP-ASVS-5
- rule_id: SEC-INJ-CMD-001
  canonical_id: security-governance:injection-input-validation:SEC-INJ-CMD-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-INJ-CMD-001
  severity: BLOCKER
  cwe_ids:
  - CWE-78
  - CWE-77
  sarif_security_severity_min: 9.3
  source_id: SRC-MITRE-CWE-78
- rule_id: SEC-INJ-SSRF-001
  canonical_id: security-governance:injection-input-validation:SEC-INJ-SSRF-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-INJ-SSRF-001
  severity: BLOCKER
  cwe_ids:
  - CWE-918
  sarif_security_severity_min: 8.6
  source_id: SRC-OWASP-ASVS-5
- rule_id: SEC-INJ-DESER-001
  canonical_id: security-governance:injection-input-validation:SEC-INJ-DESER-001
  engine: semgrep
  engine_rule_ref: p/owasp-top-ten
  severity: BLOCKER
  cwe_ids:
  - CWE-502
  - CWE-611
  - CWE-22
  sarif_security_severity_min: 9.1
  source_id: SRC-OWASP-ASVS-5
semantic_invariants:
- invariant_id: SEM-SSRFDIFF-001
  canonical_id: security-governance:injection-input-validation:SEM-SSRFDIFF-001
  severity: BLOCKER
  cwe_ids:
  - CWE-918
  - CWE-436
  diff_check: Verify outbound URL validators and downstream HTTP clients use one canonical RFC-compliant parser blocking userinfo
    differentials, IPv4-mapped IPv6 loopback, DNS rebinding, and unvalidated redirects.
  false_positive_exemption: Exempt outbound calls routed through a hardcoded destination host or verified egress proxy blocking
    private/metadata IP ranges.
  requires_cross_model_auditor: true
  source_id: SRC-OWASP-ASVS-5
evidence_contribution_mappings:
- framework: nist_ssdf
  control_ref: NIST SP 800-218 v1.1 (PW.7, PW.8, PW.9)
  contribution_scope: contributes pre-merge evidence toward automated static injection detection and input-boundary sanitization
    verification.
  evidence_artifact: tools/sec_cpu_scanner.py JSON + semgrep SARIF + Verdict Envelope v1.2.0
  source_id: SRC-NIST-SSDF
primary_sources:
- source_id: SRC-MITRE-CWE-89
  title: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command'
  publisher: MITRE Corporation
  version_or_date: CWE Latest
  identifier_type: official_url
  url_or_doi: https://cwe.mitre.org/data/definitions/89.html
- source_id: SRC-MITRE-CWE-78
  title: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command'
  publisher: MITRE Corporation
  version_or_date: CWE Latest
  identifier_type: official_url
  url_or_doi: https://cwe.mitre.org/data/definitions/78.html
- source_id: SRC-OWASP-ASVS-5
  title: OWASP Application Security Verification Standard (ASVS) 5.0.0
  publisher: OWASP Foundation
  version_or_date: '2025-05-30'
  identifier_type: official_url
  url_or_doi: https://asvs.owasp.org/
- source_id: SRC-NIST-SSDF
  title: 'NIST SP 800-218: Secure Software Development Framework (SSDF) Version 1.1'
  publisher: NIST
  version_or_date: 2022-02
  identifier_type: doi
  url_or_doi: https://doi.org/10.6028/NIST.SP.800-218
---

# SQL/NoSQL, XSS/DOM, SSTI/Eval, OS Command, SSRF, Path Traversal & Deserialization (`injection-input-validation`, Lazy On-Demand Reference)

## Exploit Mechanics & Threat Model
- STRIDE coverage: Tampering, Elevation of Privilege, Denial of Service.
- Standard anchors: OWASP Top 10:2025 (A01, A05, A08), OWASP API Security Top 10:2023 (API7), OWASP ASVS 5.0.0 (V1, V5, V15).

## Deterministic CPU vs. Clean-Room Semantic Split
- Deterministic CPU rules (`TOOL_VERIFIED`): security-governance:injection-input-validation:SEC-INJ-SQLI-001, security-governance:injection-input-validation:SEC-INJ-XSS-001, security-governance:injection-input-validation:SEC-INJ-CMD-001, security-governance:injection-input-validation:SEC-INJ-SSRF-001, security-governance:injection-input-validation:SEC-INJ-DESER-001.
- Clean-Room semantic invariants (`STATIC_LLM_INFERRED`): security-governance:injection-input-validation:SEM-SSRFDIFF-001.

## Scope & Governance Boundary
- Findings contribute pre-merge technical evidence only and do not constitute formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA` are `OUT_OF_SCOPE`).
