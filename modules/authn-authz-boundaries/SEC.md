---
schema_version: 1.2.0
module_identity:
  slug: authn-authz-boundaries
  domain: Authentication, JWT/Sessions, CORS/CSRF, Object/Function AuthZ & Tenant Isolation
  stride_categories:
  - Spoofing
  - Elevation of Privilege
  - Information Disclosure
  standard_anchors:
  - OWASP Top 10:2025 (A01, A07)
  - OWASP API Security Top 10:2023 (API1, API2, API5)
  - OWASP ASVS 5.0.0 (V3, V6, V7, V8, V9)
  - IETF RFC 8725 (JWT BCP) & RFC 6265 (Cookies)
cpu_rules:
- rule_id: SEC-AUTH-JWT-001
  canonical_id: security-governance:authn-authz-boundaries:SEC-AUTH-JWT-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-AUTH-JWT-001
  severity: BLOCKER
  cwe_ids:
  - CWE-347
  - CWE-287
  sarif_security_severity_min: 9.1
  source_id: SRC-RFC8725
- rule_id: SEC-AUTH-CORS-001
  canonical_id: security-governance:authn-authz-boundaries:SEC-AUTH-CORS-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-AUTH-CORS-001
  severity: BLOCKER
  cwe_ids:
  - CWE-942
  sarif_security_severity_min: 8.1
  source_id: SRC-OWASP-ASVS-5
- rule_id: SEC-AUTH-COOKIE-001
  canonical_id: security-governance:authn-authz-boundaries:SEC-AUTH-COOKIE-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-AUTH-COOKIE-001
  severity: MAJOR
  cwe_ids:
  - CWE-614
  - CWE-1004
  - CWE-1275
  sarif_security_severity_min: 6.1
  source_id: SRC-RFC6265
- rule_id: SEC-ELC-CDP-001
  canonical_id: security-governance:authn-authz-boundaries:SEC-ELC-CDP-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-ELC-CDP-001
  severity: MAJOR
  cwe_ids:
  - CWE-306
  - CWE-346
  - CWE-94
  sarif_security_severity_min: 6.8
  source_id: SRC-OWASP-ASVS-5
semantic_invariants:
- invariant_id: SEM-IDOR-001
  canonical_id: security-governance:authn-authz-boundaries:SEM-IDOR-001
  severity: BLOCKER
  cwe_ids:
  - CWE-639
  - CWE-284
  - CWE-863
  diff_check: Verify every handler accepting a caller-supplied object ID binds verified principal.id and principal.tenant_id
    (or PostgreSQL FORCE RLS) prior to reading or mutating records (delegated to auditor-authz-intent).
  false_positive_exemption: 'Exempt intentionally public read-only catalog records explicitly tagged visibility: PUBLIC or
    queries guarded by verified FORCE RLS.'
  requires_cross_model_auditor: true
  source_id: SRC-OWASP-API-2023
- invariant_id: SEM-IPC-001
  canonical_id: security-governance:authn-authz-boundaries:SEM-IPC-001
  severity: BLOCKER
  cwe_ids:
  - CWE-346
  - CWE-441
  - CWE-862
  diff_check: Verify Electron/IPC handlers validate event.senderFrame.origin against an explicit allowlist, enforce realpath
    root confinement, and never trust renderer-supplied role claims.
  false_positive_exemption: Exempt narrow single-purpose IPC handlers validating senderFrame.origin against trusted app origins
    with zero arbitrary filesystem access.
  requires_cross_model_auditor: true
  source_id: SRC-OWASP-ASVS-5
evidence_contribution_mappings:
- framework: eu_dora_art9
  control_ref: Regulation (EU) 2022/2554 Art. 9(4)(c)-(d)
  contribution_scope: contributes pre-merge evidence toward access-rights mediation, strong authentication, and authorization
    boundary verification.
  evidence_artifact: tools/sec_cpu_scanner.py JSON + semgrep SARIF + auditor-authz-intent Clean-Room report
  source_id: SRC-EU-DORA
primary_sources:
- source_id: SRC-RFC8725
  title: 'IETF RFC 8725 (BCP 225): JSON Web Token Best Current Practices'
  publisher: IETF
  version_or_date: 2020-02
  identifier_type: doi
  url_or_doi: https://doi.org/10.17487/RFC8725
- source_id: SRC-RFC6265
  title: 'IETF RFC 6265: HTTP State Management Mechanism'
  publisher: IETF
  version_or_date: 2011-04
  identifier_type: doi
  url_or_doi: https://doi.org/10.17487/RFC6265
- source_id: SRC-OWASP-ASVS-5
  title: OWASP Application Security Verification Standard (ASVS) 5.0.0
  publisher: OWASP Foundation
  version_or_date: '2025-05-30'
  identifier_type: official_url
  url_or_doi: https://asvs.owasp.org/
- source_id: SRC-OWASP-API-2023
  title: 'OWASP API Security Top 10: 2023'
  publisher: OWASP Foundation
  version_or_date: '2023'
  identifier_type: official_url
  url_or_doi: https://api-security.owasp.org/editions/2023/en/0x11-t10/
- source_id: SRC-EU-DORA
  title: Regulation (EU) 2022/2554 (Digital Operational Resilience Act)
  publisher: European Union (EUR-Lex)
  version_or_date: '2022-12-14'
  identifier_type: eur_lex_celex
  url_or_doi: https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng
---

# Authentication, JWT/Sessions, CORS/CSRF, Object/Function AuthZ & Tenant Isolation (`authn-authz-boundaries`, Lazy On-Demand Reference)

## Exploit Mechanics & Threat Model
- STRIDE coverage: Spoofing, Elevation of Privilege, Information Disclosure.
- Standard anchors: OWASP Top 10:2025 (A01, A07), OWASP API Security Top 10:2023 (API1, API2, API5), OWASP ASVS 5.0.0 (V3, V6, V7, V8, V9), IETF RFC 8725 (JWT BCP) & RFC 6265 (Cookies).

## Deterministic CPU vs. Clean-Room Semantic Split
- Deterministic CPU rules (`TOOL_VERIFIED`): security-governance:authn-authz-boundaries:SEC-AUTH-JWT-001, security-governance:authn-authz-boundaries:SEC-AUTH-CORS-001, security-governance:authn-authz-boundaries:SEC-AUTH-COOKIE-001, security-governance:authn-authz-boundaries:SEC-ELC-CDP-001.
- Clean-Room semantic invariants (`STATIC_LLM_INFERRED`): security-governance:authn-authz-boundaries:SEM-IDOR-001, security-governance:authn-authz-boundaries:SEM-IPC-001.

## Scope & Governance Boundary
- Findings contribute pre-merge technical evidence only and do not constitute formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA` are `OUT_OF_SCOPE`).
