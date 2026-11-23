---
schema_version: 1.2.0
module_identity:
  slug: crypto-key-management
  domain: Cryptographic Primitives, CSPRNG, TLS Validation, AEAD Composition & Password KDFs
  stride_categories:
  - Information Disclosure
  - Tampering
  standard_anchors:
  - OWASP Top 10:2025 (A04 Cryptographic Failures)
  - OWASP ASVS 5.0.0 (V6.5, V11, V12)
  - NIST SP 800-131A Rev. 2, SP 800-63B-4, IETF RFC 9106 / RFC 9325
cpu_rules:
- rule_id: SEC-CRY-HASH-001
  canonical_id: security-governance:crypto-key-management:SEC-CRY-HASH-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-CRY-HASH-001
  severity: BLOCKER
  cwe_ids:
  - CWE-327
  - CWE-328
  - CWE-916
  sarif_security_severity_min: 8.8
  source_id: SRC-NIST-SP-800-131A
- rule_id: SEC-CRY-PRNG-001
  canonical_id: security-governance:crypto-key-management:SEC-CRY-PRNG-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-CRY-PRNG-001
  severity: MAJOR
  cwe_ids:
  - CWE-330
  - CWE-338
  sarif_security_severity_min: 6.8
  source_id: SRC-OWASP-ASVS-5
- rule_id: SEC-CRY-TLS-001
  canonical_id: security-governance:crypto-key-management:SEC-CRY-TLS-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-CRY-TLS-001
  severity: BLOCKER
  cwe_ids:
  - CWE-295
  sarif_security_severity_min: 7.4
  source_id: SRC-RFC9325
semantic_invariants:
- invariant_id: SEM-DOOM-001
  canonical_id: security-governance:crypto-key-management:SEM-DOOM-001
  severity: BLOCKER
  cwe_ids:
  - CWE-347
  - CWE-353
  - CWE-208
  diff_check: Verify symmetric encryption uses AEAD (AES-GCM/ChaCha20-Poly1305) or Encrypt-then-MAC with constant-time MAC
    verification strictly BEFORE decryption/unpadding (delegated to auditor-authz-intent authz-05).
  false_positive_exemption: Exempt direct calls to vetted high-level AEAD APIs (libsodium crypto_aead_*, WebCrypto AES-GCM)
    using unique CSPRNG nonces.
  requires_cross_model_auditor: true
  source_id: SRC-RFC8439
evidence_contribution_mappings:
- framework: eu_dora_art9
  control_ref: Regulation (EU) 2022/2554 Art. 9(4)(d)
  contribution_scope: contributes pre-merge evidence toward strong cryptographic controls, TLS certificate validation, and
    key lifecycle hygiene.
  evidence_artifact: tools/sec_cpu_scanner.py JSON + semgrep SARIF + auditor-authz-intent Clean-Room report
  source_id: SRC-EU-DORA
primary_sources:
- source_id: SRC-NIST-SP-800-131A
  title: 'NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms'
  publisher: NIST
  version_or_date: 2019-03
  identifier_type: doi
  url_or_doi: https://doi.org/10.6028/NIST.SP.800-131Ar2
- source_id: SRC-RFC9325
  title: 'IETF RFC 9325 (BCP 195): Recommendations for Secure Use of TLS and DTLS'
  publisher: IETF
  version_or_date: 2022-11
  identifier_type: doi
  url_or_doi: https://doi.org/10.17487/RFC9325
- source_id: SRC-RFC8439
  title: 'IETF RFC 8439: ChaCha20 and Poly1305 for IETF Protocols'
  publisher: IETF
  version_or_date: 2018-06
  identifier_type: doi
  url_or_doi: https://doi.org/10.17487/RFC8439
- source_id: SRC-OWASP-ASVS-5
  title: OWASP Application Security Verification Standard (ASVS) 5.0.0
  publisher: OWASP Foundation
  version_or_date: '2025-05-30'
  identifier_type: official_url
  url_or_doi: https://asvs.owasp.org/
- source_id: SRC-EU-DORA
  title: Regulation (EU) 2022/2554 (Digital Operational Resilience Act)
  publisher: European Union (EUR-Lex)
  version_or_date: '2022-12-14'
  identifier_type: eur_lex_celex
  url_or_doi: https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng
---

# Cryptographic Primitives, CSPRNG, TLS Validation, AEAD Composition & Password KDFs (`crypto-key-management`, Lazy On-Demand Reference)

## Exploit Mechanics & Threat Model
- STRIDE coverage: Information Disclosure, Tampering.
- Standard anchors: OWASP Top 10:2025 (A04 Cryptographic Failures), OWASP ASVS 5.0.0 (V6.5, V11, V12), NIST SP 800-131A Rev. 2, SP 800-63B-4, IETF RFC 9106 / RFC 9325.

## Deterministic CPU vs. Clean-Room Semantic Split
- Deterministic CPU rules (`TOOL_VERIFIED`): security-governance:crypto-key-management:SEC-CRY-HASH-001, security-governance:crypto-key-management:SEC-CRY-PRNG-001, security-governance:crypto-key-management:SEC-CRY-TLS-001.
- Clean-Room semantic invariants (`STATIC_LLM_INFERRED`): security-governance:crypto-key-management:SEM-DOOM-001.

## Scope & Governance Boundary
- Findings contribute pre-merge technical evidence only and do not constitute formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA` are `OUT_OF_SCOPE`).
