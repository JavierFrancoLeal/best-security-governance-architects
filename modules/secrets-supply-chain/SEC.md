---
schema_version: 1.2.0
module_identity:
  slug: secrets-supply-chain
  domain: Secrets Hygiene, Dependency CVEs, Supply-Chain Pinning, SBOM & SPDX Licenses
  stride_categories:
  - Information Disclosure
  - Tampering
  - Repudiation
  standard_anchors:
  - OWASP Top 10:2025 (A02, A03, A08)
  - OWASP ASVS 5.0.0 (V13.3.1, V15.2.4)
  - SLSA Specification v1.2 (Build & Source Tracks)
  - NIST SP 800-218 (SSDF v1.1)
  - SPDX Specification v2.3 Annex E / v3.0.1 (ISO/IEC 5962:2021)
cpu_rules:
- rule_id: SEC-CRED-001
  canonical_id: security-governance:secrets-supply-chain:SEC-CRED-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-CRED-001
  severity: BLOCKER
  cwe_ids:
  - CWE-798
  - CWE-321
  sarif_security_severity_min: 9.5
  source_id: SRC-MITRE-CWE-798
- rule_id: SEC-CRED-002
  canonical_id: security-governance:secrets-supply-chain:SEC-CRED-002
  engine: gitleaks
  engine_rule_ref: private-key
  severity: BLOCKER
  cwe_ids:
  - CWE-798
  - CWE-312
  sarif_security_severity_min: 9.1
  source_id: SRC-MITRE-CWE-798
- rule_id: SEC-CRED-003
  canonical_id: security-governance:secrets-supply-chain:SEC-CRED-003
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-CRED-003
  severity: MAJOR
  cwe_ids:
  - CWE-312
  - CWE-522
  sarif_security_severity_min: 6.5
  source_id: SRC-OWASP-ASVS-5
- rule_id: SEC-SUP-CVE-001
  canonical_id: security-governance:secrets-supply-chain:SEC-SUP-CVE-001
  engine: osv-scanner
  engine_rule_ref: osv-high-critical-fixed
  severity: BLOCKER
  cwe_ids:
  - CWE-1395
  - CWE-1104
  sarif_security_severity_min: 7.0
  source_id: SRC-NIST-SSDF
- rule_id: SEC-SUP-TAG-001
  canonical_id: security-governance:secrets-supply-chain:SEC-SUP-TAG-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-SUP-TAG-001
  severity: MAJOR
  cwe_ids:
  - CWE-494
  - CWE-829
  sarif_security_severity_min: 5.9
  source_id: SRC-SLSA-V1-2
- rule_id: SEC-SUP-LIC-001
  canonical_id: security-governance:secrets-supply-chain:SEC-SUP-LIC-001
  engine: trivy
  engine_rule_ref: trivy-license-policy
  severity: MAJOR
  cwe_ids:
  - CWE-1104
  sarif_security_severity_min: 4.0
  source_id: SRC-SPDX-V2-3
semantic_invariants:
- invariant_id: SEM-SSC-01
  canonical_id: security-governance:secrets-supply-chain:SEM-SSC-01
  severity: MAJOR
  cwe_ids:
  - CWE-345
  - CWE-353
  diff_check: Verify release workflows publishing deployable packages or container images emit hosted-platform signed SLSA
    v1.2 Build L2+ provenance and SPDX/CycloneDX SBOM artifacts.
  false_positive_exemption: Exempt ephemeral PR preview builds, local dev Dockerfiles, or private internal packages emitting
    no distributable artifact.
  requires_cross_model_auditor: true
  source_id: SRC-SLSA-V1-2
evidence_contribution_mappings:
- framework: slsa
  control_ref: SLSA v1.2 Build Track (L1-L3) & Source Track
  contribution_scope: contributes pre-merge evidence toward verifying workflow commit-SHA pinning, lockfile integrity, and
    container digest pinning.
  evidence_artifact: tools/sec_cpu_scanner.py JSON + osv-scanner SARIF + trivy SARIF
  source_id: SRC-SLSA-V1-2
- framework: oss_license_provenance
  control_ref: SPDX v2.3 Annex E / v3.0.1 (ISO/IEC 5962:2021)
  contribution_scope: contributes pre-merge evidence toward machine-readable SPDX license screening and third-party license
    compatibility.
  evidence_artifact: trivy license SARIF + SPDX header scan output
  source_id: SRC-SPDX-V2-3
- framework: nist_ssdf
  control_ref: NIST SP 800-218 v1.1 (PO.5, PS.3.2, PW.4.1, PW.4.4, RV.1.1)
  contribution_scope: contributes pre-merge evidence toward secret hygiene, third-party component vulnerability scanning,
    and provenance checks.
  evidence_artifact: gitleaks SARIF + osv-scanner SARIF + Verdict Envelope v1.2.0
  source_id: SRC-NIST-SSDF
primary_sources:
- source_id: SRC-MITRE-CWE-798
  title: 'CWE-798: Use of Hard-coded Credentials'
  publisher: MITRE Corporation
  version_or_date: CWE Latest
  identifier_type: official_url
  url_or_doi: https://cwe.mitre.org/data/definitions/798.html
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
- source_id: SRC-SLSA-V1-2
  title: SLSA Specification v1.2 (Build Track & Source Track)
  publisher: OpenSSF
  version_or_date: v1.2
  identifier_type: official_url
  url_or_doi: https://slsa.dev/spec/v1.2/
- source_id: SRC-SPDX-V2-3
  title: 'SPDX Specification v2.3 Annex E: Using SPDX Short Identifiers'
  publisher: Linux Foundation SPDX
  version_or_date: v2.3
  identifier_type: official_url
  url_or_doi: https://spdx.github.io/spdx-spec/v2.3/using-SPDX-short-identifiers-in-source-files/
---

# Secrets Hygiene, Dependency CVEs, Supply-Chain Pinning, SBOM & SPDX Licenses (`secrets-supply-chain`, Lazy On-Demand Reference)

## Exploit Mechanics & Threat Model
- STRIDE coverage: Information Disclosure, Tampering, Repudiation.
- Standard anchors: OWASP Top 10:2025 (A02, A03, A08), OWASP ASVS 5.0.0 (V13.3.1, V15.2.4), SLSA Specification v1.2 (Build & Source Tracks), NIST SP 800-218 (SSDF v1.1), SPDX Specification v2.3 Annex E / v3.0.1 (ISO/IEC 5962:2021).

## Deterministic CPU vs. Clean-Room Semantic Split
- Deterministic CPU rules (`TOOL_VERIFIED`): security-governance:secrets-supply-chain:SEC-CRED-001, security-governance:secrets-supply-chain:SEC-CRED-002, security-governance:secrets-supply-chain:SEC-CRED-003, security-governance:secrets-supply-chain:SEC-SUP-CVE-001, security-governance:secrets-supply-chain:SEC-SUP-TAG-001, security-governance:secrets-supply-chain:SEC-SUP-LIC-001.
- Clean-Room semantic invariants (`STATIC_LLM_INFERRED`): security-governance:secrets-supply-chain:SEM-SSC-01.

## Scope & Governance Boundary
- Findings contribute pre-merge technical evidence only and do not constitute formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA` are `OUT_OF_SCOPE`).
