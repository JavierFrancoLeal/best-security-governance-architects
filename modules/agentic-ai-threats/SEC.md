---
schema_version: 1.2.0
module_identity:
  slug: agentic-ai-threats
  domain: Prompt-Only Guards, Improper LLM Output Execution, MCP Tool Poisoning & Lethal Trifecta
  stride_categories:
  - Elevation of Privilege
  - Tampering
  - Information Disclosure
  - Denial of Service
  standard_anchors:
  - OWASP Top 10 for Agentic Applications for 2026 (ASI01-ASI10)
  - OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10)
  - MITRE ATLAS (AML.T0051, AML.T0053, AML.T0110)
  - MCP Specification Authorization & Local Server Security
cpu_rules:
- rule_id: SEC-AGT-PROMPTGUARD-001
  canonical_id: security-governance:agentic-ai-threats:SEC-AGT-PROMPTGUARD-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-AGT-PROMPTGUARD-001
  severity: BLOCKER
  cwe_ids:
  - CWE-1427
  - CWE-862
  sarif_security_severity_min: 8.6
  source_id: SRC-MITRE-CWE-1427
- rule_id: SEC-AGT-OUTEXEC-001
  canonical_id: security-governance:agentic-ai-threats:SEC-AGT-OUTEXEC-001
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-AGT-OUTEXEC-001
  severity: BLOCKER
  cwe_ids:
  - CWE-94
  - CWE-95
  sarif_security_severity_min: 9.5
  source_id: SRC-OWASP-AGENTIC-2026
- rule_id: SEC-AGT-OUTEXEC-002
  canonical_id: security-governance:agentic-ai-threats:SEC-AGT-OUTEXEC-002
  engine: sec_cpu_scanner
  engine_rule_ref: SEC-AGT-OUTEXEC-002
  severity: BLOCKER
  cwe_ids:
  - CWE-78
  sarif_security_severity_min: 9.3
  source_id: SRC-OWASP-AGENTIC-2026
semantic_invariants:
- invariant_id: SEM-TRIFECTA-001
  canonical_id: security-governance:agentic-ai-threats:SEM-TRIFECTA-001
  severity: BLOCKER
  cwe_ids:
  - CWE-284
  - CWE-1427
  diff_check: Verify no agent session combines private data access, untrusted external content ingestion, and uncheckpointed
    outbound communication/write tools in one context without Dual-LLM quarantine or deterministic approval (delegated to
    auditor-agentic-abuse).
  false_positive_exemption: Exempt quarantined tool-less Dual-LLM readers emitting strict typed schemas with HMAC-verified
    human approval gates on outbound actions.
  requires_cross_model_auditor: true
  source_id: SRC-OWASP-AGENTIC-2026
evidence_contribution_mappings:
- framework: eu_ai_act
  control_ref: Regulation (EU) 2024/1689 Art. 14 (Human oversight), Art. 15 (Robustness & cybersecurity)
  contribution_scope: contributes pre-merge evidence toward adversarial prompt/tool hardening and human-oversight gating on
    high-risk agentic actions.
  evidence_artifact: tools/sec_cpu_scanner.py JSON + auditor-agentic-abuse Clean-Room report + Verdict Envelope v1.2.0
  source_id: SRC-EU-AI-ACT-2024
- framework: nist_ai_rmf
  control_ref: NIST AI 600-1 Generative AI Profile (MEASURE 2, MANAGE 2)
  contribution_scope: contributes pre-merge evidence toward measuring and mitigating agentic tool-abuse and indirect prompt-injection
    risks.
  evidence_artifact: Normalized SARIF + Clean-Room cross-model findings
  source_id: SRC-NIST-AI-600-1
primary_sources:
- source_id: SRC-MITRE-CWE-1427
  title: 'CWE-1427: Improper Neutralization of Input Used for LLM Prompting'
  publisher: MITRE Corporation
  version_or_date: CWE Latest
  identifier_type: official_url
  url_or_doi: https://cwe.mitre.org/data/definitions/1427.html
- source_id: SRC-OWASP-AGENTIC-2026
  title: OWASP Top 10 for Agentic Applications for 2026
  publisher: OWASP GenAI Security Project
  version_or_date: '2025-12-09'
  identifier_type: official_url
  url_or_doi: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- source_id: SRC-EU-AI-ACT-2024
  title: Regulation (EU) 2024/1689 (Artificial Intelligence Act)
  publisher: European Union (EUR-Lex)
  version_or_date: '2024-06-13'
  identifier_type: eur_lex_celex
  url_or_doi: https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=OJ:L_202401689
- source_id: SRC-NIST-AI-600-1
  title: 'NIST AI 600-1: Generative Artificial Intelligence Profile'
  publisher: NIST
  version_or_date: 2024-07
  identifier_type: doi
  url_or_doi: https://doi.org/10.6028/NIST.AI.600-1
---

# Prompt-Only Guards, Improper LLM Output Execution, MCP Tool Poisoning & Lethal Trifecta (`agentic-ai-threats`, Lazy On-Demand Reference)

## Exploit Mechanics & Threat Model
- STRIDE coverage: Elevation of Privilege, Tampering, Information Disclosure, Denial of Service.
- Standard anchors: OWASP Top 10 for Agentic Applications for 2026 (ASI01-ASI10), OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10), MITRE ATLAS (AML.T0051, AML.T0053, AML.T0110), MCP Specification Authorization & Local Server Security.

## Deterministic CPU vs. Clean-Room Semantic Split
- Deterministic CPU rules (`TOOL_VERIFIED`): security-governance:agentic-ai-threats:SEC-AGT-PROMPTGUARD-001, security-governance:agentic-ai-threats:SEC-AGT-OUTEXEC-001, security-governance:agentic-ai-threats:SEC-AGT-OUTEXEC-002.
- Clean-Room semantic invariants (`STATIC_LLM_INFERRED`): security-governance:agentic-ai-threats:SEM-TRIFECTA-001.

## Scope & Governance Boundary
- Findings contribute pre-merge technical evidence only and do not constitute formal legal compliance or safety-critical certification (`DO-178C`, `ISO 26262`, `ASPICE 4.0`, `FDA CSA` are `OUT_OF_SCOPE`).
