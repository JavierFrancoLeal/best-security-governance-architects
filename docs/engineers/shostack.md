---
slug: "shostack"
tier: "LINDY_CANON"
primary_axis: "C"
axis_label: "Pre-Merge Threat Modeling, Trust Boundaries & Data-Flow Integrity"
polymath_facet: false
verified_sources: ["SRC-SHOSTACK-2014", "SRC-SHOSTACK-2008", "SRC-TMM-2020"]
bound_auditor_rules: ["authz-03"]
---

# Authority Dossier: `shostack` (Offline Reference)

**Axiomatic Failure Model:** Architectural security defects enter codebases whenever a PR adds or modifies a Data Flow Diagram (DFD) process, external entity, data store, or trust-boundary crossing without explicitly mitigating spoofing, tampering, disclosure, denial of service, and privilege escalation at that boundary.

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `shostack-inv-01` | Structured payloads crossing an untrusted boundary (client JSON, webhook, third-party API response) bind directly to internal models or serialize raw entities without field-level allowlist projection (BOPLA / mass assignment). | Object spread and ORM binding syntax are idiomatic; distinguishing privileged fields (`role`, `is_admin`) requires domain schema semantics. | `MAJOR` | `SRC-SHOSTACK-2014` |
| `shostack-inv-02` | A PR introduces a new endpoint, IPC channel, external integration, or data store crossing a trust boundary without authentication, integrity checks, and resource limits. | Static scanners do not know which architectural components define distinct trust boundaries in a custom topology. | `MAJOR` | `SRC-SHOSTACK-2008` |
| `shostack-inv-03` | Responses from third-party APIs (OWASP API10:2023) receive higher implicit trust than user input, bypassing schema validation, SSRF URI allowlists, or output encoding. | Default taint configurations mark inbound HTTP requests but omit upstream SaaS/webhook responses treated as trusted. | `BLOCKER` | `SRC-SHOSTACK-2014` |
| `shostack-inv-04` | Economically sensitive or abuse-prone flows (OTP dispatch, credential reset, paid LLM inference, inventory reservation) omit flow-specific throttling or anti-automation controls (API4/API6:2023). | Recognizing which handlers wrap sensitive business flows requires business-intent comprehension. | `MAJOR` | `SRC-SHOSTACK-2014` |
| `shostack-inv-05` | Code relies on unverified environmental assumptions (e.g., "gateway strips header X" or "service is internal-only") without enforcing verification at the receiving trust boundary. | Implicit deployment assumptions exist outside single-file AST patterns and break silently across environments. | `MAJOR` | `SRC-TMM-2020` |
| `shostack-inv-06` | Deprecated, shadow, or debug API routes remain exposed alongside production endpoints without deprecation gates or equivalent authentication controls (API9:2023). | Static route inspection cannot separate intentional public endpoints from forgotten debug surfaces without spec intent. | `MAJOR` | `SRC-SHOSTACK-2008` |

## Scope & Handoff

Triggers on new endpoints, webhooks, third-party API consumers, DTO/serializers, and service boundaries. Escalate contradictory security requirements or unmodeled assumptions to `spec-context`.

## Primary Sources

- `SRC-SHOSTACK-2014`: Shostack, A. (2014). *Threat Modeling: Designing for Security*. Wiley. ISBN: `978-1-118-80999-0`.
- `SRC-SHOSTACK-2008`: Shostack, A. (2008). *Experiences Threat Modeling at Microsoft*. CEUR-WS Vol. 413, Paper 12 (`https://ceur-ws.org/Vol-413/paper12.pdf`).
- `SRC-TMM-2020`: Braiterman, Z., Shostack, A., et al. (2020). *Threat Modeling Manifesto* (`https://www.threatmodelingmanifesto.org/`).
