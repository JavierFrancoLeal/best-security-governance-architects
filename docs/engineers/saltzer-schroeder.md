---
slug: "saltzer-schroeder"
tier: "LINDY_CANON"
primary_axis: "A"
axis_label: "Access Control, Complete Mediation & Privilege Isolation"
polymath_facet: false
verified_sources: ["SRC-SALTZER-1975", "SRC-SCHROEDER-1972", "SRC-HARDY-1988"]
bound_auditor_rules: ["authz-01", "authz-02", "agentic-02"]
---

# Authority Dossier: `saltzer-schroeder` (Offline Reference)

**Axiomatic Failure Model:** Protection collapses when access decisions rely on exclusion lists rather than fail-safe permission defaults, omit complete mediation on cached or indirect object lookups, permit lower-privilege rings to invoke elevated procedures without caller-ring verification, or allow a deputy to act on ambient authority rather than caller-bound capability.

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `saltzer-schroeder-inv-01` | A handler retrieving, mutating, or deleting a resource by user-controlled key lacks an active, non-stub object-ownership or policy predicate bound to the authenticated subject before data access. | Missing ownership predicates have no syntactic sink; custom ORM scopes and no-op dependency stubs evade generic AST rules. | `BLOCKER` | `SRC-SALTZER-1975` |
| `saltzer-schroeder-inv-02` | Access control falls back to allow-on-error, allow-on-unknown-role, or denylist exclusion instead of fail-safe default-deny permission checks. | Control-flow fallthrough across custom policy evaluators and exception handlers requires cross-file semantic intent analysis. | `BLOCKER` | `SRC-SALTZER-1975` |
| `saltzer-schroeder-inv-03` | Administrative or elevated-ring operations execute on shared user controllers or internal endpoints without verifying caller privilege ring/role on every gate entry. | Framework controller inheritance and implicit middleware registration cannot be judged privileged vs. public without domain semantics. | `BLOCKER` | `SRC-SCHROEDER-1972` |
| `saltzer-schroeder-inv-04` | Cached authorization decisions, pre-signed references, or memoized tokens bypass complete mediation following role revocation, tenant transfer, or ownership change. | Static scanners cannot model state-invalidation semantics linking cache TTLs to privilege-mutation endpoints. | `MAJOR` | `SRC-SALTZER-1975` |
| `saltzer-schroeder-inv-05` | An intermediary service or AI agent executes a caller-influenced action using broad ambient credentials instead of attenuating authority to a caller-bound, task-scoped capability. | Credential calls appear syntactically valid to gitleaks and semgrep; detecting confused-deputy delegation requires comparing caller authority to token scope. | `BLOCKER` | `SRC-SALTZER-1975` |
| `saltzer-schroeder-inv-06` | High-risk security mutations (key rotation, privilege grants, deletions) omit compromise-recording audit trails or bloat protection-critical mediation into scattered unverified helpers. | Omission of reliable compromise recording and architectural mediation complexity are non-syntactic governance properties. | `MAJOR` | `SRC-SALTZER-1975` |

## Scope & Handoff

Triggers on API controllers, auth middleware, RBAC/ABAC evaluators, and privileged deputies. Escalate missing negative authorization regression tests to `verification-eval` and contradictory role hierarchies to `spec-context`.

## Primary Sources

- `SRC-SALTZER-1975`: Saltzer, J. H., & Schroeder, M. D. (1975). *The Protection of Information in Computer Systems*. Proc. IEEE 63(9), 1278-1308. DOI: `10.1109/PROC.1975.9939`.
- `SRC-SCHROEDER-1972`: Schroeder, M. D., & Saltzer, J. H. (1972). *A Hardware Architecture for Implementing Protection Rings*. CACM 15(3), 157-170. DOI: `10.1145/361268.361275`.
- `SRC-HARDY-1988`: Hardy, N. (1988). *The Confused Deputy*. ACM SIGOPS OSR 22(4), 36-38. DOI: `10.1145/54289.871709`.
