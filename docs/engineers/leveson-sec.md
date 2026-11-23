---
slug: "leveson-sec"
tier: "LINDY_CANON"
primary_axis: "D"
axis_label: "Systems-Theoretic Security Control Loops & Hierarchical Constraints (STAMP / STPA-Sec)"
polymath_facet: true
polymath_scope: "Security-only facet: adversarial control-loop subversion, stale security process models, unsafe actuation constraints, and Separation of Powers anti-self-auditing."
sibling_handoffs:
  systems-harness: "Non-adversarial structural architecture, reliability, and build/migration boundaries."
  spec-context: "Pre-implementation hazard/loss definitions when unacceptable losses are undefined."
verified_sources: ["SRC-LEVESON-2011", "SRC-LEVESON-2014"]
bound_auditor_rules: ["agentic-05"]
---

# Authority Dossier: `leveson-sec` (Offline Reference)

**Axiomatic Failure Model:** Unacceptable security losses arise even when every individual component meets its local specification whenever hierarchical control constraints are absent, feedback loops leave a controller operating on a stale process model, coupled controllers produce dysfunctional interactions, fallback paths migrate the system into a high-risk state, or a controlled builder entity is permitted to modify its own verification oracles or audit logs.

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `leveson-sec-inv-01` | An autonomous controller or AI agent triggers high-impact, irreversible actuations (deletions, credentialed external writes, financial transfers) without an independent deterministic control gate or explicit full-parameter human approval, OR holds write permissions over its own `tests/`, `evals/`, `rules.yaml`, policy files, or audit logs (self-auditing violation). | Static tools see standard SDK/CLI calls; verifying an independent non-LLM enforcement constraint and Separation of Powers requires control-structure reasoning. | `BLOCKER` | `SRC-LEVESON-2011` |
| `leveson-sec-inv-02` | A security controller (policy engine, authz cache, agent planner) acts on an inaccurate or stale process model because state-mutating writers omit mandatory synchronous feedback updates. | Missing feedback paths between mutating services and policy controllers span multiple modules and runtime states. | `MAJOR` | `SRC-LEVESON-2011` |
| `leveson-sec-inv-03` | Multiple individually compliant controllers issue conflicting actions on a shared security-critical resource without hierarchical priority enforcement (e.g., optimistic UI write racing server authz denial). | Component-level SAST cannot capture emergent dysfunctional interactions between coupled controllers. | `MAJOR` | `SRC-LEVESON-2014` |
| `leveson-sec-inv-04` | Security-critical actuations lack ordering preconditions or consumption/iteration bounds, permitting out-of-sequence execution or unbounded retry/spend loops (LLM10:2025). | Ordering and bounded-actuation loop constraints are dynamic control properties absent from syntactic patterns. | `MAJOR` | `SRC-LEVESON-2011` |
| `leveson-sec-inv-05` | Feature flags, degraded-mode fallbacks, or exception handlers silently migrate the system into a high-risk state by bypassing security policy enforcement on timeout or error. | Fail-open degradation semantics require evaluating fallback branches against unacceptable-loss constraints. | `BLOCKER` | `SRC-LEVESON-2014` |
| `leveson-sec-inv-06` | Human-in-the-loop override interfaces omit full target, payload, or privilege parameters, inducing operator process-model mismatch under adversarial obfuscation. | Static tools cannot verify whether an approval dialog faithfully exposes hidden arguments. | `MAJOR` | `SRC-LEVESON-2011` |

## Scope & Handoff

Strictly governs adversarial control-loop subversion, actuation constraints, and Separation of Powers in `security-governance`; non-adversarial structural coupling routes to `systems-harness`, and undefined loss criteria route to `spec-context`.

## Primary Sources

- `SRC-LEVESON-2011`: Leveson, N. G. (2011). *Engineering a Safer World: Systems Thinking Applied to Safety*. MIT Press. ISBN: `978-0-262-01662-9`; DOI: `10.7551/mitpress/8179.001.0001`.
- `SRC-LEVESON-2014`: Leveson, N. G. (2014). *An Integrated Approach to Safety and Security Based on Systems Theory*. CACM 57(2), 31-35. DOI: `10.1145/2556938`.
