---
slug: "anderson"
tier: "LINDY_CANON"
primary_axis: "B"
axis_label: "Security Economics, Bookkeeping Integrity & Composed API Abuse"
polymath_facet: false
verified_sources: ["SRC-ANDERSON-2020", "SRC-ANDERSON-2001", "SRC-ANDERSON-1994", "SRC-BOND-ANDERSON-2001"]
bound_auditor_rules: ["authz-04", "authz-07"]
---

# Authority Dossier: `anderson` (Offline Reference)

**Axiomatic Failure Model:** Deployed systems typically fail not from broken cipher math, but from misaligned liability incentives, missing bookkeeping/audit trails, leaky multi-tenant boundaries, flawed operational recovery procedures, and composable API sequences where individually authorized operations combine to violate global invariants.

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `anderson-inv-01` | Multi-tenant queries, shared caches, or billing/ledger endpoints allow cross-tenant observation or trust client-supplied prices, balances, or liability flags without server-authoritative computation. | ORM queries and arithmetic expressions are syntactically valid; tenant isolation and authoritative ledger boundaries exist strictly in domain logic. | `BLOCKER` | `SRC-ANDERSON-2020` |
| `anderson-inv-02` | Individually authorized API endpoints or stateful operations can be composed out-of-order, replayed, or invoked concurrently to extract protected values or violate workflow invariants. | SAST checks single-call shapes and local taint; multi-call API composition and concurrent TOCTOU races require behavioral state reasoning. | `MAJOR` | `SRC-BOND-ANDERSON-2001` |
| `anderson-inv-03` | Security-critical financial or account-dispute mutations lack immutable, attributable bookkeeping records, externalizing loss and proof burdens onto end users. | Absent audit-trail emission on specific domain state changes is an omission defect with no AST signature. | `MAJOR` | `SRC-ANDERSON-2001` |
| `anderson-inv-04` | Key-lifecycle, credential-recovery, or support-override flows allow operational bypasses or weak secret handling despite strong underlying cryptographic primitives. | Scanners validate algorithm names (e.g., AES-256), not operational recovery logic that circumvents cryptography. | `BLOCKER` | `SRC-ANDERSON-1994` |
| `anderson-inv-05` | Aggregate reporting, error differentiation, or query endpoints permit inference of confidential individual records across repeated requests or unfiltered joins. | Inference-control flaws emerge from schema design and query semantics rather than syntactic injection sinks. | `MAJOR` | `SRC-ANDERSON-2020` |
| `anderson-inv-06` | Defensive controls create unworkable operator/user friction or opaque warnings that predictably incentivize bypasses (e.g., blanket TLS skip flags, shared admin keys, rubber-stamp clicks). | Sociotechnical bypass ergonomics cannot be detected via static AST patterns. | `MAJOR` | `SRC-ANDERSON-2020` |

## Scope & Handoff

Triggers on billing/ledger services, multi-tenant stores, stateful workflow APIs, and audit logging. Escalate confirmation-dialog usability issues to `ui-ux` (under `security-governance` precedence) and concurrency tests to `verification-eval`.

## Primary Sources

- `SRC-ANDERSON-2020`: Anderson, R. (2020). *Security Engineering* (3rd ed.). Wiley. ISBN: `978-1-119-64278-7`.
- `SRC-ANDERSON-2001`: Anderson, R. (2001). *Why Information Security is Hard - An Economic Perspective*. ACSAC. DOI: `10.1109/ACSAC.2001.991552`.
- `SRC-ANDERSON-1994`: Anderson, R. (1994). *Why Cryptosystems Fail*. CACM 37(11), 32-40. DOI: `10.1145/188280.188291`.
- `SRC-BOND-ANDERSON-2001`: Bond, M., & Anderson, R. (2001). *API-Level Attacks on Embedded Systems*. IEEE Computer 34(10), 67-75. DOI: `10.1109/2.955101`.
