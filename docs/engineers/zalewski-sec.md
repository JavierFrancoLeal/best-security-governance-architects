---
slug: "zalewski-sec"
tier: "LINDY_CANON"
primary_axis: "F"
axis_label: "Web/Browser Origin Isolation, IPC/Renderer Boundaries & Parser-Differential Resistance"
polymath_facet: true
polymath_scope: "Security-only facet: origin/renderer isolation, parser/protocol differential elimination, and indirect reconnaissance resistance."
sibling_handoffs:
  verification-eval: "Coverage-guided fuzzing execution and dynamic test harnesses."
  ui-ux: "Client-side interaction ergonomics, perceived latency, and visual affordances."
verified_sources: ["SRC-ZALEWSKI-2011", "SRC-ZALEWSKI-2005", "SRC-ELECTRON-SEC", "SRC-SERIOT-JSON", "SRC-KETTLE-2019", "SRC-SASSAMAN-2013", "SRC-RFC8259", "SRC-RFC8785"]
bound_auditor_rules: ["authz-06"]
---

# Authority Dossier: `zalewski-sec` (Offline Reference)

**Axiomatic Failure Model:** Modern web, Electron/webview, and reverse-proxied API stacks fail along seams between layered parsers and origin boundaries — where Same-Origin Policy assumptions break on `about:blank`/`blob:` inheritance, generic preload/IPC bridges grant renderers native power, or two components parse duplicate JSON keys, URLs, or HTTP framing headers inconsistently.

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `zalewski-sec-inv-01` | Electron/webview preloads expose generic IPC forwarding (`invoke(channel, args)`), disable `contextIsolation`/`sandbox`, or `ipcMain` handlers omit strict `event.senderFrame.origin` allowlists (rejecting `null`, `about:blank`, `blob:`). | Dynamic channel names, helper indirection, and origin-inheritance edge cases evade static AST pattern matchers. | `BLOCKER` | `SRC-ZALEWSKI-2011` |
| `zalewski-sec-inv-02` | An auth/validation layer and a downstream service parse the same JSON, URL, or HTTP payload with divergent parsers without rejecting duplicate keys, userinfo ambiguity, invalid surrogates, or conflicting `Content-Length`/`Transfer-Encoding` framing. | Parser differentials exist strictly in the semantic gap between two services or libraries across files or languages. | `BLOCKER` | `SRC-ZALEWSKI-2011` |
| `zalewski-sec-inv-03` | User-uploaded files or untrusted HTML/SVG/document artifacts are hosted on the same authenticated origin as session credentials or without anti-content-sniffing controls and restrictive CSP (`script-src 'self'`, `object-src 'none'`). | Origin topology and cookie-compartmentalization consequences span reverse-proxy config, response headers, and frontend routes. | `BLOCKER` | `SRC-ZALEWSKI-2011` |
| `zalewski-sec-inv-04` | CORS, `postMessage`, `will-navigate`, or `shell.openExternal` handlers validate origins via wildcard `*`, substring/suffix regexes, or unvalidated untrusted URLs alongside credentials or native actions. | Semantic equivalence of custom origin predicates and downstream privilege scope requires cross-file flow analysis. | `BLOCKER` | `SRC-ZALEWSKI-2011` |
| `zalewski-sec-inv-05` | Authentication, lookup, or webhook handlers expose divergent status codes, response sizes, or timing branches enabling passive reconnaissance or indirect enumeration. | Comparing response observables across sibling execution paths is a semantic behavioral check, not a syntactic sink. | `MAJOR` | `SRC-ZALEWSKI-2005` |
| `zalewski-sec-inv-06` | Signed or hashed JSON payloads omit deterministic canonicalization (RFC 8785 JCS) or verify signatures over raw bytes while consuming re-serialized objects with divergent key order or numeric precision. | Detecting mismatch between signed byte representation and downstream parsed-field consumption requires cross-layer semantic tracing. | `MAJOR` | `SRC-ZALEWSKI-2011` |

## Scope & Handoff

Strictly governs web/origin isolation, desktop IPC boundaries, parser differentials, and passive reconnaissance in `security-governance`; fuzzing harnesses route to `verification-eval` and client UX ergonomics to `ui-ux`.

## Primary Sources

- `SRC-ZALEWSKI-2011`: Zalewski, M. (2011). *The Tangled Web*. No Starch Press. ISBN: `978-1-59327-388-0`.
- `SRC-ZALEWSKI-2005`: Zalewski, M. (2005). *Silence on the Wire*. No Starch Press. ISBN: `978-1-59327-046-9`.
- `SRC-SASSAMAN-2013`: Sassaman, L., Patterson, M. L., Bratus, S., & Locasto, M. E. (2013). *Security Applications of Formal Language Theory*. IEEE Systems Journal 7(3), 489-500. DOI: `10.1109/JSYST.2012.2222000`.
- `SRC-RFC8259`: IETF RFC 8259 (JSON). DOI: `10.17487/RFC8259`.
- `SRC-RFC8785`: IETF RFC 8785 (JCS). DOI: `10.17487/RFC8785`.
