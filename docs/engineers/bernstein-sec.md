---
slug: "bernstein-sec"
tier: "LINDY_CANON"
primary_axis: "E"
axis_label: "Misuse-Resistant Cryptographic Engineering, Constant-Time Hygiene & Process Compartmentalization"
polymath_facet: true
polymath_scope: "Security-only facet: cryptographic API misuse-resistance, verification-order/side-channel elimination, and UID-isolated daemon boundaries."
sibling_handoffs:
  systems-harness: "Pure performance tuning, dependency modularity, and build-system engineering."
  verification-eval: "Formal verification harnesses and cryptographic test-vector execution."
verified_sources: ["SRC-BERNSTEIN-2012", "SRC-BERNSTEIN-2006", "SRC-BERNSTEIN-2005", "SRC-BERNSTEIN-2007", "SRC-MARLINSPIKE-2011", "SRC-RFC8439", "SRC-RFC8725", "SRC-RFC9106"]
bound_auditor_rules: ["authz-05"]
---

# Authority Dossier: `bernstein-sec` (Offline Reference)

**Axiomatic Failure Model:** Cryptographic and daemon breaches stem from footgun-laden APIs exposing unauthenticated modes or algorithm negotiation, performing decryption/parsing prior to MAC verification, branching or indexing memory on secret data, colliding nonces, and executing untrusted parsers inside monolithic privileged processes.

## Non-SAST Pre-Merge Invariants (6)

| Invariant ID | Falsifiable Pre-Merge Predicate (Violation Condition) | Why Deterministic CPU Scanners Miss It | Severity | Source ID |
|---|---|---|---|---|
| `bernstein-sec-inv-01` | Custom cryptographic or token wrapper code decrypts/parses ciphertext before verifying an authentication tag (violating Encrypt-then-MAC / AEAD), compares MACs/secrets non-constant-time, or allows attacker-driven algorithm negotiation (unpinned JWT `alg`). | Generic SAST catches banned primitives (MD5) but misses verification ordering across wrappers, custom equality logic, and context-dependent JWT header trust. | `BLOCKER` | `SRC-BERNSTEIN-2012` |
| `bernstein-sec-inv-02` | Secret-processing routines permit data flow from keys, tokens, or plaintexts into branch conditions or array/load indices, creating timing or cache-timing side channels. | Secret-to-branch and secret-to-index flows across custom helpers exceed regex/AST SAST coverage. | `BLOCKER` | `SRC-BERNSTEIN-2012` |
| `bernstein-sec-inv-03` | AEAD or stream-cipher wrappers (ChaCha20-Poly1305, AES-GCM) derive nonces from static values, unpersisted counters, or collision-prone sources under a shared key. | Nonce uniqueness across restarts, retries, or horizontally scaled workers is a stateful architectural property invisible to static patterns. | `BLOCKER` | `SRC-BERNSTEIN-2005` |
| `bernstein-sec-inv-04` | Internal crypto wrappers expose raw primitive knobs (cipher mode, padding, MAC toggle) to application developers instead of a single misuse-resistant high-level API (`crypto_box`/`crypto_secretbox` pattern). | Evaluating API abstraction safety and default-combination footguns requires architectural review. | `MAJOR` | `SRC-BERNSTEIN-2012` |
| `bernstein-sec-inv-05` | Network-facing parsers, untrusted media/archive decoders, or external executors run under the same OS UID/process/credential boundary as secret stores or root privileges (`qmail` compartmentalization violation). | Privilege separation spans Dockerfiles, service wrappers, and IPC entrypoints across files. | `BLOCKER` | `SRC-BERNSTEIN-2007` |
| `bernstein-sec-inv-06` | Key-exchange or credential-hashing code selects non-vetted/timing-sensitive primitives over constant-time defaults (Curve25519 ECDH, ChaCha20-Poly1305) or hashes low-entropy user passwords without a memory-hard KDF (Argon2, RFC 9106). | Distinguishing high-entropy API token digests from low-entropy user passwords requires semantic data classification. | `MAJOR` | `SRC-BERNSTEIN-2006` |

## Scope & Handoff

Strictly governs crypto misuse-resistance, side-channel hygiene, and privilege separation in `security-governance`; performance optimization routes to `systems-harness` and test-vector validation to `verification-eval`.

## Primary Sources

- `SRC-BERNSTEIN-2012`: Bernstein, D. J., Lange, T., & Schwabe, P. (2012). *The Security Impact of a New Cryptographic Library*. LATINCRYPT 2012. DOI: `10.1007/978-3-642-33481-8_9`.
- `SRC-BERNSTEIN-2006`: Bernstein, D. J. (2006). *Curve25519*. PKC 2006. DOI: `10.1007/11745853_14`.
- `SRC-BERNSTEIN-2005`: Bernstein, D. J. (2005). *The Poly1305-AES Message-Authentication Code*. FSE 2005. DOI: `10.1007/11502760_3`.
- `SRC-BERNSTEIN-2007`: Bernstein, D. J. (2007). *Some Thoughts on Security After Ten Years of qmail 1.0*. ACM CSAW. DOI: `10.1145/1314466.1314467`.
- `SRC-MARLINSPIKE-2011`: Marlinspike, M. (2011). *The Cryptographic Doom Principle* (`https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html`).
