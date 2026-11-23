---
module_id: crypto-key-management
suite_id: security-governance
max_bytes: 2600
synthesis_mode: conjunctive_gate
auditor_refs: [auditor-authz-intent]
handoff_targets: [verification-eval]
---

# BRIEF: `crypto-key-management`

**Scope & Triggers:** crypto helpers, TLS/HTTP/gRPC configs, password hashing, token generators, KMS/Vault/HSM adapters.

**Mandatory CPU Gate (Fail-Closed):**
- Run `python3 ./tools/sec_cpu_scanner.py --root . --format json` + Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 ./tools/sarif_ingest.py`.
- Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`).

**Conjunctive Gate Checklist:**
- [BLOCKER] `SEC-CRY-HASH-001`: Zero MD5/SHA-1/DES/3DES/RC4/ECB in security contexts; hash passwords with Argon2id/scrypt/bcrypt (`sec_cpu_scanner` + `semgrep`).
- [MAJOR] `SEC-CRY-PRNG-001`: Zero `Math.random()` / `random.*` / `math/rand` for tokens, keys, nonces, or salts (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEC-CRY-TLS-001`: Zero disabled TLS verification (`rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify: true`) (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEM-DOOM-001`: Enforce AEAD or Encrypt-then-MAC with constant-time verify BEFORE decrypt/unpad (`auditor-authz-intent` `authz-05`).

**Deduplication & Boundaries:**
- Count each root cause at `(file, line, crypto-key-management)` once at highest severity.
- Escalate cross-suite defects cleanly (`handoff_targets: [verification-eval]`) without duplicating sibling rules.
