---
module_id: authn-authz-boundaries
suite_id: security-governance
max_bytes: 2600
synthesis_mode: conjunctive_gate
auditor_refs: [auditor-authz-intent]
handoff_targets: [verification-eval, spec-context]
---

# BRIEF: `authn-authz-boundaries`

**Scope & Triggers:** routers, controllers, GraphQL/RPC resolvers, Electron preloads/IPC, auth middleware, JWT/OIDC, cookie/CORS/CSRF configs, RBAC policies.

**Mandatory CPU Gate (Fail-Closed):**
- Run `python3 ./tools/sec_cpu_scanner.py --root . --format json` + Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 ./tools/sarif_ingest.py`.
- Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`).

**Conjunctive Gate Checklist:**
- [BLOCKER] `SEC-AUTH-JWT-001`: Verify JWT cryptographic signature, single-family `algorithms` allowlist (no `none`), pinned JWKS, `exp`/`iss`/`aud` (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEC-AUTH-CORS-001`: Zero wildcard `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true` (`sec_cpu_scanner`).
- [MAJOR] `SEC-AUTH-COOKIE-001`: Session cookies MUST set `HttpOnly`, `Secure`, `SameSite=Lax|Strict`, and `__Host-` prefix (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEM-IDOR-001`: Zero IDOR/BOLA or missing tenant predicates; delegate deep AuthZ/BFLA audit to Clean-Room `auditor-authz-intent`.
- [BLOCKER] `SEM-IPC-001`: Electron/IPC handlers MUST validate `event.senderFrame.origin` and never trust renderer-supplied roles (`auditor-authz-intent`).

**Deduplication & Boundaries:**
- Count each root cause at `(file, line, authn-authz-boundaries)` once at highest severity.
- Escalate cross-suite defects cleanly (`handoff_targets: [verification-eval, spec-context]`) without duplicating sibling rules.
