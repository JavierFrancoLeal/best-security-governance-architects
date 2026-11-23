---
module_id: agentic-ai-threats
suite_id: security-governance
max_bytes: 2600
synthesis_mode: conjunctive_gate
auditor_refs: [auditor-agentic-abuse]
handoff_targets: [verification-eval]
---

# BRIEF: `agentic-ai-threats`

**Scope & Triggers:** LLM orchestrators, agent graphs, tool handlers, system prompts, `.mcp.json`, `mcp/**`, `agents/**`, `prompts/**`, `RAG` pipelines.

**Mandatory CPU Gate (Fail-Closed):**
- Run `python3 ./tools/sec_cpu_scanner.py --root . --format json` + Tier B SARIF (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`) via `python3 ./tools/sarif_ingest.py`.
- Missing required tool -> `UNVERIFIED_MISSING_TOOL` (`security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE`, cap verdict at `ITERATE`).

**Conjunctive Gate Checklist:**
- [BLOCKER] `SEC-AGT-PROMPTGUARD-001`: Zero prompt-only safety barriers over prod DBs/tools; enforce deterministic runtime RBAC/allowlist (`sec_cpu_scanner` + `auditor-agentic-abuse`).
- [BLOCKER] `SEC-AGT-OUTEXEC-001`: Zero raw LLM completion output routed into `eval`/`exec`/`new Function` (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEC-AGT-OUTEXEC-002`: Zero raw LLM completion output routed into `subprocess(..., shell=True)` or OS shell (`sec_cpu_scanner` + `semgrep`).
- [BLOCKER] `SEM-TRIFECTA-001`: Break Lethal Trifecta (private data + untrusted input + outbound tool); pin MCP tool schemas (`auditor-agentic-abuse`).

**Deduplication & Boundaries:**
- Count each root cause at `(file, line, agentic-ai-threats)` once at highest severity.
- Escalate cross-suite defects cleanly (`handoff_targets: [verification-eval]`) without duplicating sibling rules.
