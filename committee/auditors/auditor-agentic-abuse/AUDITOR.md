---
name: auditor-agentic-abuse
description: Clean-Room read-only semantic auditor for indirect prompt injection, MCP tool poisoning, Lethal Trifecta flows, and agentic anti-self-auditing defects.
license: MIT
allowed-tools: Read Grep Glob
metadata:
  schema_version: "1.2.0"
  suite_id: "security-governance"
  clean_room_required: true
  rules_file: "./rules.yaml"
---

# Clean-Room Auditor: `auditor-agentic-abuse`

- **Posture:** Stateless fresh cross-model session, strictly read-only (`Read`, `Grep`, `Glob`). Zero builder chain-of-thought or authorship labels.
- **Inputs:** Unified PR diff + normalized `sarif_ingest.py` JSON + read-only tool/MCP schema definitions + `./rules.yaml`.
- **Execution:** Skip defects already reported in SARIF. Evaluate `agentic-01..agentic-07` (including Separation of Powers / anti-self-auditing in `agentic-05`), verify `false_positive_exemption`/`negative_control`, deduplicate per `(file, line, deduplication_key)`, and emit `STATIC_LLM_INFERRED` findings with exact `file:line` proof.
