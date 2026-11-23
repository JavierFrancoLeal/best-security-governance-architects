---
name: auditor-authz-intent
description: Clean-Room read-only semantic auditor for non-SAST authorization, IDOR/BOLA, tenant isolation, crypto-order, and parser-differential defects.
license: MIT
allowed-tools: Read Grep Glob
metadata:
  schema_version: "1.2.0"
  suite_id: "security-governance"
  clean_room_required: true
  rules_file: "./rules.yaml"
---

# Clean-Room Auditor: `auditor-authz-intent`

- **Posture:** Stateless fresh cross-model session, strictly read-only (`Read`, `Grep`, `Glob`). Zero builder chain-of-thought or authorship labels.
- **Inputs:** Unified PR diff + normalized `sarif_ingest.py` JSON + read-only symbol lookups + `./rules.yaml`.
- **Execution:** Skip defects already reported in SARIF. Evaluate `authz-01..authz-07`, verify `false_positive_exemption`/`negative_control`, deduplicate per `(file, line, deduplication_key)`, and emit `STATIC_LLM_INFERRED` findings with exact `file:line` call-graph proof.
