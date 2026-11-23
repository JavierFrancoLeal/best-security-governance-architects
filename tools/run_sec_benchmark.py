#!/usr/bin/env python3
"""Two-Layer Security Governance Benchmark & EvalOps Calibration Harness (ECOSYSTEM_CONTRACT v1.2.0)."""
from __future__ import annotations

import argparse
import json
import math
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

Z_95 = 1.959963984540054
SEVERITY_RANK = {"BLOCKER": 3, "MAJOR": 2, "MINOR": 1}
CANONICAL_ID_RE = re.compile(r"^security-governance:[a-z0-9-]+:[A-Za-z0-9_-]+$")

CPU_GROUND_TRUTH: dict[str, dict[str, Any]] = {
    "tp_01_canary_secret.js": {"tp": True, "module": "secrets-supply-chain"},
    "tp_02_sqli_and_xss.js": {"tp": True, "module": "injection-input-validation"},
    "tp_03_cmd_injection_and_ssrf.py": {"tp": True, "module": "injection-input-validation"},
    "tp_04_weak_crypto_and_tls.js": {"tp": True, "module": "crypto-key-management"},
    "tp_05_pii_in_logs.js": {"tp": True, "module": "data-isolation-pii"},
    "tp_06_insecure_cookie_cors.js": {"tp": True, "module": "authn-authz-boundaries"},
    "tp_07_prompt_only_guard.js": {"tp": True, "module": "agentic-ai-threats"},
    "tp_08_llm_output_to_exec.py": {"tp": True, "module": "agentic-ai-threats"},
    "tp_09_privileged_container.yaml": {"tp": True, "module": "systemic-governance-audit"},
    "tp_10_unverified_jwt.js": {"tp": True, "module": "authn-authz-boundaries"},
    "tn_01_parameterized_and_escaped.js": {"tp": False, "module": "injection-input-validation"},
    "tn_02_sanitized_diagnostic_export.js": {"tp": False, "module": "secrets-supply-chain"},
    "tn_03_safe_agent_tool_allowlist.ts": {"tp": False, "module": "agentic-ai-threats"},
    "tn_04_secure_cookie_and_authz.js": {"tp": False, "module": "authn-authz-boundaries"},
}

SEMANTIC_GROUND_TRUTH: dict[str, dict[str, Any]] = {
    "sem_01_idor_missing_ownership.js": {"tp": True, "auditor": "auditor-authz-intent"},
    "sem_02_confused_deputy_ipc.js": {"tp": True, "auditor": "auditor-authz-intent"},
    "sem_03_crypto_doom_decrypt_first.py": {"tp": True, "auditor": "auditor-authz-intent"},
    "sem_04_parser_differential_ssrf.py": {"tp": True, "auditor": "auditor-authz-intent"},
    "sem_05_lethal_trifecta_agent.ts": {"tp": True, "auditor": "auditor-agentic-abuse"},
    "sem_06_self_auditing_governance.yaml": {"tp": True, "auditor": "auditor-agentic-abuse"},
    "sem_07_clean_tenant_isolated_authz.js": {"tp": False, "auditor": "auditor-authz-intent"},
    "sem_08_clean_checkpointed_agent.ts": {"tp": False, "auditor": "auditor-agentic-abuse"},
}


def wilson_ci(successes: int, total: int, z: float = Z_95) -> tuple[float, float]:
    """Compute exact 95% Wilson score confidence interval for binomial proportion."""
    if total <= 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1.0 + (z * z) / total
    center = (p + (z * z) / (2.0 * total)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p) / total) + (z * z) / (4.0 * total * total))
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def rogan_gladen_summary(p_obs: float, tpr: float, tnr: float, n_test: int, m1: int, m0: int) -> dict[str, Any]:
    """Compute Rogan-Gladen bias-corrected prevalence and delta-method 95% CI."""
    youden_j = tpr + tnr - 1.0
    if youden_j <= 0.30 or m1 <= 0 or m0 <= 0 or n_test <= 0:
        return {
            "youden_j": round(youden_j, 4),
            "advisory_only_fallback": True,
            "reason": "J <= 0.30 or insufficient calibration support; decline automated gating.",
        }
    theta_raw = (p_obs + tnr - 1.0) / youden_j
    theta_clip = max(0.0, min(1.0, theta_raw))
    var_sum = (
        (p_obs * (1.0 - p_obs)) / n_test
        + (theta_clip**2 * tpr * (1.0 - tpr)) / m1
        + ((1.0 - theta_clip) ** 2 * tnr * (1.0 - tnr)) / m0
    )
    se = math.sqrt(var_sum) / youden_j
    return {
        "youden_j": round(youden_j, 4),
        "se_inflation_factor": round(1.0 / youden_j, 3),
        "theta_raw": round(theta_raw, 4),
        "theta_clipped": round(theta_clip, 4),
        "ci_95": [round(max(0.0, theta_clip - Z_95 * se), 4), round(min(1.0, theta_clip + Z_95 * se), 4)],
        "advisory_only_fallback": theta_raw < 0.0 or theta_raw > 1.0,
    }


def deduplicate_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enforce ECOSYSTEM_CONTRACT §5.1.2 single-root-cause deduplication per (file, line, module)."""
    best: dict[tuple[str, int, str], dict[str, Any]] = {}
    for item in raw_findings:
        key = (Path(item["file"]).name, int(item.get("line", 0)), str(item.get("module_id") or item.get("module", "unknown")))
        sev = str(item.get("severity", "MINOR")).upper()
        if key not in best or SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(best[key]["severity"], 0):
            best[key] = {**item, "file": key[0], "line": key[1], "module": key[2], "severity": sev}
    return list(best.values())


def parse_sarif_findings(sarif_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize OASIS SARIF 2.1.0 results into canonical benchmark findings."""
    level_map = {"error": "BLOCKER", "warning": "MAJOR", "note": "MINOR", "none": "MINOR"}
    normalized: list[dict[str, Any]] = []
    for run in sarif_payload.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "unknown")
            line = phys.get("region", {}).get("startLine", 1)
            normalized.append({
                "file": Path(uri).name,
                "line": int(line),
                "module": "sarif-external",
                "rule_id": str(res.get("ruleId", "UNKNOWN")),
                "severity": level_map.get(str(res.get("level", "warning")), "MAJOR"),
            })
    return normalized


def validate_eval_suites(repo_root: Path, scanner: Path | None = None) -> list[str]:
    """Verify v1.1.0/v1.2.0 evals.json schema, trigger balance, canonical IDs, and live CPU scanner parity."""
    errors: list[str] = []
    eval_paths = sorted(
        list((repo_root / "modules").glob("*/evals/evals.json"))
        + list((repo_root / "committee").glob("*/evals/evals.json"))
    )
    if not eval_paths:
        return ["No evals.json files found under modules/*/evals/ or committee/*/evals/"]

    for path in eval_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        skill_name = str(data.get("skill_name", ""))
        if data.get("schema_version") not in {"1.1.0", "1.2.0"} or data.get("suite_id") != "security-governance":
            errors.append(f"{path}: invalid schema_version or suite_id")
        cases = data.get("evals", [])
        if len(cases) < 5:
            errors.append(f"{path}: fewer than 5 eval cases ({len(cases)})")
        pos = sum(1 for c in cases if c.get("should_trigger") is True)
        neg = sum(1 for c in cases if c.get("should_trigger") is False)
        if pos < 3 or neg < 2:
            errors.append(f"{path}: requires >=3 positive and >=2 negative cases (got {pos}/{neg})")
        for case in cases:
            fixture_abs = repo_root / case["fixture_path"]
            if not fixture_abs.exists():
                errors.append(f"{path}:{case['id']}: missing fixture {case['fixture_path']}")
                continue
            exp = case["expected_output"]
            for cid in exp["expected_canonical_ids"]:
                if not CANONICAL_ID_RE.match(cid):
                    errors.append(f"{path}:{case['id']}: malformed canonical ID {cid}")
            c = exp["expected_counts"]
            expected_verdict = "REJECT" if c["blocker"] >= 1 else "ITERATE" if c["major"] >= 1 else "SHIP"
            if exp["expected_evidence_tier"] == "UNVERIFIED_MISSING_TOOL" and exp["verdict"] == "SHIP":
                errors.append(f"{path}:{case['id']}: fail-closed violation (SHIP with missing tool)")
            elif exp["verdict"] != expected_verdict:
                errors.append(f"{path}:{case['id']}: verdict {exp['verdict']} != conjunctive {expected_verdict}")

            # Live CPU execution parity check for deterministic CPU eval cases
            if scanner and scanner.is_file() and case.get("layer") == "cpu" and case.get("case_type") != "fail_closed_tooling":
                cmd = [sys.executable, str(scanner), "--target", str(fixture_abs), "--format", "json"]
                if skill_name and skill_name != "security-director":
                    cmd.extend(["--module", skill_name])
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if proc.returncode not in (0, 2) or not proc.stdout.strip():
                    errors.append(f"{path}:{case['id']}: scanner failed rc={proc.returncode}")
                    continue
                out = json.loads(proc.stdout)
                actual_cids = sorted({f["canonical_id"] for f in out.get("findings", [])})
                expected_cids = sorted(exp["expected_canonical_ids"])
                actual_counts = out.get("counts", {})
                if actual_cids != expected_cids:
                    errors.append(f"{path}:{case['id']}: canonical_ids mismatch actual={actual_cids} expected={expected_cids}")
                if actual_counts != c:
                    errors.append(f"{path}:{case['id']}: counts mismatch actual={actual_counts} expected={c}")
    return errors


def run_layer1(cpu_dir: Path, sem_dir: Path, scanner: Path, use_semgrep: bool, use_gitleaks: bool) -> dict[str, Any]:
    """Execute deterministic CPU CI gate on 14 canary fixtures + SAST-zero check on semantic fixtures."""
    if not scanner.exists():
        return {
            "evidence_tier": "UNVERIFIED_MISSING_TOOL",
            "verdict": "ITERATE",
            "exit_code": 127,
            "blocking_ids": ["security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE"],
            "calibration_scope": "synthetic_canary_regression_floor",
            "synthetic_regression_gate_passed": False,
        }

    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, str(scanner), "--target", str(cpu_dir), "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    runtime_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    if proc.returncode not in (0, 2) or not proc.stdout.strip():
        return {
            "evidence_tier": "UNVERIFIED_MISSING_TOOL",
            "verdict": "ITERATE",
            "exit_code": proc.returncode,
            "blocking_ids": ["security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE"],
            "error": proc.stderr.strip()[:400],
            "synthetic_regression_gate_passed": False,
        }

    raw_findings = json.loads(proc.stdout).get("findings", [])
    if use_semgrep and shutil.which("semgrep"):
        sg = subprocess.run(["semgrep", "scan", "--sarif", "--config", "auto", str(cpu_dir)],
                            capture_output=True, text=True, check=False)
        if sg.stdout.strip().startswith("{"):
            raw_findings.extend(parse_sarif_findings(json.loads(sg.stdout)))
    if use_gitleaks and shutil.which("gitleaks"):
        gl = subprocess.run(["gitleaks", "dir", str(cpu_dir), "--report-format", "json", "--report-path", "-"],
                            capture_output=True, text=True, check=False)
        if gl.stdout.strip().startswith("["):
            for leak in json.loads(gl.stdout):
                raw_findings.append({
                    "file": Path(leak.get("File", "unknown")).name,
                    "line": int(leak.get("StartLine", 1)),
                    "module": "secrets-supply-chain",
                    "rule_id": f"security-governance:secrets-supply-chain:{leak.get('RuleID', 'GITLEAKS')}",
                    "severity": "BLOCKER",
                })

    deduped = deduplicate_findings(raw_findings)
    flagged_files = {f["file"] for f in deduped if f["severity"] in ("BLOCKER", "MAJOR")}

    tp = fp = tn = fn = 0
    per_mod: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    for fname, meta in CPU_GROUND_TRUTH.items():
        detected = fname in flagged_files
        idx = 0 if (meta["tp"] and detected) else 3 if meta["tp"] else 1 if detected else 2
        per_mod[meta["module"]][idx] += 1
        tp, fp, tn, fn = tp + (idx == 0), fp + (idx == 1), tn + (idx == 2), fn + (idx == 3)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    module_summary = {
        mod: {
            "tp": c[0], "fp": c[1], "tn": c[2], "fn": c[3],
            "recall": round(c[0] / (c[0] + c[3]), 4) if (c[0] + c[3]) else None,
            "fpr": round(c[1] / (c[1] + c[2]), 4) if (c[1] + c[2]) else None,
        }
        for mod, c in sorted(per_mod.items())
    }

    # Fail-closed SAST-zero precondition on Layer 2 semantic fixtures.
    sem_proc = subprocess.run([sys.executable, str(scanner), "--target", str(sem_dir), "--format", "json"],
                              capture_output=True, text=True, check=False)
    sem_ok = sem_proc.returncode in (0, 2) and bool(sem_proc.stdout.strip())
    sem_blockers = (
        [f for f in json.loads(sem_proc.stdout).get("findings", []) if f.get("severity") == "BLOCKER"]
        if sem_ok else [{"error": "semantic_sast_scan_failed"}]
    )

    gate_passed = recall == 1.0 and fpr == 0.0 and sem_ok and len(sem_blockers) == 0
    return {
        "evidence_tier": "TOOL_VERIFIED",
        "exit_code": proc.returncode,
        "calibration_scope": "synthetic_fixture_regression_floor_not_universal_production_precision",
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "youden_j": round(recall - fpr, 4),
        "wilson_ci_95": {"recall": wilson_ci(tp, tp + fn), "fpr": wilson_ci(fp, fp + tn)},
        "per_module": module_summary,
        "runtime_ms": runtime_ms,
        "semantic_sast_zero_verified": sem_ok and len(sem_blockers) == 0,
        "semantic_sast_blockers": sem_blockers,
        "synthetic_regression_gate_passed": gate_passed,
    }


def make_synthetic_diff(fixture_path: Path) -> str:
    lines = fixture_path.read_text(encoding="utf-8").splitlines()
    body = "\n".join(f"+{line}" for line in lines)
    return (
        f"diff --git a/{fixture_path.name} b/{fixture_path.name}\n"
        f"--- /dev/null\n+++ b/{fixture_path.name}\n@@ -0,0 +1,{len(lines)} @@\n{body}\n"
    )


def run_layer2(sem_dir: Path, semantic_cmd: str | None, trials: int) -> dict[str, Any]:
    if not semantic_cmd:
        return {
            "status": "skipped_no_runner",
            "calibration_scope": "smoke_set_requires_verification_eval_holdout",
            "escalation_required": True,
        }

    cmd_argv = shlex.split(semantic_cmd)
    item_verdicts: dict[str, list[bool]] = {}
    for fname, meta in SEMANTIC_GROUND_TRUTH.items():
        diff_text = make_synthetic_diff(sem_dir / fname)
        trial_flags: list[bool] = []
        for trial_idx in range(trials):
            payload = json.dumps({
                "clean_room_session": True,
                "trial_index": trial_idx,
                "auditor": meta["auditor"],
                "diff": diff_text,
                "layer1_findings": [],
            })
            proc = subprocess.run(cmd_argv, input=payload, capture_output=True, text=True, check=False)
            verdict_obj = json.loads(proc.stdout) if proc.returncode == 0 and proc.stdout.strip() else {"verdict": "ITERATE"}
            trial_flags.append(verdict_obj.get("verdict") == "REJECT")
        item_verdicts[fname] = trial_flags

    tp = fp = tn = fn = unstable_items = 0
    for fname, flags in item_verdicts.items():
        majority_flag = sum(flags) > (len(flags) / 2.0)
        if 0 < sum(flags) < len(flags):
            unstable_items += 1
        expected_tp = SEMANTIC_GROUND_TRUTH[fname]["tp"]
        tp += int(expected_tp and majority_flag)
        fn += int(expected_tp and not majority_flag)
        fp += int((not expected_tp) and majority_flag)
        tn += int((not expected_tp) and not majority_flag)

    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    return {
        "calibration_scope": "layer2_semantic_smoke_not_calibrated_holdout",
        "trials_per_item": trials,
        "item_counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "tpr": round(tpr, 4),
        "tnr": round(tnr, 4),
        "youden_j": round(tpr + tnr - 1.0, 4),
        "unstable_tail_items": unstable_items,
        "item_wilson_ci_95": {"tpr": wilson_ci(tp, tp + fn), "tnr": wilson_ci(tn, tn + fp)},
        "rogan_gladen_preview_n500": rogan_gladen_summary(0.25, tpr, tnr, 500, tp + fn, tn + fp),
        "escalation_required": True,
    }


def emit_verdict_envelope(layer1: dict[str, Any], layer2: dict[str, Any], cli_cmd: str) -> str:
    visited = ["security-governance"]
    escalations = []
    if "verification-eval" not in visited:
        escalations.append({
            "target_suite_id": "verification-eval",
            "reason": "Execute holdout Dev/Test calibration (m>=100/class) with Rogan-Gladen CIs.",
            "blocking_ids": ["security-governance:evalops:UNCALIBRATED_SEMANTIC_HOLDOUT_PENDING"],
            "artifact_slice": "tests/fixtures/semantic/*, modules/*/evals/evals.json",
        })
    l1_ok = layer1.get("synthetic_regression_gate_passed", False)
    missing_tool = layer1.get("evidence_tier") == "UNVERIFIED_MISSING_TOOL"
    verdict = "ITERATE" if (l1_ok or missing_tool) else "REJECT"
    blocking_ids = (
        ["security-governance:evalops:UNCALIBRATED_SEMANTIC_HOLDOUT_PENDING"]
        if l1_ok else layer1.get("blocking_ids", ["security-governance:cpu-scanner:SYNTHETIC_GATE_FAILED"])
    )
    envelope = {
        "verdict_envelope": {
            "envelope_version": "1.2.0",
            "envelope_id": str(uuid.uuid4()),
            "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
            "suite_id": "security-governance",
            "director_slug": "security-director",
            "artifact_ref": "tests/fixtures/cpu/*, tests/fixtures/semantic/*",
            "sdlc_stage": "secure",
            "regime": "two_layer_benchmark",
            "synthesis_mode": "conjunctive_gate",
            "evidence_tier": layer1.get("evidence_tier", "UNVERIFIED_MISSING_TOOL"),
            "evidence": [
                {
                    "tool": "sec_cpu_scanner.py",
                    "command_or_ref": cli_cmd,
                    "exit_code": int(layer1.get("exit_code", 1)),
                    "format": "json",
                    "summary": (
                        f"Layer 1 synthetic fixture regression floor recall={layer1.get('recall')} "
                        f"fpr={layer1.get('false_positive_rate')} runtime_ms={layer1.get('runtime_ms')}"
                    ),
                }
            ],
            "verdict": verdict,
            "counts": {"blocker": 0 if (l1_ok or missing_tool) else 1, "major": 1 if (l1_ok or missing_tool) else 0, "minor": 0},
            "score_heuristic": None,
            "blocking_ids": blocking_ids,
            "clean_room_required": True,
            "hop_count": 0,
            "max_hops": 2,
            "visited_suites": visited,
            "escalations": escalations,
            "domain_extensions": {"layer1": layer1, "layer2": layer2},
        }
    }
    return json.dumps(envelope, indent=2)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Run Two-Layer Security Governance Benchmark.")
    parser.add_argument("--layer", choices=["1", "2", "all"], default="all")
    parser.add_argument("--cpu-dir", type=Path, default=repo_root / "tests/fixtures/cpu")
    parser.add_argument("--semantic-dir", type=Path, default=repo_root / "tests/fixtures/semantic")
    parser.add_argument("--scanner", type=Path, default=repo_root / "tools/sec_cpu_scanner.py")
    parser.add_argument("--semgrep", action="store_true")
    parser.add_argument("--gitleaks", action="store_true")
    parser.add_argument("--validate-evals", action="store_true")
    parser.add_argument("--semantic-runner", type=str, default=None, help="CLI accepting Clean-Room JSON on stdin")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--out-envelope", type=Path, default=None)
    args = parser.parse_args()

    if args.validate_evals:
        eval_errors = validate_eval_suites(repo_root, scanner=args.scanner)
        if eval_errors:
            print(json.dumps({"eval_validation_errors": eval_errors}, indent=2), file=sys.stderr)
            return 2

    l1 = run_layer1(args.cpu_dir, args.semantic_dir, args.scanner, args.semgrep, args.gitleaks) if args.layer in ("1", "all") else {}
    l2 = run_layer2(args.semantic_dir, args.semantic_runner, max(3, args.trials)) if args.layer in ("2", "all") else {}
    rendered = emit_verdict_envelope(l1, l2, " ".join(sys.argv))
    if args.out_envelope:
        args.out_envelope.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if (args.layer == "2" or l1.get("synthetic_regression_gate_passed", False)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
