#!/usr/bin/env python3
"""Tier B SARIF 2.1.0 normalizer, fail-closed gate & human-signoff verifier (v1.2.0).

Python 3.9+ standard library only.
Exit codes:
  0 - All required tools verified and verdict is SHIP (or 0 BLOCKER & 0 MAJOR)
  2 - Verdict is REJECT or ITERATE (blocking findings or pending human signoff)
  3 - Missing required tool evidence (fail-closed UNVERIFIED_MISSING_TOOL) or invalid input
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REQUIRED_TOOLS = ["semgrep", "gitleaks", "osv-scanner", "trivy"]
MISSING_TOOL_ID = "security-governance:tooling:MISSING_REQUIRED_TOOL_EVIDENCE"
PENDING_SIGNOFF_ID = "security-governance:governance:PENDING_NAMED_HUMAN_SIGNOFF"

SEVERITY_RANK = {"BLOCKER": 3, "MAJOR": 2, "MINOR": 1}
LEVEL_TO_SEV = {"error": "BLOCKER", "warning": "MAJOR", "note": "MINOR", "none": "MINOR"}


def normalize_sarif_file(path: Path, default_tool: str) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    runs = payload.get("runs")
    if not isinstance(runs, list) or len(runs) == 0:
        raise ValueError(f"Empty or forged SARIF payload in {path.name}: 'runs' must be a non-empty list with valid tool.driver.name")
    findings: list[dict[str, Any]] = []
    for run in runs:
        driver = run.get("tool", {}).get("driver", {})
        if not driver.get("name"):
            raise ValueError(f"Invalid SARIF run in {path.name}: missing tool.driver.name")
        tool_name = str(driver.get("name", default_tool)).lower()
        for res in run.get("results", []):
            props = res.get("properties") or {}
            rule_id = str(res.get("ruleId", "UNKNOWN"))
            sev = str(props.get("ecosystem_severity") or LEVEL_TO_SEV.get(str(res.get("level", "warning")).lower(), "MAJOR")).upper()
            if sev not in SEVERITY_RANK:
                sev = "MAJOR"
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            uri = str(phys.get("artifactLocation", {}).get("uri", "unknown"))
            line = int(phys.get("region", {}).get("startLine", 1))
            module_id = "secrets-supply-chain" if tool_name in {"gitleaks", "osv-scanner"} else "systemic-governance-audit" if tool_name == "trivy" else "injection-input-validation"
            canonical_id = str(props.get("canonical_id") or f"security-governance:{module_id}:{rule_id}")
            fp = hashlib.sha256(f"{uri}:{line}:{canonical_id}".encode("utf-8")).hexdigest()[:32]
            findings.append(
                {
                    "canonical_id": canonical_id,
                    "rule_id": rule_id,
                    "module_id": canonical_id.split(":")[1] if canonical_id.count(":") == 2 else module_id,
                    "tool": tool_name,
                    "severity": sev,
                    "evidence_tier": "TOOL_VERIFIED",
                    "file": uri,
                    "line": line,
                    "fingerprint": f"sha256:{fp}",
                    "message": str((res.get("message") or {}).get("text", "")),
                }
            )
    return findings


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[tuple[str, int, str], dict[str, Any]] = {}
    for item in findings:
        key = (item["file"], int(item["line"]), item["module_id"])
        if key not in best or SEVERITY_RANK[item["severity"]] > SEVERITY_RANK[best[key]["severity"]]:
            best[key] = item
    return sorted(best.values(), key=lambda f: (f["file"], f["line"], f["canonical_id"]))


def ingest_reports(reports_dir: Path, required_tools: list[str]) -> tuple[int, dict[str, Any]]:
    missing: list[dict[str, Any]] = []
    raw_findings: list[dict[str, Any]] = []
    present_tools: list[str] = []

    for tool in required_tools:
        candidates = [
            reports_dir / f"{tool}.sarif",
            reports_dir / f"{tool}.sarif.json",
            reports_dir / f"{tool.replace('-', '_')}.sarif",
        ]
        found = next((c for c in candidates if c.is_file()), None)
        if found is None:
            missing.append({"tool": tool, "reason": "sarif_report_missing", "exit_code": 127})
            continue
        try:
            raw_findings.extend(normalize_sarif_file(found, tool))
            present_tools.append(tool)
        except Exception as exc:
            missing.append({"tool": tool, "reason": f"sarif_parse_error: {exc}", "exit_code": 3})

    # Optional Tier A sec_cpu_scanner SARIF if present
    tier_a = reports_dir / "sec_cpu_scanner.sarif"
    if tier_a.is_file():
        raw_findings.extend(normalize_sarif_file(tier_a, "sec_cpu_scanner"))
        present_tools.append("sec_cpu_scanner")

    deduped = deduplicate(raw_findings)
    counts = {
        "blocker": sum(1 for f in deduped if f["severity"] == "BLOCKER"),
        "major": sum(1 for f in deduped if f["severity"] == "MAJOR"),
        "minor": sum(1 for f in deduped if f["severity"] == "MINOR"),
    }
    blocking_ids = sorted({f["canonical_id"] for f in deduped if f["severity"] in {"BLOCKER", "MAJOR"}})

    if missing:
        counts["major"] += 1
        if MISSING_TOOL_ID not in blocking_ids:
            blocking_ids.append(MISSING_TOOL_ID)
        verdict = "REJECT" if counts["blocker"] >= 1 else "ITERATE"
        return 3, {
            "schema_version": "1.2.0",
            "exit_code": 3,
            "evidence_tier": "UNVERIFIED_MISSING_TOOL",
            "required_tools_checked": required_tools,
            "verified_tools": present_tools,
            "missing_or_failed_tools": missing,
            "max_allowed_verdict": "ITERATE",
            "verdict": verdict,
            "counts": counts,
            "blocking_ids": blocking_ids,
            "findings": deduped,
        }

    verdict = "REJECT" if counts["blocker"] >= 1 else "ITERATE" if counts["major"] >= 1 else "SHIP"
    exit_code = 0 if verdict == "SHIP" else 2
    return exit_code, {
        "schema_version": "1.2.0",
        "exit_code": exit_code,
        "evidence_tier": "TOOL_VERIFIED",
        "required_tools_checked": required_tools,
        "verified_tools": present_tools,
        "missing_or_failed_tools": [],
        "verdict": verdict,
        "counts": counts,
        "blocking_ids": blocking_ids,
        "findings": deduped,
    }


def verify_envelope_json(envelope_path: Path, pr_author: str | None) -> tuple[int, dict[str, Any]]:
    data = json.loads(envelope_path.read_text(encoding="utf-8"))
    env = data.get("verdict_envelope", data)
    signoff = (env.get("domain_extensions") or {}).get("human_signoff") or {}
    errors: list[str] = []

    if signoff.get("required") is True:
        status = str(signoff.get("status", "PENDING")).upper()
        approver = signoff.get("approver_id")
        if status == "PENDING":
            errors.append(f"Human signoff is PENDING ({PENDING_SIGNOFF_ID})")
        elif status == "REJECTED":
            errors.append("Human signoff was REJECTED")
        elif status == "APPROVED":
            if not approver:
                errors.append("APPROVED human_signoff missing non-empty approver_id")
            if pr_author and approver == pr_author:
                errors.append(f"Self-approval violation: approver_id '{approver}' == pr_author '{pr_author}'")
            if not signoff.get("signed_off_at"):
                errors.append("APPROVED human_signoff missing signed_off_at timestamp")
        else:
            errors.append(f"Unknown human_signoff.status '{status}'")

    if env.get("evidence_tier") == "UNVERIFIED_MISSING_TOOL" and env.get("verdict") == "SHIP":
        errors.append("Fail-closed violation: SHIP emitted under UNVERIFIED_MISSING_TOOL")

    ok = len(errors) == 0 and env.get("verdict") == "SHIP"
    return (0 if ok else 2), {"verified": ok, "verdict": env.get("verdict"), "errors": errors}


def run_tier_b_tools(target_dir: Path, reports_dir: Path, required_tools: list[str]) -> None:
    """Execute installed Tier B CLI scanners (semgrep, gitleaks, osv-scanner, trivy) and write SARIF reports."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    commands: dict[str, list[str]] = {
        "semgrep": ["semgrep", "scan", "--sarif", "--config", "auto", "--output", str(reports_dir / "semgrep.sarif"), str(target_dir)],
        "gitleaks": ["gitleaks", "dir", str(target_dir), "--report-format", "sarif", "--report-path", str(reports_dir / "gitleaks.sarif")],
        "osv-scanner": ["osv-scanner", "scan", "--format", "sarif", "--output", str(reports_dir / "osv-scanner.sarif"), "-r", str(target_dir)],
        "trivy": ["trivy", "fs", "--format", "sarif", "--output", str(reports_dir / "trivy.sarif"), str(target_dir)],
    }
    for tool in required_tools:
        cmd = commands.get(tool)
        if not cmd or not shutil.which(cmd[0]):
            continue
        subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=180)
    # Also run bundled Tier A sec_cpu_scanner
    sec_scanner = Path(__file__).resolve().parent / "sec_cpu_scanner.py"
    if sec_scanner.is_file():
        subprocess.run(
            [sys.executable, str(sec_scanner), "--target", str(target_dir), "--sarif-output", str(reports_dir / "sec_cpu_scanner.sarif")],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize SARIF 2.1.0 reports with fail-closed required-tool gate.")
    parser.add_argument("--reports", type=Path, default=None, help="Directory containing <tool>.sarif files")
    parser.add_argument("--run-tools", type=Path, default=None, help="Execute installed Tier B tools + Tier A scanner against target directory before ingesting")
    parser.add_argument("--required-tools", type=str, default=",".join(REQUIRED_TOOLS), help="Comma-separated required tools")
    parser.add_argument("--out", type=Path, default=None, help="Write normalized JSON summary to path")
    parser.add_argument("--verify-envelope", type=Path, default=None, help="Verify JSON Verdict Envelope human_signoff invariants")
    parser.add_argument("--pr-author", type=str, default=None, help="PR author identity for independent approver check")
    args = parser.parse_args()

    if args.verify_envelope:
        rc, res = verify_envelope_json(args.verify_envelope, args.pr_author)
        print(json.dumps(res, indent=2))
        return rc

    if not args.reports:
        parser.print_help()
        return 3

    req = [t.strip() for t in args.required_tools.split(",") if t.strip()]
    if args.run_tools:
        run_tier_b_tools(args.run_tools.resolve(), args.reports.resolve(), req)
    rc, summary = ingest_reports(args.reports, req)
    rendered = json.dumps(summary, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
