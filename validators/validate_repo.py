#!/usr/bin/env python3
"""Suite-specific deterministic repository validator for best-security-governance-architects (v1.2.0)."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "validators"))
import ecosystem_core_validator as core  # noqa: E402

EXPECTED_MODULES = [
    "agentic-ai-threats",
    "authn-authz-boundaries",
    "crypto-key-management",
    "data-isolation-pii",
    "injection-input-validation",
    "secrets-supply-chain",
    "systemic-governance-audit",
]

EXPECTED_ENGINEERS = [
    "anderson",
    "bernstein-sec",
    "beurer-kellner",
    "greshake",
    "leveson-sec",
    "saltzer-schroeder",
    "shostack",
    "zalewski-sec",
]

REQUIRED_MODULE_H2 = [
    "When To Use",
    "Do Not Use When",
    "Required Inputs",
    "Execution & Audit Workflow",
    "Verdict & Severity Criteria",
    "Guardrails",
]

OVERCLAIM_RE = re.compile(
    r"\b(?:guarantees compliance|100% secure|legally certified|bulletproof|zero false positives|Q_total)\b",
    re.IGNORECASE,
)


def scanner_smoke_fn(installed_scanner: Path, dest: Path) -> list[str]:
    """Domain smoke check executed inside live coexistence workspace."""
    errors: list[str] = []
    sample = dest / "smoke_vuln.js"
    canary_val = "SYNTH_TEST_" + "KEY_" + ("0" * 20)
    sample.write_text(f'const k = "{canary_val}";\n', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(installed_scanner), "--target", str(sample), "--format", "json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 2:
        errors.append(f"Installed sec_cpu_scanner expected exit 2 on canary secret, got {proc.returncode}")
    else:
        data = json.loads(proc.stdout)
        if data.get("counts", {}).get("blocker", 0) < 1:
            errors.append("Installed sec_cpu_scanner returned 0 blockers on canary secret")
    return errors


def check_suite_invariants(suite_data: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if suite_data.get("suite_id") != "security-governance":
        errors.append(f"suite_id must be 'security-governance', got {suite_data.get('suite_id')!r}")
    if suite_data.get("synthesis_mode") != "conjunctive_gate":
        errors.append("synthesis_mode must be 'conjunctive_gate'")
    if suite_data.get("score_heuristic") is not None:
        errors.append("score_heuristic must be null for conjunctive_gate")
    if suite_data.get("clean_room_required") is not True:
        errors.append("clean_room_required must be true")
    tooling = suite_data.get("tooling", {})
    if tooling.get("fail_closed_on_missing_required_tool") is not True:
        errors.append("tooling.fail_closed_on_missing_required_tool must be true")
    if tooling.get("required_tools") != ["semgrep", "gitleaks", "osv-scanner", "trivy"]:
        errors.append(f"tooling.required_tools mismatch: {tooling.get('required_tools')}")
    roster = suite_data.get("roster_summary", {})
    if roster.get("total_modules") != 7 or roster.get("auditors") != 2 or roster.get("regimes") != 0:
        errors.append(f"roster_summary mismatch: {roster}")
    return len(errors) == 0, errors


def check_modules_and_sec_schema() -> tuple[bool, list[str]]:
    errors: list[str] = []
    schema = json.loads((REPO_ROOT / "validators" / "schema_sec.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    actual_modules = sorted(p.name for p in (REPO_ROOT / "modules").iterdir() if p.is_dir())
    if actual_modules != EXPECTED_MODULES:
        errors.append(f"modules/ mismatch expected={EXPECTED_MODULES}, actual={actual_modules}")

    nested_skills = list((REPO_ROOT / "modules").rglob("SKILL.md"))
    if nested_skills:
        errors.append(f"Forbidden nested SKILL.md under modules/: {[str(p.relative_to(REPO_ROOT)) for p in nested_skills]}")

    for slug in EXPECTED_MODULES:
        mdir = REPO_ROOT / "modules" / slug
        # PROFILE.md
        prof = mdir / "PROFILE.md"
        if not prof.is_file():
            errors.append(f"Missing modules/{slug}/PROFILE.md")
        else:
            fm, body = core._parse_frontmatter(prof.read_text(encoding="utf-8"))
            if not fm or fm.get("name") != slug:
                errors.append(f"modules/{slug}/PROFILE.md invalid frontmatter or name != '{slug}'")
            h2s = core._extract_h2(body)
            if h2s != REQUIRED_MODULE_H2:
                errors.append(f"modules/{slug}/PROFILE.md H2 mismatch: {h2s}")

        # BRIEF.md <= 2,600 B
        brief = mdir / "BRIEF.md"
        if not brief.is_file():
            errors.append(f"Missing modules/{slug}/BRIEF.md")
        elif brief.stat().st_size > 2600:
            errors.append(f"modules/{slug}/BRIEF.md exceeds 2,600 B ({brief.stat().st_size} B)")

        # SEC.md schema + referential integrity
        sec = mdir / "SEC.md"
        if not sec.is_file():
            errors.append(f"Missing modules/{slug}/SEC.md")
        else:
            fm, _ = core._parse_frontmatter(sec.read_text(encoding="utf-8"))
            if not fm:
                errors.append(f"modules/{slug}/SEC.md missing YAML frontmatter")
            else:
                for err in validator.iter_errors(fm):
                    errors.append(f"modules/{slug}/SEC.md schema error: {err.message}")
                if fm.get("module_identity", {}).get("slug") != slug:
                    errors.append(f"modules/{slug}/SEC.md module_identity.slug != '{slug}'")
                src_ids = {s["source_id"] for s in fm.get("primary_sources", []) if isinstance(s, dict) and "source_id" in s}
                for grp in ("cpu_rules", "semantic_invariants", "evidence_contribution_mappings"):
                    for idx, item in enumerate(fm.get(grp, [])):
                        if item.get("source_id") not in src_ids:
                            errors.append(f"modules/{slug}/SEC.md {grp}[{idx}]: unresolved source_id '{item.get('source_id')}'")
                        if "canonical_id" in item and not item["canonical_id"].startswith(f"security-governance:{slug}:"):
                            errors.append(f"modules/{slug}/SEC.md {grp}[{idx}]: canonical_id prefix mismatch '{item['canonical_id']}'")

    return len(errors) == 0, errors


def check_context_budget_and_offline_docs() -> tuple[bool, list[str]]:
    errors: list[str] = []
    active_files = [
        REPO_ROOT / "committee" / "security-director" / "SKILL.md",
        REPO_ROOT / "committee" / "security-director" / "control-matrix.yaml",
        REPO_ROOT / "committee" / "auditors" / "auditor-authz-intent" / "AUDITOR.md",
        REPO_ROOT / "committee" / "auditors" / "auditor-agentic-abuse" / "AUDITOR.md",
    ] + [REPO_ROOT / "modules" / slug / "BRIEF.md" for slug in EXPECTED_MODULES]

    total_bytes = sum(p.stat().st_size for p in active_files if p.is_file())
    if total_bytes > 25600:
        errors.append(f"Total active operational context {total_bytes} B exceeds 25,600 B ceiling")

    mindset = REPO_ROOT / "docs" / "security-mindset.md"
    if not mindset.is_file():
        errors.append("Missing docs/security-mindset.md")
    elif mindset.stat().st_size > 6000:
        errors.append(f"docs/security-mindset.md exceeds 6,000 B ({mindset.stat().st_size} B)")

    actual_eng = sorted(p.stem for p in (REPO_ROOT / "docs" / "engineers").glob("*.md"))
    if actual_eng != EXPECTED_ENGINEERS:
        errors.append(f"docs/engineers/ mismatch expected={EXPECTED_ENGINEERS}, actual={actual_eng}")

    return len(errors) == 0, errors


def check_evals_and_anti_overclaim() -> tuple[bool, list[str]]:
    errors: list[str] = []
    for slug in EXPECTED_MODULES:
        ep = REPO_ROOT / "modules" / slug / "evals" / "evals.json"
        if not ep.is_file():
            errors.append(f"Missing modules/{slug}/evals/evals.json")
    dir_ep = REPO_ROOT / "committee" / "security-director" / "evals" / "evals.json"
    if not dir_ep.is_file():
        errors.append("Missing committee/security-director/evals/evals.json")

    # Overclaim check across operational docs
    for path in list((REPO_ROOT / "modules").rglob("*.md")) + list((REPO_ROOT / "committee").rglob("*.md")):
        txt = path.read_text(encoding="utf-8")
        m = OVERCLAIM_RE.search(txt)
        if m:
            errors.append(f"{path.relative_to(REPO_ROOT)}: prohibited overclaim/cliché '{m.group(0)}'")

    return len(errors) == 0, errors


def main() -> int:
    core_ok, core_results, suite_data = core.run_all_core_checks(REPO_ROOT, scanner_smoke_fn=scanner_smoke_fn)
    suite_results: list[tuple[str, bool, list[str]]] = []

    ok, errs = check_suite_invariants(suite_data)
    suite_results.append(("[Suite] security-governance v1.2.0 manifest invariants", ok, errs))

    ok, errs = check_modules_and_sec_schema()
    suite_results.append(("[Suite] 7 modules, PROFILE.md, BRIEF.md <=2.6KB, SEC.md Draft 2020-12", ok, errs))

    ok, errs = check_context_budget_and_offline_docs()
    suite_results.append(("[Suite] Active context <=25.6KB, 8 dossiers & security-mindset.md <=6KB", ok, errs))

    ok, errs = check_evals_and_anti_overclaim()
    suite_results.append(("[Suite] evals.json presence & anti-overclaim guard", ok, errs))

    all_results = core_results + suite_results
    all_ok = core_ok and all(p for _, p, _ in suite_results)

    print("=" * 78)
    print("  SECURITY-GOVERNANCE REPOSITORY VALIDATOR (ECOSYSTEM_CONTRACT v1.2.0)")
    print("=" * 78)
    for label, passed, errs in all_results:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {label}")
        for e in errs:
            print(f"         -> {e}")
    print("-" * 78)
    if all_ok:
        print("  ALL CORE + SUITE CHECKS PASSED.")
        return 0
    print("  VALIDATION FAILED.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
