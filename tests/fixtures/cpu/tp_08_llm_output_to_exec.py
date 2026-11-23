"""Synthetic fixture: agentic-ai-threats (OWASP LLM05 Improper Output Handling)."""
from __future__ import annotations

import subprocess
from typing import Any


def execute_llm_diagnostic(llm_client: Any, incident_summary: str) -> dict[str, Any]:
    """Defect: executes raw LLM completion text in eval() and subprocess without allowlist."""
    completion = llm_client.chat_complete(
        system="Return a Python expression and shell probe separated by '---'.",
        user=incident_summary,
    )
    raw_output = str(completion.choices[0].message.content)
    expr_part, _, cmd_part = raw_output.partition("---")

    # Defect 1 (SEC-AGT-OUTEXEC-001): arbitrary code execution via eval() on LLM output.
    computed_metric = eval(expr_part.strip())
    # Defect 2 (SEC-AGT-OUTEXEC-002): arbitrary shell execution via shell=True on LLM output.
    probe = subprocess.run(cmd_part.strip(), shell=True, check=False, capture_output=True, text=True)
    return {
        "metric": computed_metric,
        "stdout": probe.stdout,
        "exit_code": probe.returncode,
    }
