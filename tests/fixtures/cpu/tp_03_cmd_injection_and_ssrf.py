"""Synthetic fixture: injection-input-validation (shell=True + unvalidated SSRF)."""
from __future__ import annotations

import subprocess
import requests


def export_support_bundle(report_slug: str) -> int:
    """Defect: untrusted slug interpolated into shell command with shell=True."""
    cmd = f"tar -czf /tmp/bundles/{report_slug}.tar.gz /var/data/reports/{report_slug}"
    completed = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
    return completed.returncode


def fetch_partner_webhook_preview(user_url: str) -> dict[str, object]:
    """Defect: arbitrary user-supplied URL fetched without scheme/host/IP allowlist."""
    response = requests.get(user_url, timeout=5)
    return {
        "target": user_url,
        "status": response.status_code,
        "preview_bytes": len(response.content),
    }
