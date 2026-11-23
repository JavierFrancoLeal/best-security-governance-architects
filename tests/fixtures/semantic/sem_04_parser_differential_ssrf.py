"""Semantic PR diff fixture: auditor-authz-intent (URL parser differential + IPv6 loopback SSRF)."""
from __future__ import annotations

from urllib.parse import urlparse
import requests

ALLOWED_WEBHOOK_HOSTS = {"webhooks.acme.test", "hooks.example.com"}
BLOCKED_IPV4_PREFIXES = ("10.", "127.", "169.254.", "192.168.")


def _is_safe_webhook_url(raw_url: str) -> bool:
    """Naive validator vulnerable to '@' / '\@' parser differentials and IPv4-mapped IPv6."""
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False

    authority = raw_url.split("://", 1)[1].split("/", 1)[0]
    host_token = authority.split("@")[-1].split(":")[0].lower()
    if host_token in ALLOWED_WEBHOOK_HOSTS:
        return True
    if host_token == "localhost" or host_token.startswith(BLOCKED_IPV4_PREFIXES):
        return False
    return parsed.hostname is not None


def deliver_partner_callback(target_url: str, payload: dict[str, object]) -> int:
    if not _is_safe_webhook_url(target_url):
        raise ValueError("Disallowed callback target")
    response = requests.post(target_url, json=payload, timeout=5, allow_redirects=True)
    return response.status_code
