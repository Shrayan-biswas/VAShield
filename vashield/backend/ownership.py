"""
Proof-of-ownership gate, per Security_Integration_Roadmap.md section 4.

Before any scan runs against a non-local target, the caller must place a
verification token at http://<target>/.well-known/security-check.txt.
This is a REAL HTTP check — it does not trust a checkbox in the UI.

Local/loopback targets (127.0.0.1, localhost, private RFC1918 ranges) are
exempt, since those are always self-owned by whoever is running this tool.
"""
import ipaddress
import secrets
import socket
from urllib.parse import urlparse

import requests

_pending_tokens: dict[str, str] = {}  # host -> expected token


def generate_token(host: str) -> str:
    token = secrets.token_hex(16)
    _pending_tokens[host] = token
    return token


def _is_private_host(host: str) -> bool:
    try:
        # resolve then check
        addr = socket.gethostbyname(host)
        ip = ipaddress.ip_address(addr)
        return ip.is_loopback or ip.is_private
    except Exception:
        return host in ("localhost",)


def verify_ownership(target_url: str) -> tuple[bool, str]:
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        return False, "Could not parse target hostname."

    if _is_private_host(host):
        return True, "Target resolves to a loopback/private address — treated as self-owned, no external proof required."

    expected = _pending_tokens.get(host)
    if not expected:
        return False, (
            "No verification token has been issued for this host. Call "
            "/api/v1/ownership/request-token first, then publish it at "
            "/.well-known/security-check.txt before starting a scan."
        )

    check_url = f"{parsed.scheme}://{host}/.well-known/security-check.txt"
    try:
        resp = requests.get(check_url, timeout=6)
        if resp.status_code == 200 and expected in resp.text:
            return True, f"Ownership verified via {check_url}"
        return False, f"Verification file did not contain the expected token (HTTP {resp.status_code})."
    except requests.RequestException as e:
        return False, f"Could not reach {check_url}: {e}"
