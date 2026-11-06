"""
Phase 1 — Transport Layer Assessment.
Real handshake-level checks via Python's ssl module: no fabricated results.
Equivalent in spirit to testssl.sh's non-intrusive checks; if testssl.sh or
sslyze are installed on the host, external_tools.py can shell out to them
for a deeper pass — this module always runs as the dependency-free baseline.
"""
import socket
import ssl
from datetime import datetime, timezone

from models import Finding, Severity

WEAK_PROTOCOLS = {
    "SSLv2": "CWE-327", "SSLv3": "CWE-327", "TLSv1": "CWE-327", "TLSv1.1": "CWE-327",
}
WEAK_CIPHER_TOKENS = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon"]


def _try_protocol(host: str, port: int, proto) -> tuple[bool, str | None]:
    """Return (negotiated, cipher_name) for a specific min/max TLS version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = proto
        ctx.maximum_version = proto
    except (ValueError, AttributeError):
        return False, None
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ssock.cipher()[0]
    except Exception:
        return False, None


def run(target_host: str, port: int, log, add_finding):
    log("INFO", f"Opening TLS handshake probe against {target_host}:{port}", "phase-1")

    # 1. Determine best negotiated protocol/cipher (normal handshake)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    negotiated_proto, negotiated_cipher, cert = None, None, None
    try:
        with socket.create_connection((target_host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                negotiated_proto = ssock.version()
                negotiated_cipher = ssock.cipher()[0]
                cert = ssock.getpeercert()
        log("INFO", f"Default handshake negotiated {negotiated_proto} / {negotiated_cipher}", "phase-1")
    except Exception as e:
        log("WARN", f"Could not complete baseline TLS handshake: {e}", "phase-1")
        add_finding(Finding(
            phase_id="phase-1", module="tls_scanner",
            title="TLS Endpoint Unreachable or Non-TLS Port",
            severity=Severity.INFO, cwe="CWE-Other",
            endpoint=f"{target_host}:{port}",
            evidence=str(e),
            description="Could not establish a TLS session on this port during the assessment window.",
            remediation="Confirm the port is expected to serve TLS and is reachable from the scanner's network position.",
        ))
        return

    # 2. Explicitly probe deprecated protocol versions
    version_map = {}
    for name, const in [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ]:
        if const is None:
            continue
        ok, cipher = _try_protocol(target_host, port, const)
        version_map[name] = ok
        if ok:
            log("CRIT", f"Deprecated protocol {name} accepted by server (cipher: {cipher})", "phase-1")
            add_finding(Finding(
                phase_id="phase-1", module="tls_scanner",
                title=f"Deprecated Protocol Supported: {name}",
                severity=Severity.HIGH, cwe="CWE-327",
                endpoint=f"{target_host}:{port}",
                evidence=f"Server completed a full handshake using {name} with cipher {cipher}.",
                description=f"The server still accepts {name}, a deprecated TLS/SSL protocol version with known "
                             "cryptographic weaknesses (e.g. BEAST, POODLE-adjacent issues).",
                remediation="Disable TLSv1.0/1.1 on the ingress/load balancer and enforce a minimum of TLS 1.2, "
                             "preferring TLS 1.3 where client compatibility allows.",
            ))
        else:
            log("INFO", f"{name} correctly rejected", "phase-1")

    # 3. Weak cipher token check on the negotiated cipher
    if negotiated_cipher and any(tok in negotiated_cipher for tok in WEAK_CIPHER_TOKENS):
        log("CRIT", f"Weak cipher in use: {negotiated_cipher}", "phase-1")
        add_finding(Finding(
            phase_id="phase-1", module="tls_scanner",
            title="Weak Cipher Suite Negotiated",
            severity=Severity.HIGH, cwe="CWE-327",
            endpoint=f"{target_host}:{port}",
            evidence=f"Negotiated cipher: {negotiated_cipher}",
            description="The server negotiated a cipher suite containing a known-weak primitive.",
            remediation="Restrict the server's cipher list to modern AEAD suites (e.g. ECDHE-RSA-AES128-GCM-SHA256, "
                         "TLS_AES_128_GCM_SHA256) and disable legacy/export-grade suites.",
        ))
    elif negotiated_cipher:
        log("INFO", f"Negotiated cipher {negotiated_cipher} has no known-weak markers", "phase-1")

    # 4. Certificate validity window
    if cert:
        try:
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days
            if days_left < 0:
                log("CRIT", "TLS certificate has EXPIRED", "phase-1")
                add_finding(Finding(
                    phase_id="phase-1", module="tls_scanner",
                    title="Expired TLS Certificate",
                    severity=Severity.HIGH, cwe="CWE-295",
                    endpoint=f"{target_host}:{port}",
                    evidence=f"notAfter={cert['notAfter']}",
                    description="The presented certificate's validity window has already ended.",
                    remediation="Renew and redeploy the certificate; automate renewal (e.g. ACME/Let's Encrypt) to prevent recurrence.",
                ))
            elif days_left < 14:
                log("WARN", f"TLS certificate expires in {days_left} days", "phase-1")
                add_finding(Finding(
                    phase_id="phase-1", module="tls_scanner",
                    title="TLS Certificate Nearing Expiry",
                    severity=Severity.MEDIUM, cwe="CWE-295",
                    endpoint=f"{target_host}:{port}",
                    evidence=f"notAfter={cert['notAfter']} ({days_left} days remaining)",
                    description="Certificate expiry is imminent, risking an unplanned outage or browser trust warnings.",
                    remediation="Renew ahead of expiry and add monitoring/alerting on certificate lifetime.",
                ))
            else:
                log("INFO", f"Certificate valid for {days_left} more days", "phase-1")
        except Exception:
            log("INFO", "Could not parse certificate expiry field", "phase-1")

    log("SUCCESS", "Transport layer assessment complete", "phase-1")
