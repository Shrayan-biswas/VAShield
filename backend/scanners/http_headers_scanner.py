"""
Phase 2 — HTTP Response Header & Config Hardening.
Real passive checks (equivalent to OWASP ZAP's passive scan rules for
headers) plus non-destructive probes for commonly-exposed artifact paths.
Every request here is a plain GET/HEAD — nothing destructive, nothing
that mutates state.
"""
import requests

from models import Finding, Severity

SECURITY_HEADERS = {
    "content-security-policy": ("CWE-1021", Severity.MEDIUM,
        "Missing Content-Security-Policy header",
        "No CSP header was returned, leaving the app more exposed to XSS and data-injection attacks that a "
        "well-formed policy would otherwise mitigate.",
        "Define and ship a CSP restricting script/style/img sources to trusted origins; start in Report-Only mode, "
        "then enforce."),
    "x-frame-options": ("CWE-1021", Severity.MEDIUM,
        "Missing X-Frame-Options / anti-clickjacking header",
        "Neither X-Frame-Options nor a frame-ancestors CSP directive was present, allowing the page to be framed.",
        "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive scoped to trusted origins."),
    "x-content-type-options": ("CWE-16", Severity.LOW,
        "Missing X-Content-Type-Options header",
        "Without 'nosniff', some browsers may MIME-sniff responses, enabling certain content-type confusion attacks.",
        "Add 'X-Content-Type-Options: nosniff' at the reverse proxy or framework middleware layer."),
    "strict-transport-security": ("CWE-319", Severity.MEDIUM,
        "Missing HTTP Strict Transport Security (HSTS)",
        "The server did not advertise HSTS, so clients aren't instructed to always use HTTPS for this host.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' once all subdomains are HTTPS-ready."),
    "referrer-policy": ("CWE-200", Severity.LOW,
        "Missing Referrer-Policy header",
        "No Referrer-Policy was set, which can leak full URLs (including sensitive query params) to third parties.",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
}

EXPOSED_PATHS = [
    (".git/HEAD", "CWE-538", Severity.CRITICAL, "Exposed .git repository metadata",
     "The .git directory is publicly reachable, which can allow full source disclosure via known .git-dumping techniques."),
    (".env", "CWE-538", Severity.CRITICAL, "Exposed .env file",
     "A .env file was reachable and may contain credentials, API keys, or database connection strings."),
    ("wp-config.php.bak", "CWE-538", Severity.HIGH, "Exposed backup config file",
     "A backup configuration file was reachable, which commonly contains plaintext secrets."),
]


def run(base_url: str, log, add_finding):
    log("INFO", f"Fetching baseline response headers for {base_url}", "phase-2")
    try:
        resp = requests.get(base_url, timeout=8, allow_redirects=True)
    except requests.RequestException as e:
        log("WARN", f"Could not fetch {base_url}: {e}", "phase-2")
        return

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    log("INFO", f"Received {len(resp.headers)} response headers, status {resp.status_code}", "phase-2")

    for header, (cwe, sev, title, desc, fix) in SECURITY_HEADERS.items():
        if header not in headers_lower:
            log("WARN" if sev != Severity.LOW else "INFO", f"Header check failed: {title}", "phase-2")
            add_finding(Finding(
                phase_id="phase-2", module="http_headers_scanner",
                title=title, severity=sev, cwe=cwe, endpoint=base_url,
                evidence=f"Response headers did not include '{header}'.",
                description=desc, remediation=fix,
            ))
        else:
            log("INFO", f"{header} present: {headers_lower[header][:80]}", "phase-2")

    # CORS reflection + credentials check — send a bogus Origin, see what bounces back
    log("INFO", "Probing CORS policy with a crafted Origin header", "phase-2")
    try:
        probe = requests.get(base_url, timeout=8, headers={"Origin": "https://evil-attacker-controlled.example"})
        acao = probe.headers.get("Access-Control-Allow-Origin")
        acac = probe.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == "https://evil-attacker-controlled.example" or (acao == "*" and acac):
            log("CRIT", f"CORS reflects arbitrary Origin (ACAO={acao}, credentials={acac})", "phase-2")
            add_finding(Finding(
                phase_id="phase-2", module="http_headers_scanner",
                title="Overly Permissive CORS Configuration",
                severity=Severity.HIGH, cwe="CWE-942",
                endpoint=base_url,
                evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                description="The server reflects arbitrary Origins (optionally with credentials allowed), letting "
                             "any third-party site make authenticated cross-origin requests on a victim's behalf.",
                remediation="Replace wildcard/reflective CORS with an explicit allow-list of trusted origins, and "
                             "never combine 'Allow-Credentials: true' with a reflected or wildcard origin.",
            ))
        else:
            log("INFO", f"CORS policy looks scoped (ACAO={acao})", "phase-2")
    except requests.RequestException as e:
        log("INFO", f"CORS probe failed: {e}", "phase-2")

    # Exposed artifact paths
    for path, cwe, sev, title, desc in EXPOSED_PATHS:
        url = base_url.rstrip("/") + "/" + path
        try:
            r = requests.get(url, timeout=6)
            if r.status_code == 200 and len(r.content) > 0:
                log("CRIT", f"Exposed path reachable: /{path} (200 OK)", "phase-2")
                add_finding(Finding(
                    phase_id="phase-2", module="http_headers_scanner",
                    title=title, severity=sev, cwe=cwe, endpoint=url,
                    evidence=f"GET {url} -> HTTP {r.status_code}, {len(r.content)} bytes",
                    description=desc,
                    remediation="Remove the artifact from the web root and block the path at the reverse proxy; "
                                 "rotate any credentials that may have been exposed.",
                ))
            else:
                log("INFO", f"/{path} -> HTTP {r.status_code} (not exposed)", "phase-2")
        except requests.RequestException:
            log("INFO", f"/{path} unreachable", "phase-2")

    log("SUCCESS", "HTTP header & config hardening assessment complete", "phase-2")
