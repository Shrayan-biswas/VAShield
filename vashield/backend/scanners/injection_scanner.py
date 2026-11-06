"""
Phase 4 — Input Validation & Injection (detection-only DAST).

This mirrors what OWASP ZAP's baseline/active rules do for SQLi/XSS
*detection*: send a harmless probe, look for an error signature or an
unescaped reflection. It never attempts to extract data, escalate a
finding into exploitation, or run destructive payloads (no UNION-based
dumping, no stacked queries, no file writes). That keeps this tool in
"vulnerability assessment" territory, not exploitation.

Scope is explicit: the caller must pass the exact params to probe. This
tool does not crawl or guess endpoints on its own — that keeps testing
inside whatever scope the target owner has authorized.
"""
import re

import requests

from models import Finding, Severity

SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "sqlstate", "unclosed quotation mark",
    "quoted string not properly terminated", "sqlite3.operationalerror",
    "pg_query", "odbc sql server driver", "ora-00933", "ora-01756",
]

XSS_MARKER = "vaXssProbe1337<z>"


def _probe_sqli(url: str, param: str, method: str, log):
    payload = "vaProbe'"
    try:
        if method.upper() == "GET":
            r = requests.get(url, params={param: payload}, timeout=8)
        else:
            r = requests.post(url, data={param: payload}, timeout=8)
        body = r.text.lower()
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body:
                return True, sig, r.status_code
        return False, None, r.status_code
    except requests.RequestException as e:
        log("INFO", f"SQLi probe request failed: {e}", "phase-4")
        return False, None, None


def _probe_xss(url: str, param: str, method: str, log):
    try:
        if method.upper() == "GET":
            r = requests.get(url, params={param: XSS_MARKER}, timeout=8)
        else:
            r = requests.post(url, data={param: XSS_MARKER}, timeout=8)
        # Unescaped reflection = marker appears verbatim, including the raw '<' and '>'
        reflected_raw = XSS_MARKER in r.text
        return reflected_raw, r.status_code
    except requests.RequestException as e:
        log("INFO", f"XSS probe request failed: {e}", "phase-4")
        return False, None


def run(targets: list[dict], log, add_finding):
    """
    targets: list of {"url": str, "param": str, "method": "GET"|"POST"}
    Explicit, user-authorized list only — no auto-discovery.
    """
    if not targets:
        log("INFO", "No injection test targets configured — skipping phase 4 active checks", "phase-4")
        log("SUCCESS", "Input validation assessment complete (no in-scope params provided)", "phase-4")
        return

    for t in targets:
        url, param, method = t["url"], t["param"], t.get("method", "GET")
        log("INFO", f"Probing {method} {url} param='{param}' for SQL error-based injection", "phase-4")
        hit, sig, status = _probe_sqli(url, param, method, log)
        if hit:
            log("CRIT", f"SQL error signature '{sig}' triggered by single-quote probe on '{param}'", "phase-4")
            add_finding(Finding(
                phase_id="phase-4", module="injection_scanner",
                title=f"Error-Based SQL Injection Indicator on '{param}'",
                severity=Severity.CRITICAL, cwe="CWE-89",
                endpoint=url,
                evidence=f"Injecting a single quote into '{param}' surfaced a database error signature ('{sig}'), "
                          f"HTTP {status}.",
                description="The parameter appears to be concatenated directly into a SQL statement rather than "
                             "passed as a bound parameter, and the resulting database error is reflected in the response.",
                remediation="Rewrite the query using parameterized statements / prepared statements or an ORM; "
                             "never interpolate user input into SQL text. Suppress raw DB error output in production.",
            ))
        else:
            log("INFO", f"No SQL error signature observed on '{param}' (HTTP {status})", "phase-4")

        log("INFO", f"Probing {method} {url} param='{param}' for unescaped reflection (XSS)", "phase-4")
        reflected, status = _probe_xss(url, param, method, log)
        if reflected:
            log("CRIT", f"Marker string reflected unescaped for param '{param}'", "phase-4")
            add_finding(Finding(
                phase_id="phase-4", module="injection_scanner",
                title=f"Reflected XSS Indicator on '{param}'",
                severity=Severity.HIGH, cwe="CWE-79",
                endpoint=url,
                evidence=f"Probe marker '{XSS_MARKER}' was reflected verbatim (unescaped) in the response body, HTTP {status}.",
                description="User-controlled input is reflected into the response without context-appropriate "
                             "output encoding, which a real payload could use to execute script in a victim's browser.",
                remediation="Apply context-aware output encoding (HTML entity encoding at minimum) wherever user "
                             "input is rendered, and set a restrictive CSP as defense-in-depth.",
            ))
        else:
            log("INFO", f"No unescaped reflection observed on '{param}' (HTTP {status})", "phase-4")

    log("SUCCESS", "Input validation assessment complete", "phase-4")
