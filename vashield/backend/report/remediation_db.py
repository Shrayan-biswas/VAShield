"""
Rule-based Fix Finder. Every finding already carries a `remediation` string
written by the scanner that detected it (see scanners/*.py) — this module
adds a slightly richer, CWE-indexed reference card for the dedicated
Fix Finder tab / drawer in the UI, plus generic priority guidance.
"""

CWE_REFERENCE = {
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp": "OWASP TLS Cipher String Cheat Sheet",
        "effort": "Low (config change)",
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "owasp": "OWASP Transport Layer Protection Cheat Sheet",
        "effort": "Low (renew/automate cert)",
    },
    "CWE-1021": {
        "name": "Improper Restriction of Rendered UI Layers (Clickjacking) / Missing Headers",
        "owasp": "OWASP Secure Headers Project",
        "effort": "Low (add header at proxy/middleware)",
    },
    "CWE-16": {"name": "Configuration", "owasp": "OWASP Secure Headers Project", "effort": "Low"},
    "CWE-319": {"name": "Cleartext Transmission of Sensitive Information", "owasp": "OWASP HSTS Cheat Sheet", "effort": "Low"},
    "CWE-200": {"name": "Exposure of Sensitive Information", "owasp": "OWASP Referrer Policy", "effort": "Low"},
    "CWE-942": {"name": "Permissive Cross-domain Policy (CORS)", "owasp": "OWASP CORS OriginHeaderScrutiny", "effort": "Medium"},
    "CWE-538": {"name": "Insertion of Sensitive Information into Externally-Accessible File", "owasp": "OWASP Top 10 A05", "effort": "Low (remove + rotate secrets)"},
    "CWE-1004": {"name": "Sensitive Cookie Without HttpOnly", "owasp": "OWASP Session Management Cheat Sheet", "effort": "Low"},
    "CWE-614": {"name": "Sensitive Cookie in HTTPS Session Without Secure Attribute", "owasp": "OWASP Session Management Cheat Sheet", "effort": "Low"},
    "CWE-347": {"name": "Improper Verification of Cryptographic Signature", "owasp": "OWASP JWT Cheat Sheet", "effort": "Medium"},
    "CWE-613": {"name": "Insufficient Session Expiration", "owasp": "OWASP Session Management Cheat Sheet", "effort": "Low"},
    "CWE-89": {"name": "SQL Injection", "owasp": "OWASP SQL Injection Prevention Cheat Sheet", "effort": "Medium-High (query rewrite)"},
    "CWE-79": {"name": "Cross-Site Scripting (XSS)", "owasp": "OWASP XSS Prevention Cheat Sheet", "effort": "Medium"},
    "CWE-639": {"name": "Authorization Bypass Through User-Controlled Key (IDOR)", "owasp": "OWASP API Security Top 10 - API1", "effort": "Medium-High"},
    "CWE-862": {"name": "Missing Authorization", "owasp": "OWASP API Security Top 10 - API5", "effort": "Medium"},
}


def enrich(finding_dict: dict) -> dict:
    ref = CWE_REFERENCE.get(finding_dict["cwe"], {"name": "General Weakness", "owasp": "OWASP Top 10", "effort": "Unknown"})
    finding_dict["reference"] = ref
    return finding_dict
