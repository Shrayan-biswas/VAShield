"""
Phase 3 — Identity, Session, and Token Verification.

Cookie flag inspection is fully passive. JWT analysis is static by default
(decodes the header/claims without verifying signature, exactly like
`jwt.decode(..., options={"verify_signature": False})` — this never forges
or replays a token). The one active check — attempting an 'alg: none'
bypass against a live auth-check endpoint — only runs if the caller
explicitly opts into intrusive testing AND supplies that endpoint, per the
roadmap's environment-scoping control.
"""
import base64
import json

import jwt as pyjwt
import requests

from models import Finding, Severity


def _b64_json(segment: str) -> dict:
    pad = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def run(base_url: str, jwt_token: str | None, intrusive: bool, auth_check_endpoint: str | None,
        log, add_finding):
    log("INFO", f"Auditing session cookies from {base_url}", "phase-3")
    try:
        resp = requests.get(base_url, timeout=8)
        raw_cookies = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else \
            resp.headers.get("Set-Cookie")
        if isinstance(raw_cookies, str):
            raw_cookies = [raw_cookies]
        raw_cookies = raw_cookies or []

        if not raw_cookies:
            log("INFO", "No Set-Cookie headers observed on this response", "phase-3")

        for raw in raw_cookies:
            name = raw.split("=")[0]
            lower = raw.lower()
            missing = []
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "secure" not in lower:
                missing.append("Secure")
            if "samesite" not in lower:
                missing.append("SameSite")

            if missing:
                log("WARN", f"Cookie '{name}' missing flags: {', '.join(missing)}", "phase-3")
                add_finding(Finding(
                    phase_id="phase-3", module="session_scanner",
                    title=f"Session Cookie Missing Security Flags: {name}",
                    severity=Severity.HIGH if "HttpOnly" in missing or "Secure" in missing else Severity.MEDIUM,
                    cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614",
                    endpoint=base_url,
                    evidence=f"Set-Cookie: {raw[:120]}",
                    description=f"Cookie '{name}' is missing: {', '.join(missing)}. This increases exposure to "
                                 "session theft via XSS (missing HttpOnly), transmission over plaintext HTTP "
                                 "(missing Secure), or cross-site request forgery (missing SameSite).",
                    remediation="Set HttpOnly, Secure, and SameSite=Lax (or Strict) on all session/auth cookies.",
                ))
            else:
                log("INFO", f"Cookie '{name}' has HttpOnly, Secure, and SameSite set", "phase-3")
    except requests.RequestException as e:
        log("WARN", f"Could not fetch {base_url} for cookie audit: {e}", "phase-3")

    # Static JWT analysis (no network call, no forgery)
    if jwt_token:
        log("INFO", "Statically decoding supplied JWT header/claims (signature not verified)", "phase-3")
        try:
            header_seg, payload_seg, *_ = jwt_token.split(".")
            header = _b64_json(header_seg)
            payload = _b64_json(payload_seg)
            alg = header.get("alg", "")
            log("INFO", f"Token alg={alg}, claims present: {list(payload.keys())}", "phase-3")

            if alg.lower() == "none":
                log("CRIT", "Token header already declares alg=none", "phase-3")
                add_finding(Finding(
                    phase_id="phase-3", module="session_scanner",
                    title="JWT Uses 'none' Algorithm",
                    severity=Severity.CRITICAL, cwe="CWE-347",
                    endpoint=base_url,
                    evidence=f"Decoded header: {header}",
                    description="The token's header specifies alg=none, meaning no signature is required — "
                                 "any client can mint arbitrary tokens.",
                    remediation="Reject alg=none server-side; enforce an explicit algorithm allow-list "
                                 "(e.g. RS256 only) when verifying tokens.",
                ))
            if "exp" not in payload:
                log("WARN", "Token has no 'exp' (expiration) claim", "phase-3")
                add_finding(Finding(
                    phase_id="phase-3", module="session_scanner",
                    title="JWT Missing Expiration Claim",
                    severity=Severity.MEDIUM, cwe="CWE-613",
                    endpoint=base_url,
                    evidence=f"Decoded payload keys: {list(payload.keys())}",
                    description="The token carries no 'exp' claim, so once issued it may be valid indefinitely if "
                                 "the server doesn't enforce expiry out-of-band.",
                    remediation="Include a short-lived 'exp' claim and enforce it server-side on every request.",
                ))
        except Exception as e:
            log("INFO", f"Could not parse supplied token as JWT: {e}", "phase-3")

        if intrusive and auth_check_endpoint:
            log("WARN", f"Intrusive mode: attempting alg=none bypass against {auth_check_endpoint}", "phase-3")
            try:
                header_seg, payload_seg, *_ = jwt_token.split(".")
                forged = f"{header_seg}.{payload_seg}."  # classic alg:none forgery, empty signature
                # Re-encode header with alg=none explicitly to be a faithful test
                forged_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
                forged = f"{forged_header}.{payload_seg}."
                r = requests.get(auth_check_endpoint, headers={"Authorization": f"Bearer {forged}"}, timeout=8)
                if r.status_code < 400:
                    log("CRIT", f"alg=none forged token was ACCEPTED (HTTP {r.status_code})", "phase-3")
                    add_finding(Finding(
                        phase_id="phase-3", module="session_scanner",
                        title="JWT Signature Verification Bypass (alg=none accepted)",
                        severity=Severity.CRITICAL, cwe="CWE-347",
                        endpoint=auth_check_endpoint,
                        evidence=f"Forged alg=none token accepted with HTTP {r.status_code}.",
                        description="The auth-check endpoint accepted a token forged with alg=none and an empty "
                                     "signature, meaning authentication can be bypassed entirely.",
                        remediation="Enforce an explicit algorithm allow-list server-side and reject any token "
                                     "whose header algorithm isn't on that list before checking claims.",
                    ))
                else:
                    log("SUCCESS", f"alg=none forgery correctly rejected (HTTP {r.status_code})", "phase-3")
            except requests.RequestException as e:
                log("INFO", f"Intrusive JWT bypass test failed to execute: {e}", "phase-3")
    else:
        log("INFO", "No JWT supplied — skipping token analysis", "phase-3")

    log("SUCCESS", "Identity & session assessment complete", "phase-3")
