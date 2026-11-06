"""
Phase 5 — Access Control (BOLA/IDOR).

Real matrix test, exactly as described in the roadmap:
  1. Authenticate as Tenant A (token supplied by caller — this tool never
     harvests or guesses credentials).
  2. Attempt to access a Tenant-B-owned resource ID using Tenant A's token.
  3. Assert the server returns 403/404, not 200 with Tenant B's data.

This requires the caller to supply two distinct, legitimately-obtained test
accounts/tokens for their own staging environment. Without both tokens the
check is skipped rather than guessed at.
"""
import requests

from models import Finding, Severity


def run(resource_url_template: str, tenant_a_token: str | None, tenant_b_object_id: str | None,
        admin_only_url: str | None, low_priv_token: str | None, log, add_finding):
    if not (resource_url_template and tenant_a_token and tenant_b_object_id):
        log("INFO", "BOLA/IDOR matrix test skipped — requires a resource URL template, Tenant A token, "
                     "and a Tenant B object id to test against", "phase-5")
    else:
        url = resource_url_template.format(id=tenant_b_object_id)
        log("INFO", f"Requesting {url} using Tenant A's credentials (object belongs to Tenant B)", "phase-5")
        try:
            r = requests.get(url, headers={"Authorization": f"Bearer {tenant_a_token}"}, timeout=8)
            if r.status_code == 200:
                log("CRIT", f"Cross-tenant object returned data (HTTP 200) instead of 403/404", "phase-5")
                add_finding(Finding(
                    phase_id="phase-5", module="access_control_scanner",
                    title="Broken Object Level Authorization (BOLA/IDOR)",
                    severity=Severity.CRITICAL, cwe="CWE-639",
                    endpoint=url,
                    evidence=f"Tenant A's token retrieved Tenant B's object at {url} with HTTP 200.",
                    description="Object-level ownership is not being enforced: a caller can access another "
                                 "tenant's resource purely by knowing/guessing its identifier.",
                    remediation="Enforce `resource.owner_id == context.user_id` (or equivalent tenant scoping) at "
                                 "the data-access layer for every object-returning endpoint, not just in the UI.",
                ))
            else:
                log("SUCCESS", f"Cross-tenant access correctly denied (HTTP {r.status_code})", "phase-5")
        except requests.RequestException as e:
            log("INFO", f"BOLA probe request failed: {e}", "phase-5")

    if not (admin_only_url and low_priv_token):
        log("INFO", "BFLA (function-level authorization) test skipped — requires an admin-only URL and a "
                     "low-privilege token", "phase-5")
    else:
        log("INFO", f"Requesting admin-only endpoint {admin_only_url} using a low-privilege token", "phase-5")
        try:
            r = requests.get(admin_only_url, headers={"Authorization": f"Bearer {low_priv_token}"}, timeout=8)
            if r.status_code in (401, 403, 404):
                log("SUCCESS", f"Admin function correctly denied to low-priv user (HTTP {r.status_code})", "phase-5")
            else:
                log("CRIT", f"Low-privilege token reached admin function (HTTP {r.status_code})", "phase-5")
                add_finding(Finding(
                    phase_id="phase-5", module="access_control_scanner",
                    title="Broken Function Level Authorization (BFLA)",
                    severity=Severity.CRITICAL, cwe="CWE-862",
                    endpoint=admin_only_url,
                    evidence=f"Low-privilege token reached admin-only endpoint with HTTP {r.status_code}.",
                    description="A privileged/admin function is reachable by a low-privilege authenticated user.",
                    remediation="Add explicit role/permission checks (RBAC/PBAC) on every privileged endpoint, "
                                 "enforced server-side — never rely on the client hiding the button.",
                ))
        except requests.RequestException as e:
            log("INFO", f"BFLA probe request failed: {e}", "phase-5")

    log("SUCCESS", "Access control assessment complete", "phase-5")
