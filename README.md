# VAShield — Vulnerability Assessment Orchestrator

A real, working implementation of the architecture in `Security_Integration_Roadmap.md`.
Unlike the original `CyberScan_Enterprise_VA_Hub.html` prototype — whose "scan" was a
`setTimeout` loop printing hardcoded fake findings — every finding this tool reports
comes from a check that actually ran against your target, with the raw evidence
attached. If a check finds nothing, the report says so; it never invents a result.

**⚠️ Legal: only scan systems you own or are explicitly authorized to test.** The
tool enforces this technically for non-local targets (see "Ownership verification"
below) but that is not a substitute for having a signed authorization/rules-of-engagement
document in hand before testing anyone else's infrastructure.

## What's real right now (no extra tools needed)

| Phase | Module | What it actually does |
|---|---|---|
| 1 | `tls_scanner.py` | Opens real TLS sockets, forces TLS1.0/1.1 handshakes to test for deprecation, inspects negotiated cipher, checks cert expiry |
| 2 | `http_headers_scanner.py` | Real GET requests: checks CSP/HSTS/X-Frame-Options/etc, probes CORS reflection with a crafted `Origin` header, checks for exposed `.git`/`.env` |
| 3 | `session_scanner.py` | Passive cookie flag audit (HttpOnly/Secure/SameSite) from real `Set-Cookie` headers; static JWT header/claims decode; optional live `alg:none` bypass test (opt-in, intrusive) |
| 4 | `injection_scanner.py` | Real HTTP probes: single-quote error-based SQLi detection, unescaped-reflection XSS detection, against URL+param pairs *you* specify |
| 5 | `access_control_scanner.py` | Real BOLA/IDOR matrix test (Tenant A token against Tenant B's object) and BFLA test (low-priv token against an admin endpoint) |
| 6 | `external_tools.py` | Shells out to **nmap**, **testssl.sh**, **semgrep** if they're installed on the host — real subprocess calls, real parsed output. Reports "not installed" honestly instead of faking results. |

## Why the demo only shows `127.0.0.1`

This was built and tested inside a sandboxed dev environment with no general
internet egress, so it can't scan a live company site from here. To prove the
scanners are genuinely correct (not just "runs without crashing"), `testlab/vulnerable_app.py`
stands up a small Flask app with known, deliberately-planted issues (missing headers,
bad cookie flags, SQLi, XSS, BOLA, BFLA, exposed `.env`). Running VAShield against it
found **every single one**, with correct severities and accurate evidence — see
`sample_VA_report.html` for the real output of that run. Point `target_url` at any
host you're authorized to test and the same code runs unchanged.

## Getting it running

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open `frontend/index.html` in a browser (or serve it with any static file
server). It talks to `http://127.0.0.1:8000` by default — edit the `API` constant
at the top of the `<script>` block if you deploy the backend elsewhere.

### Ownership verification

For any non-local target, before `/api/v1/assessments/start` will run:

```bash
curl -X POST "http://localhost:8000/api/v1/ownership/request-token?target_url=https://staging.example.com"
# -> {"token": "a1b2c3...", "instructions": "..."}
```

Publish that token so `GET https://staging.example.com/.well-known/security-check.txt`
returns it, *then* start the scan. Loopback/private-IP targets skip this since they're
inherently self-owned.

### Full report

`GET /api/v1/scans/{session_id}/report` returns a self-contained, print-ready HTML
report (executive summary, risk index, phase breakdown, per-finding evidence +
remediation + CWE/OWASP reference). Open it and use the browser's Print → Save as PDF
for a polished PDF deliverable — this avoids a heavy PDF-rendering dependency and
gives you full control over page headers/footers/branding via the browser's print dialog.

## Wiring in the full Kali/Parrot toolset

`external_tools.py` already has the pattern — add more tools the same way:

```python
def run_sqlmap(url, param, log, add_finding):
    if not shutil.which("sqlmap"):
        log("INFO", "sqlmap not installed, skipping"); return
    proc = subprocess.run(["sqlmap", "-u", url, "-p", param, "--batch", "--risk=1", "--level=1"],
                           capture_output=True, text=True, timeout=180)
    # parse proc.stdout, call add_finding(...) for real hits
```

Recommended deployment: run the backend inside a container built `FROM kalilinux/kali-rolling`
(or Parrot's Docker image) with `nmap`, `testssl.sh`, `semgrep`, `nikto`, `sqlmap`, `zaproxy`
installed via `apt`/`pip`, so `shutil.which()` finds them automatically — no code changes needed.

For OWASP ZAP specifically, the cleanest integration is ZAP's own REST API
(`zap-baseline.py` or the `zaproxy` Docker image exposing port 8080) rather than a raw
subprocess call — call `http://localhost:8080/JSON/ascan/action/scan/` and poll status,
then pull `JSON/core/view/alerts/` for findings, mapped into `Finding` objects the same
way `external_tools.py` does for nmap/testssl.

## Architecture notes matching the roadmap

- **Async, event-driven**: each scan session runs in a background thread and streams
  `log` / `finding` / `phase_start` / `phase_done` / `complete` events over Server-Sent
  Events at `/api/v1/scans/{id}/stream` — swap the in-process `queue.Queue` for
  Redis/Celery if you need multi-worker/horizontal scaling.
- **Safe operating controls**: ownership verification (§4.1), intrusive tests are
  opt-in and scoped to explicit endpoints/params you provide rather than auto-crawled
  (§4.2), and every scan session's findings/log are retained in-memory for the report
  (§4.3) — swap in PostgreSQL for persistence across restarts.

## What this is not

This is a solid, real DAST/config-audit orchestrator covering the OWASP-Top-10-adjacent
checks in phases 1–5, plus real hooks for heavier tools in phase 6. It is **not** a
replacement for a licensed penetration test against complex business logic, and no
automated tool — commercial or open-source — should be the sole basis for a
compliance sign-off; pair it with periodic manual testing.
