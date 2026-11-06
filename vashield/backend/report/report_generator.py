"""
Generates a self-contained, print-ready HTML report from REAL findings only.
No template ever inserts a finding that wasn't actually produced by a
scanner module during this session — if a phase found nothing, the report
says so explicitly rather than filling space with invented issues.

Open the output in a browser and use Print -> Save as PDF for a clean,
paginated PDF deliverable (this avoids pulling in a heavy PDF-rendering
dependency and gives the client full control over headers/footers/margins).
"""
from datetime import datetime, timezone

from models import SEVERITY_WEIGHT, Severity
from report.remediation_db import enrich

SEVERITY_COLOR = {
    "CRITICAL": "#F43F5E", "HIGH": "#F97316", "MEDIUM": "#FBBF24", "LOW": "#3B82F6", "INFO": "#64748B",
}


def _severity_counts(findings):
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def render_report(session: dict, findings: list[dict], phases: list[dict]) -> str:
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_WEIGHT[Severity(f["severity"])], reverse=True)
    counts = _severity_counts(findings)
    total = len(findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    risk_score = min(100, sum(SEVERITY_WEIGHT[Severity(f["severity"])] * 8 for f in findings))

    def sev_badge(sev):
        return f'<span style="background:{SEVERITY_COLOR[sev]}22;color:{SEVERITY_COLOR[sev]};border:1px solid {SEVERITY_COLOR[sev]}66;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.03em">{sev}</span>'

    rows = []
    for f in findings_sorted:
        f = enrich(dict(f))
        rows.append(f"""
        <div class="finding-card" id="{f['finding_id']}">
          <div class="finding-head">
            <div>{sev_badge(f['severity'])} <span class="fid">{f['finding_id']}</span></div>
            <div class="cvss">CVSS ~{f['cvss']}</div>
          </div>
          <h3>{f['title']}</h3>
          <table class="meta">
            <tr><td>Phase</td><td>{f['phase_id']}</td><td>Module</td><td>{f['module']}</td></tr>
            <tr><td>CWE</td><td>{f['cwe']} — {f['reference']['name']}</td><td>Endpoint</td><td class="mono">{f['endpoint']}</td></tr>
            <tr><td>Detected</td><td colspan="3">{f['timestamp']}</td></tr>
          </table>
          <p class="label">Description</p><p>{f['description']}</p>
          <p class="label">Evidence</p><pre class="evidence">{f['evidence']}</pre>
          <p class="label">Remediation</p><p>{f['remediation']}</p>
          <p class="ref">Reference: {f['reference']['owasp']} &middot; Estimated remediation effort: {f['reference']['effort']}</p>
        </div>""")

    phase_summary_rows = "".join(
        f"<tr><td>{p['name']}</td><td>{sum(1 for f in findings if f['phase_id']==p['id'])}</td></tr>"
        for p in phases
    )

    findings_html = "".join(rows) if rows else '<p class="empty">No findings were produced during this assessment window.</p>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Vulnerability Assessment Report — {session.get('target','')}</title>
<style>
  @page {{ margin: 2cm; }}
  body {{ font-family: 'Inter', Arial, sans-serif; color:#0f172a; max-width: 900px; margin: 0 auto; padding: 40px 20px; line-height:1.55; }}
  h1 {{ font-size: 26px; margin-bottom:4px; }}
  h2 {{ font-size: 19px; border-bottom: 2px solid #0891B2; padding-bottom:6px; margin-top:40px; }}
  h3 {{ font-size: 16px; margin-bottom:6px; }}
  .cover {{ border-bottom: 4px solid #0891B2; padding-bottom: 24px; margin-bottom: 24px; }}
  .cover .sub {{ color:#475569; font-size:14px; }}
  .badge-row {{ display:flex; gap:10px; margin: 18px 0; flex-wrap:wrap; }}
  .stat {{ border:1px solid #e2e8f0; border-radius:10px; padding:10px 16px; min-width:90px; text-align:center; }}
  .stat .n {{ font-size:22px; font-weight:800; }}
  .stat .l {{ font-size:11px; text-transform:uppercase; color:#64748b; letter-spacing:.04em; }}
  table {{ border-collapse: collapse; width:100%; margin: 10px 0; }}
  table.summary td, table.summary th {{ border:1px solid #e2e8f0; padding:6px 10px; text-align:left; font-size:13px; }}
  table.meta td {{ font-size:12px; padding:3px 8px; color:#334155; }}
  table.meta td:nth-child(odd) {{ color:#64748b; width:80px; }}
  .finding-card {{ border:1px solid #e2e8f0; border-radius:12px; padding:18px 20px; margin:16px 0; page-break-inside: avoid; }}
  .finding-head {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }}
  .fid {{ font-family: monospace; color:#64748b; font-size:12px; margin-left:8px; }}
  .cvss {{ font-size:12px; color:#64748b; }}
  .label {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#0891B2; font-weight:700; margin:10px 0 2px; }}
  .evidence {{ background:#0f172a; color:#67e8f9; padding:10px 14px; border-radius:8px; font-size:12px; white-space:pre-wrap; word-break:break-word; }}
  .ref {{ font-size:11px; color:#94a3b8; margin-top:10px; }}
  .mono {{ font-family: monospace; font-size:12px; }}
  .empty {{ color:#64748b; font-style:italic; }}
  .disclaimer {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:14px 18px; font-size:12px; color:#475569; margin-top:30px; }}
  footer {{ margin-top:40px; font-size:11px; color:#94a3b8; text-align:center; }}
  @media print {{ .finding-card {{ break-inside: avoid; }} }}
</style></head>
<body>
  <div class="cover">
    <div style="font-size:12px;color:#0891B2;font-weight:700;letter-spacing:.08em;text-transform:uppercase">Vulnerability Assessment Report</div>
    <h1>{session.get('target', 'Target Application')}</h1>
    <div class="sub">Assessment ID: {session.get('session_id','')} &nbsp;|&nbsp; Generated: {generated} &nbsp;|&nbsp; Profile: {session.get('profile','baseline')}</div>
  </div>

  <h2>Executive Summary</h2>
  <p>This report summarizes the results of an automated vulnerability assessment against the scope defined for
  <strong>{session.get('target','the target application')}</strong>. The assessment executed
  {len(phases)} phases covering transport security, HTTP configuration, session/token handling, input validation,
  and access control, using a combination of built-in checks and (where available on the scan host) integrated
  open-source tooling. <strong>{total}</strong> findings were identified.</p>

  <div class="badge-row">
    <div class="stat"><div class="n" style="color:{SEVERITY_COLOR['CRITICAL']}">{counts['CRITICAL']}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:{SEVERITY_COLOR['HIGH']}">{counts['HIGH']}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:{SEVERITY_COLOR['MEDIUM']}">{counts['MEDIUM']}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:{SEVERITY_COLOR['LOW']}">{counts['LOW']}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n" style="color:{SEVERITY_COLOR['INFO']}">{counts['INFO']}</div><div class="l">Info</div></div>
    <div class="stat"><div class="n">{risk_score}</div><div class="l">Risk Index /100</div></div>
  </div>

  <h2>Scope &amp; Methodology</h2>
  <table class="summary">
    <tr><th>Target</th><td>{session.get('target','')}</td></tr>
    <tr><th>Ports in scope</th><td>{session.get('ports','')}</td></tr>
    <tr><th>Scan profile</th><td>{session.get('profile','')}</td></tr>
    <tr><th>Ownership verification</th><td>{session.get('ownership_note','')}</td></tr>
    <tr><th>Intrusive testing enabled</th><td>{session.get('intrusive', False)}</td></tr>
  </table>
  <table class="summary">
    <tr><th>Phase</th><th>Findings</th></tr>
    {phase_summary_rows}
  </table>

  <h2>Detailed Findings</h2>
  {findings_html}

  <div class="disclaimer">
    <strong>Scope &amp; limitations.</strong> This assessment was performed using automated tooling within the
    scope and parameters supplied for this session. Automated results reduce but do not eliminate the need for
    periodic manual penetration testing, particularly for business-logic and complex authorization flaws.
    Absence of a finding in a given category is not a guarantee of absence of vulnerability in that category.
  </div>
  <footer>Generated by VAShield Orchestrator &middot; {generated}</footer>
</body></html>"""
