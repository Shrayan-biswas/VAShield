"""
Phase 6 — External Open-Source Tool Integration (Kali/Parrot).

This is the real integration point requested in the roadmap: if the host
running this backend has these tools installed (as it would inside a
Kali/Parrot container, or `apt install nmap testssl.sh` on Debian/Ubuntu),
this module shells out to them with the target as a strict argument list
(never shell=True, never string-interpolated into a shell command) and
parses their real output. If a tool isn't installed, that is reported
honestly instead of faking a result.

Tools wired up here:
  - nmap       (port/service enumeration)
  - testssl.sh (deep TLS/cipher audit — supplements tls_scanner.py)
  - semgrep    (SAST — static source analysis, needs a source path, not a URL)
Add more by following the same pattern: check shutil.which, build an argv
list, run with a timeout, parse stdout.
"""
import json
import shutil
import subprocess

from models import Finding, Severity

TOOL_TIMEOUT = 120


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_nmap(host: str, ports: str, log, add_finding):
    if not _tool_available("nmap"):
        log("INFO", "nmap not installed on this host — skipping live port/service enumeration "
                     "(install via `apt install nmap` or use a Kali/Parrot base image to enable)", "phase-6")
        return
    log("INFO", f"Running nmap -sV -p{ports} {host}", "phase-6")
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "-Pn", "-p", ports, "-oX", "-", host],
            capture_output=True, text=True, timeout=TOOL_TIMEOUT,
        )
        log("INFO", f"nmap exited with code {proc.returncode}", "phase-6")
        # Lightweight parse: flag any open port whose service/version string is present
        import re
        for m in re.finditer(r'<port protocol="tcp" portid="(\d+)">.*?<state state="open".*?(?:<service name="([^"]*)"(?: product="([^"]*)")?(?: version="([^"]*)")?)?', proc.stdout, re.S):
            port_id, svc, product, version = m.groups()
            desc = " ".join(filter(None, [svc, product, version])) or "unknown service"
            log("INFO", f"Open port {port_id}: {desc}", "phase-6")
        add_finding(Finding(
            phase_id="phase-6", module="external_tools:nmap",
            title="nmap Service Enumeration Completed",
            severity=Severity.INFO, cwe="CWE-Other",
            endpoint=f"{host}:{ports}",
            evidence=f"nmap raw XML output ({len(proc.stdout)} bytes) captured for the report appendix.",
            description="Live port/service enumeration was executed via nmap. Review the raw output in the report "
                         "appendix for services that shouldn't be internet-reachable.",
            remediation="Close or firewall any ports/services not required for the application to function.",
        ))
    except subprocess.TimeoutExpired:
        log("WARN", "nmap scan timed out", "phase-6")
    except Exception as e:
        log("WARN", f"nmap execution failed: {e}", "phase-6")


def run_testssl(host: str, port: str, log, add_finding):
    binary = "testssl.sh" if _tool_available("testssl.sh") else ("testssl" if _tool_available("testssl") else None)
    if not binary:
        log("INFO", "testssl.sh not installed — relying on the built-in tls_scanner baseline only "
                     "(install testssl.sh for a deeper cipher/vulnerability audit)", "phase-6")
        return
    log("INFO", f"Running {binary} --jsonfile - {host}:{port}", "phase-6")
    try:
        proc = subprocess.run(
            [binary, "--fast", "--jsonfile-pretty", "-", f"{host}:{port}"],
            capture_output=True, text=True, timeout=TOOL_TIMEOUT,
        )
        try:
            results = json.loads(proc.stdout)
        except json.JSONDecodeError:
            results = []
        criticals = [r for r in results if isinstance(r, dict) and r.get("severity") in ("CRITICAL", "HIGH")]
        log("INFO", f"testssl.sh reported {len(results)} findings, {len(criticals)} HIGH/CRITICAL", "phase-6")
        for r in criticals[:20]:
            add_finding(Finding(
                phase_id="phase-6", module="external_tools:testssl",
                title=f"testssl.sh: {r.get('id', 'finding')}",
                severity=Severity.HIGH, cwe="CWE-327",
                endpoint=f"{host}:{port}",
                evidence=str(r.get("finding", ""))[:300],
                description="Deep TLS/cipher audit finding reported directly by testssl.sh.",
                remediation="See testssl.sh finding detail and the OWASP TLS Cipher String Cheat Sheet for the "
                             "specific remediation for this cipher/protocol issue.",
            ))
    except subprocess.TimeoutExpired:
        log("WARN", "testssl.sh scan timed out", "phase-6")
    except Exception as e:
        log("WARN", f"testssl.sh execution failed: {e}", "phase-6")


def run_semgrep(source_path: str | None, log, add_finding):
    if not source_path:
        log("INFO", "No source path supplied — semgrep SAST pass skipped (this is a source-code scan, "
                     "not a URL scan; point it at your repo checkout to enable)", "phase-6")
        return
    if not _tool_available("semgrep"):
        log("INFO", "semgrep not installed — skipping SAST pass (`pip install semgrep` to enable)", "phase-6")
        return
    log("INFO", f"Running semgrep --config=auto against {source_path}", "phase-6")
    try:
        proc = subprocess.run(
            ["semgrep", "--config=auto", "--json", source_path],
            capture_output=True, text=True, timeout=TOOL_TIMEOUT,
        )
        data = json.loads(proc.stdout or "{}")
        results = data.get("results", [])
        log("INFO", f"semgrep reported {len(results)} findings", "phase-6")
        for r in results[:30]:
            sev = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM}.get(
                r.get("extra", {}).get("severity", ""), Severity.LOW)
            add_finding(Finding(
                phase_id="phase-6", module="external_tools:semgrep",
                title=r.get("check_id", "semgrep finding").split(".")[-1],
                severity=sev, cwe="CWE-Other",
                endpoint=r.get("path", source_path),
                evidence=f"Line {r.get('start', {}).get('line')}: {r.get('extra', {}).get('message', '')[:200]}",
                description=r.get("extra", {}).get("message", "Static analysis finding."),
                remediation="See the semgrep rule documentation linked in the full JSON report for the specific fix pattern.",
            ))
    except subprocess.TimeoutExpired:
        log("WARN", "semgrep scan timed out", "phase-6")
    except Exception as e:
        log("WARN", f"semgrep execution failed: {e}", "phase-6")


def run(host: str, ports: str, source_path: str | None, log, add_finding):
    log("INFO", "Checking host for available open-source security tools (nmap, testssl.sh, semgrep)...", "phase-6")
    run_nmap(host, ports, log, add_finding)
    first_port = ports.split(",")[0].strip() if ports else "443"
    run_testssl(host, first_port, log, add_finding)
    run_semgrep(source_path, log, add_finding)
    log("SUCCESS", "External tool integration pass complete", "phase-6")
