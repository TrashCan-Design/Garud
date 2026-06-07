import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Garud Security Tools API", version="3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TSUNAMI_JAR     = os.getenv("TSUNAMI_JAR",     "/opt/tsunami/tsunami.jar")
TSUNAMI_PLUGINS = os.getenv("TSUNAMI_PLUGINS", "/opt/tsunami/plugins")
JAVA_OPTS       = os.getenv("JAVA_OPTS",       "-Xms128m -Xmx1536m -XX:+UseG1GC")


class ScanRequest(BaseModel):
    target:   str
    severity: str = "low,medium,high,critical"
    timeout:  int = 180


class Finding(BaseModel):
    tool:        str
    type:        str
    name:        str
    severity:    str
    description: str
    url:         str = ""
    evidence:    str = ""
    cwe:         str = ""
    cvss:        str = ""


class ScanResponse(BaseModel):
    success:   bool
    tool:      str
    target:    str
    findings:  list[Finding]
    raw_count: int
    error:     str = ""


def _run(cmd: list[str], timeout: int, env: dict = None) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
            stdin=subprocess.DEVNULL,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except FileNotFoundError as exc:
        return -2, "", str(exc)


def _normalize_severity(raw: str) -> str:
    return {
        "critical": "Critical", "high": "High",
        "medium":   "Medium",   "low":  "Low",
        "info":     "Info",     "informational": "Info",
        "unknown":  "Info",
    }.get(raw.lower().strip(), "Info")


def _tool_installed(cmd: list[str]) -> bool:
    rc, _, _ = _run(cmd, timeout=5)
    return rc == 0


def _parse_nuclei(raw: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line: continue
        try: obj: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError: continue

        info      = obj.get("info", {})
        name      = info.get("name", obj.get("template-id", "Nuclei Finding"))
        severity  = _normalize_severity(info.get("severity", "info"))
        desc      = info.get("description", "")
        matched   = obj.get("matched-at", obj.get("host", target))
        extracted = obj.get("extracted-results", [])
        evidence  = ", ".join(extracted) if extracted else obj.get("matcher-name", "")
        cwe_list  = info.get("classification", {}).get("cwe-id", [])
        cwe       = ", ".join(cwe_list) if isinstance(cwe_list, list) else str(cwe_list)
        cvss      = str(info.get("classification", {}).get("cvss-score", ""))
        ref       = info.get("reference", [])
        if ref: desc += " | Refs: " + (", ".join(ref[:2]) if isinstance(ref, list) else ref)

        findings.append(Finding(
            tool="nuclei", type="Nuclei — " + info.get("tags", ["vuln"])[0] if info.get("tags") else "Nuclei Finding",
            name=name, severity=severity, description=desc,
            url=matched, evidence=evidence, cwe=cwe, cvss=cvss,
        ))
    return findings


async def _run_nuclei(req: ScanRequest) -> ScanResponse:
    logger.info(f"Nuclei surface scan → {req.target}")
    out_file = tempfile.mktemp(suffix=".jsonl")
    try:
        cmd = [
            "nuclei",
            "-u",            req.target,
            "-severity",     req.severity,
            "-jsonl",
            "-o",            out_file,
            "-timeout",      "2",
            "-rate-limit",   "150",
            "-bulk-size",    "25",
            "-concurrency",  "25",
            "-tags",         "cve,misconfig,exposure,takeover",
            "-follow-redirects",
            "-max-redirects", "2",
        ]
        loop = asyncio.get_event_loop()
        rc, stdout, stderr = await loop.run_in_executor(None, lambda: _run(cmd, req.timeout))

        if rc == -2:
            raise HTTPException(503, "nuclei not installed")

        raw = ""
        if os.path.exists(out_file):
            with open(out_file) as f: raw = f.read()

        findings = _parse_nuclei(raw, req.target)
        logger.info(f"Nuclei → {len(findings)} findings")
        return ScanResponse(success=True, tool="nuclei", target=req.target, findings=findings, raw_count=len(findings))
    except HTTPException: raise
    except Exception as exc:
        logger.exception("Nuclei error")
        return ScanResponse(success=False, tool="nuclei", target=req.target, findings=[], raw_count=0, error=str(exc))
    finally:
        if os.path.exists(out_file): os.unlink(out_file)


def _parse_sqlmap(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []

    if not re.search(r'is vulnerable|appears to be .+ injectable|sqlmap identified the following injection|parameter .+ is (not )?injectable', stdout, re.I):
        return findings

    blocks = re.findall(r"Parameter:\s+'?(.+?)'?\s+\((.+?)\).*?Type:\s+(.+?)\n.*?Title:\s+(.+?)\n.*?Payload:\s+(.+?)(?=\n\n|\Z)", stdout, re.S)
    reported: set[str] = set()

    if blocks:
        for param, position, inj_type, title, payload in blocks:
            param = param.strip()
            if param in reported: continue
            reported.add(param)
            findings.append(Finding(
                tool="sqlmap", type="SQL Injection",
                name=f"SQLi — {param} ({inj_type.strip()})",
                severity="Critical",
                description=f"{title.strip()}. Parameter '{param}' ({position.strip()}) is injectable.",
                url=target, evidence=payload.strip()[:300], cwe="CWE-89",
            ))
    else:
        for param in set(re.findall(r"Parameter:\s+'?(.+?)'?\s+\(", stdout)):
            findings.append(Finding(tool="sqlmap", type="SQL Injection", name=f"SQLi — {param.strip()}", severity="Critical", description=f"SQLMap confirmed injectable parameter: {param.strip()}", url=target, evidence="", cwe="CWE-89"))

    return findings


async def _run_sqlmap(req: ScanRequest) -> ScanResponse:
    logger.info(f"SQLMap surface scan → {req.target}")
    out_dir = tempfile.mkdtemp(prefix="sqlmap_")
    try:
        cmd = [
            "sqlmap",
            "-u",           req.target,
            "--batch",
            "--level",      "1",
            "--risk",       "1",
            "--threads",    "4",
            "--smart",
            "--timeout",    "10",
            "--technique",  "BEUS",        
            "--output-dir", out_dir,
            "--random-agent",
            "--flush-session",
            "--forms",
            "--crawl",      "1",
        ]
        loop = asyncio.get_event_loop()
        rc, stdout, stderr = await loop.run_in_executor(None, lambda: _run(cmd, req.timeout))

        if rc == -2: raise HTTPException(503, "sqlmap not installed")
        if rc != 0:
            logger.warning(f"SQLMap process exited with code {rc}. stderr: {stderr.strip()}")

        findings = _parse_sqlmap(stdout + stderr, req.target)
        logger.info(f"SQLMap → {len(findings)} findings")
        return ScanResponse(success=True, tool="sqlmap", target=req.target, findings=findings, raw_count=len(findings))
    except HTTPException: raise
    except Exception as exc:
        logger.exception("SQLMap error")
        return ScanResponse(success=False, tool="sqlmap", target=req.target, findings=[], raw_count=0, error=str(exc))


_NIKTO_SKIP = re.compile(r'^\s*(-\s+)?(\+\s+)?(Target IP|Target Hostname|Target Port|Start Time|End Time|1 host\(s\) tested|Nikto|No web server found|Platform|Server|Scan terminated|Web Server|Port|Host|Target|SSL Info)', re.I)

CWE_CVSS_MAP = {
    "CWE-78": ("9.8", "Critical"),
    "CWE-89": ("9.8", "Critical"),
    "CWE-79": ("6.1", "Medium"),
    "CWE-352": ("8.8", "High"),
    "CWE-918": ("9.1", "Critical"),
    "CWE-284": ("8.2", "High"),
    "CWE-798": ("9.8", "Critical"),
    "CWE-200": ("5.3", "Medium"),
    "CWE-319": ("7.5", "High"),
    "CWE-310": ("7.4", "High"),
    "CWE-693": ("4.3", "Medium"),
    "CWE-770": ("5.3", "Medium"),
    "CWE-400": ("7.5", "High"),
    "CWE-353": ("5.9", "Medium"),
    "CWE-538": ("5.3", "Medium"),
    "CWE-1104": ("6.5", "Medium"),
}

def _parse_nikto(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("+"): continue
        if _NIKTO_SKIP.match(stripped): continue

        detail = re.sub(r'^\+\s*(OSVDB-\d+:\s*)?', '', stripped).strip()
        if len(detail) < 12 or detail in seen: continue
        seen.add(detail)


        cwe = ""
        cwe_match = re.search(r'\[(CWE-\d+)\]', detail, re.I)
        if cwe_match:
            cwe = cwe_match.group(1).upper()

        sev, cvss = "Low", ""
        if cwe and cwe in CWE_CVSS_MAP:
            cvss, sev = CWE_CVSS_MAP[cwe]
        else:
            lower = detail.lower()
            if any(re.search(rf"\b{k}\b", lower) for k in ("rce", "exec", "command injection", "remote code", "eval", "execution")):
                sev, cwe, cvss = "Critical", "CWE-78", "9.8"
            elif any(re.search(rf"\b{k}\b", lower) for k in ("xss", "cross-site", "sql", "injection", "traversal", "path")):
                if "sql" in lower:
                    sev, cwe, cvss = "Critical", "CWE-89", "9.8"
                else:
                    sev, cwe, cvss = "Medium", "CWE-79", "6.1"
            elif any(re.search(rf"\b{k}\b", lower) for k in ("directory listing", "backup", "phpinfo", "debug", "config", "password", "credentials", "token", "key")):
                sev, cwe, cvss = "Medium", "CWE-200", "5.3"
            elif any(re.search(rf"\b{k}\b", lower) for k in ("header", "cookie", "ssl", "tls", "cors", "csrf")):
                sev, cwe, cvss = "Medium", "CWE-693", "4.3"
            else:
                sev, cwe, cvss = "Low", "", "2.5"

        osvdb = re.search(r'OSVDB-(\d+)', stripped)
        evidence = f"OSVDB-{osvdb.group(1)}" if osvdb else ""

        findings.append(Finding(
            tool="nikto",
            type="Nikto Finding",
            name=detail[:100],
            severity=sev,
            description=detail,
            url=target,
            evidence=evidence,
            cwe=cwe,
            cvss=cvss
        ))
    return findings


async def _run_nikto(req: ScanRequest) -> ScanResponse:
    logger.info(f"Nikto surface scan → {req.target}")
    try:
        cmd = [
            "nikto",
            "-h",            req.target,
            "-Format",       "txt",
            "-Tuning",       "1",
            "-maxtime",      "60s",
            "-nointeractive",
            "-useragent",    "Garud-Scanner/3.0",
            "-timeout",      "3",
            "-C",            "all",
        ]
        if req.target.lower().startswith("https://"):
            cmd.append("-ssl")
        loop = asyncio.get_event_loop()
        rc, stdout, stderr = await loop.run_in_executor(None, lambda: _run(cmd, req.timeout))

        if rc == -2: raise HTTPException(503, "nikto not installed")

        findings = _parse_nikto(stdout, req.target)
        logger.info(f"Nikto → {len(findings)} findings")
        return ScanResponse(success=True, tool="nikto", target=req.target, findings=findings, raw_count=len(findings))
    except HTTPException: raise
    except Exception as exc:
        logger.exception("Nikto error")
        return ScanResponse(success=False, tool="nikto", target=req.target, findings=[], raw_count=0, error=str(exc))


def _extract_host_port(target: str) -> tuple[str, int]:
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else "http://" + target)
    host   = parsed.hostname or target
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _is_ipv4(value: str) -> bool:
    parts = value.split('.')
    if len(parts) != 4:
        return False
    for item in parts:
        try:
            if not 0 <= int(item) <= 255:
                return False
        except ValueError:
            return False
    return True



def _parse_tsunami(json_path: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    if not os.path.exists(json_path): return findings
    try:
        with open(json_path) as f: data = json.load(f)
    except Exception: return findings

    for finding in data.get("scanFindings", []):
        vuln     = finding.get("vulnerability", {})
        severity = _normalize_severity(vuln.get("severity", "info"))
        title    = vuln.get("title", vuln.get("description", {}).get("title", "Tsunami Finding"))
        desc     = vuln.get("description", {})
        desc_str = desc.get("description", title) if isinstance(desc, dict) else str(desc)
        refs     = vuln.get("relatedId",   [])
        cvss     = str(vuln.get("cvssScore", ""))
        cve_refs = [r.get("id", "") for r in refs if r.get("publisher", "") == "CVE"]
        cwe_refs = [r.get("id", "") for r in refs if r.get("publisher", "") == "CWE"]

        evidence_parts = []
        for rpc in finding.get("networkService", {}).get("serviceContext", {}).values():
            if isinstance(rpc, str): evidence_parts.append(rpc)

        findings.append(Finding(
            tool="tsunami", type="Tsunami Finding", name=title[:120], severity=severity,
            description=desc_str, url=target, evidence="; ".join(evidence_parts)[:300],
            cwe=", ".join(cwe_refs), cvss=cvss + (" CVE: " + ", ".join(cve_refs) if cve_refs else ""),
        ))
    return findings


async def _run_tsunami(req: ScanRequest) -> ScanResponse:
    logger.info(f"Tsunami surface scan → {req.target}")

    if not os.path.exists(TSUNAMI_JAR):
        return ScanResponse(success=False, tool="tsunami", target=req.target, findings=[], raw_count=0, error="Tsunami JAR not found")

    host, port = _extract_host_port(req.target)
    out_file   = tempfile.mktemp(suffix=".json")
    target_flag = f"--ip-v4-target={host}" if _is_ipv4(host) else f"--hostname-target={host}"

    try:
        cmd = [
            "java", *JAVA_OPTS.split(),
            "-cp", f"{TSUNAMI_JAR}:{TSUNAMI_PLUGINS}/*",
            "-Dtsunami.config.location=/opt/tsunami/tsunami.yaml",
            "com.google.tsunami.main.cli.TsunamiCli",
            target_flag,
            "--scan-results-local-output-format=JSON",
            f"--scan-results-local-output-filename={out_file}",
            f"--port-ranges-target={port}",
        ]
        loop = asyncio.get_event_loop()
        rc, stdout, stderr = await loop.run_in_executor(None, lambda: _run(cmd, req.timeout))

        if rc == -2:
            return ScanResponse(success=False, tool="tsunami", target=req.target, findings=[], raw_count=0, error="java not found")
        if rc != 0:
            logger.error(f"Tsunami process exited with code {rc}. stderr: {stderr.strip()}")

        findings = _parse_tsunami(out_file, req.target)
        logger.info(f"Tsunami → {len(findings)} findings")
        return ScanResponse(success=True, tool="tsunami", target=req.target, findings=findings, raw_count=len(findings))
    except Exception as exc:
        logger.exception("Tsunami error")
        return ScanResponse(success=False, tool="tsunami", target=req.target, findings=[], raw_count=0, error=str(exc))
    finally:
        if os.path.exists(out_file): os.unlink(out_file)


@app.get("/")
def health():
    return {"service": "Garud Security Tools API", "status": "online", "version": "3.1 (Surface Scan Mode)"}


@app.get("/tools")
def list_tools():
    return {
        "nuclei":  _tool_installed(["nuclei",  "-version"]),
        "sqlmap":  _tool_installed(["sqlmap",  "--version"]),
        "nikto":   _tool_installed(["nikto",   "-Version"]),
        "nmap":    _tool_installed(["nmap",    "-V"]),
        "tsunami": os.path.exists(TSUNAMI_JAR),
        "java":    _tool_installed(["java",    "-version"]),
    }


@app.post("/scan/nuclei",  response_model=ScanResponse)
async def scan_nuclei(req: ScanRequest):
    return await _run_nuclei(req)


@app.post("/scan/sqlmap",  response_model=ScanResponse)
async def scan_sqlmap(req: ScanRequest):
    return await _run_sqlmap(req)


@app.post("/scan/nikto",   response_model=ScanResponse)
async def scan_nikto(req: ScanRequest):
    return await _run_nikto(req)


@app.post("/scan/tsunami", response_model=ScanResponse)
async def scan_tsunami(req: ScanRequest):
    return await _run_tsunami(req)


@app.post("/scan/full")
async def scan_full(req: ScanRequest):
    logger.info(f"Full parallel surface scan → {req.target}")

    tsunami_req = ScanRequest(target=req.target, severity=req.severity, timeout=min(req.timeout, 900))

    results = await asyncio.gather(
        _run_nuclei(req),
        _run_sqlmap(req),
        _run_nikto(req),
        _run_tsunami(tsunami_req),
        return_exceptions=True,
    )

    all_findings: list[dict] = []
    tool_errors:  dict       = {}

    for res in results:
        if isinstance(res, Exception):
            logger.warning(f"Tool error: {res}")
            continue
        if isinstance(res, ScanResponse):
            if res.error: tool_errors[res.tool] = res.error
            all_findings.extend([f.model_dump() for f in res.findings])

    seen:   set[tuple]  = set()
    unique: list[dict]  = []
    for f in all_findings:
        key = (f["name"].lower()[:60], f["url"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    unique.sort(key=lambda x: sev_order.get(x["severity"], 5))

    return {
        "success":        True,
        "target":         req.target,
        "total_findings": len(unique),
        "findings":       unique,
        "tools_run":      ["nuclei", "sqlmap", "nikto", "tsunami"],
        "tool_errors":    tool_errors,
    }