import concurrent.futures
import json
import logging
import os
import re
import time

import requests as http_requests
from flask import Flask, jsonify, request, Response, send_file, stream_with_context
from flask_cors import CORS
from urllib.parse import urljoin, urlparse

from crawler_manager import HybridCrawlerManager
from beautifulsoup_crawler import BeautifulSoupCrawler
from api_scanner import APIScanner
from bac_scanner import BACScanner
from config import Config
from cryptographic_faliures import CryptographicFailuresScanner
from Integrity_checker import IntegrityFailuresScanner
from network_scanner import NetworkScanner
from Outdated_Comp_Checker import scan_outdated_components
from report_generator import generate_pdf_report
from sqli_scanner import SQLiScanner
from ssrf_scanner import SSRFScanner
from xss_scanner import XSSScanner
from dos_check import DoSScanner
from rate_limit import RateLimitScanner
from xpath_injection_scanner import XPathInjectionScanner
from exposed_admin_panels import ExposedAdminScanner
from path_traversal_scanner import PathTraversalScanner
from directory_listing_scanner import DirectoryListingScanner

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)


hybrid_crawler  = HybridCrawlerManager(max_depth=2)
bs_crawler_util = BeautifulSoupCrawler()
network_scanner = NetworkScanner()
sqli_scanner    = SQLiScanner()
xss_scanner     = XSSScanner()
api_scanner     = APIScanner()
bac_scanner     = BACScanner()
ssrf_scanner    = SSRFScanner()
dos_scanner     = DoSScanner()
xpath_scanner   = XPathInjectionScanner()
admin_panel_scanner = ExposedAdminScanner()
path_traversal_scanner = PathTraversalScanner()
directory_listing_scanner = DirectoryListingScanner()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SEC_TOOLS_URL = os.getenv("SEC_TOOLS_URL", "http://127.0.0.1:8001")


_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


CWE_REFERENCE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cwe_reference.json")
try:
    with open(CWE_REFERENCE_PATH, "r", encoding="utf-8") as f:
        CWE_REFERENCE_CACHE = json.load(f)
except Exception as e:
    logger.error(f"Failed to load CWE reference JSON: {e}")
    CWE_REFERENCE_CACHE = {}

def clean_cwe(cwe_str) -> str:
    """Standardize CWE ID format."""
    if not cwe_str:
        return ""
    match = re.search(r'(?:CWE|cwe)[-_\s]?(\d+)', str(cwe_str))
    if match:
        return f"CWE-{match.group(1)}"
    return ""

def get_cvss_and_severity(vuln: dict) -> tuple[float, str]:
    """Map vulnerability to CVSS score and severity."""

    cvss_val = vuln.get("cvss_score")
    if cvss_val is None:
        cvss_val = vuln.get("cvss")
    
    if cvss_val is not None:
        try:
            # Strip trailing "(version)" from string scores
            if isinstance(cvss_val, str) and "(" in cvss_val:
                cvss_val = cvss_val.split("(")[0].strip()
            cvss_float = float(cvss_val)

            if cvss_float >= 7.0:
                return cvss_float, "Critical"
            elif cvss_float >= 4.0:
                return cvss_float, "Medium"
            elif cvss_float >= 0.1:
                return cvss_float, "Low"
            else:
                return 0.0, "Info"
        except (ValueError, TypeError):
            pass

    # Fall back to CWE reference lookup
    cwe_id = clean_cwe(vuln.get("cwe"))
    if cwe_id and cwe_id in CWE_REFERENCE_CACHE:
        entry = CWE_REFERENCE_CACHE[cwe_id]
        severity = entry.get("classification", "Info")
        if severity == "High":
            severity = "Critical"
        return float(entry.get("cvss", 0.0)), severity


    return 0.0, "Suggestion"

@app.route('/api/cwe-reference', methods=['GET'])
@app.route('/api/cwe_reference', methods=['GET'])
def get_cwe_reference():
    return jsonify(CWE_REFERENCE_CACHE)

# Vuln type → CWE ID lookup
CWE_MAP = {
    "SQL Injection":                    "CWE-89",
    "Reflected XSS":                    "CWE-79",
    "Stored XSS":                       "CWE-79",
    "Dom XSS":                          "CWE-79",
    "DOM XSS":                          "CWE-79",
    "Missing Security Header":          "CWE-693",
    "CSRF Risk":                        "CWE-352",
    "Sensitive Input Exposure":         "CWE-200",
    "Broken Access Control":            "CWE-284",
    "Server-Side Request Forgery":      "CWE-918",
    "Rate Limiting Missing":            "CWE-770",
    "Missing DDoS/WAF Protection":      "CWE-693",
    "Exposed Secret":                   "CWE-798",
    "Database Port Open":               "CWE-200",
    "Telnet Exposed":                   "CWE-319",
    "Insecure FTP":                     "CWE-319",
    "Potential Denial of Service":      "CWE-400",
    "Cryptographic Failure":            "CWE-310",
    "Weak Cipher Suite":                "CWE-310",
    "Information Disclosure":           "CWE-200",
    "No HTTPS":                         "CWE-319",
    "Missing SRI":                      "CWE-353",
    "Exposed Sensitive File":           "CWE-538",
    "Inline Script Exposure":           "CWE-79",
    "External Script Without SRI (Crawl)": "CWE-353",
    "VCS/Build Path in Crawler Graph":  "CWE-538",
    "Outdated Component":               "CWE-1104",
    "DoS Risk":                         "CWE-400",
    "Mass Assignment / Parameter Pollution": "CWE-915",
    "Missing Authorization":            "CWE-862",
    "IDOR":                             "CWE-639",
    "HTTP Verb Tampering":              "CWE-284",
    "Header-Based Authorization Bypass": "CWE-285",
    "Path Confusion":                   "CWE-863",
    "Privilege Escalation":             "CWE-269",
    "Missing Authentication":           "CWE-306",
    "CORS Misconfiguration":            "CWE-942",
    "XPath Injection":                  "CWE-643",
    "Exposed Admin Panel":              "CWE-200",
    "Path Traversal":                   "CWE-22",
    "Directory Listing":                "CWE-548",
}


def _get_vuln_cvss(vuln: dict) -> float:
    """Get CVSS score via CWE mapping."""
    cvss, _ = get_cvss_and_severity(vuln)
    return cvss


def _compute_cwe_score(vulnerabilities: list[dict]) -> dict:
    """Calculate security score and grade based on penalties."""
    if not vulnerabilities:
        return {"score": 100, "grade": "A", "status": "Secure"}

    seen_cwes: dict[str, int] = {}   # Track occurrences
    total_penalty = 0.0

    for vuln in vulnerabilities:
        cvss = _get_vuln_cvss(vuln)
        cwe = clean_cwe(vuln.get("cwe") or CWE_MAP.get(vuln.get("type", ""), "UNKNOWN"))

        count = seen_cwes.get(cwe, 0)
        weight = 1.0 if count == 0 else 0.3
        seen_cwes[cwe] = count + 1

        total_penalty += cvss * weight

    score = max(0, round(100 - total_penalty, 1))

    if score >= 90:
        grade, status = "A", "Secure"
    elif score >= 75:
        grade, status = "B", "Warnings"
    elif score >= 50:
        grade, status = "C", "Medium Risk"
    elif score >= 25:
        grade, status = "D", "Critical"
    else:
        grade, status = "F", "Critical"

    return {"score": score, "grade": grade, "status": status}


def _enrich_vulns_with_cwe(vulnerabilities: list[dict]) -> list[dict]:
    """Decorate vulnerability dictionary with CWE metadata."""
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "")
        cwe_raw = vuln.get("cwe")
        if not cwe_raw:
            cwe_raw = CWE_MAP.get(vuln_type)
            if not cwe_raw:
                for key, val in CWE_MAP.items():
                    if key.lower() in vuln_type.lower():
                        cwe_raw = val
                        break
        cwe = clean_cwe(cwe_raw)
        vuln["cwe"] = cwe
        cvss, severity = get_cvss_and_severity(vuln)
        vuln["cvss_score"] = cvss
        vuln["severity"] = severity
        if not vuln.get("source"):
            vuln["source"] = "Garud"
    return vulnerabilities


def _call_sec_tool(endpoint: str, payload: dict, timeout: int = 180) -> dict:
    url = f"{SEC_TOOLS_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        resp = http_requests.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except http_requests.exceptions.ConnectionError:
        logger.warning(f"Sec-tools microservice offline — {url}")
        return {"success": False, "findings": [], "error": "microservice offline"}
    except Exception as exc:
        logger.warning(f"Sec-tools call failed [{url}]: {exc}")
        return {"success": False, "findings": [], "error": str(exc)}


def _external_findings_to_vulns(findings: list[dict]) -> list[dict]:
    vulns = []
    for f in findings:
        if f.get("tool") == "nikto":
            desc_lower = (f.get("description") or f.get("name") or "").lower().strip()
            if any(desc_lower.startswith(prefix) for prefix in (
                "platform:", "server:", "scan terminated:", "web server:",
                "port:", "host:", "target:", "ssl info:"
            )):
                continue
        cwe = clean_cwe(f.get("cwe", ""))
        cvss = f.get("cvss", "")

        temp_vuln = {
            "cwe": cwe,
            "cvss": cvss,
            "severity": f.get("severity", "Medium"),
            "type": f.get("type", f.get("tool", "External Finding")),
        }
        cvss_score, sev = get_cvss_and_severity(temp_vuln)

        desc = f.get("description") or f.get("name", "")
        evidence = f.get("evidence", "")
        if evidence:
            desc = f"{desc} | Evidence: {evidence}"
        

        if cwe or cvss_score:
            parts = []
            if cwe:
                parts.append(cwe)
            if cvss_score:
                parts.append(f"CVSS: {cvss_score}")
            desc += f" [{' | '.join(parts)}]"

        vulns.append({
            "type":        temp_vuln["type"],
            "severity":    sev,
            "description": desc,
            "source":      f.get("tool", "external"),
            "url":         f.get("url", ""),
            "cwe":         cwe,
            "cvss_score":  cvss_score,
            "cvss":        cvss,
        })
    return vulns



def _normalize_internal_findings(findings: list[dict], source: str) -> list[dict]:
    vulns = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        sev = finding.get("severity", "Medium")
        if sev not in _SEV_ORDER:
            sev = "Medium"

        vuln_type = finding.get("type") or finding.get("name") or source
        vuln = {
            "type": vuln_type,
            "name": finding.get("name", vuln_type),
            "severity": sev,
            "description": finding.get("description") or vuln_type,
            "recommendation": finding.get("recommendation", ""),
            "source": source,
        }
        if finding.get("type"):
            vuln["category"] = finding["type"]
        

        for key in ("cwe", "evidence", "payload", "test_url", "final_url", "status_code", "parameter", "injection_point"):
            if key in finding:
                vuln[key] = finding[key]
        
        if "endpoint" in finding:
            vuln["url"] = finding["endpoint"]
        elif "url" in finding:
            vuln["url"] = finding["url"]
            
        vulns.append(vuln)

    return vulns


def _normalize_vulnerability_entries(vulnerabilities: list[dict], source: str) -> list[dict]:
    normalized = []
    for vuln in vulnerabilities or []:
        if not isinstance(vuln, dict):
            continue

        item = dict(vuln)
        sev = item.get("severity", "Medium")
        if sev not in _SEV_ORDER:
            sev = "Medium"

        item["severity"] = sev
        item.setdefault("source", source)
        item.setdefault("name", item.get("type", source))
        if not item.get("type"):
            item["type"] = item["name"]
        normalized.append(item)

    return normalized


def _vuln_key(vuln: dict) -> tuple[str, str, str]:
    vuln_type = vuln.get("type", "")
    description = vuln.get("description", "")
    if vuln_type == "Missing Security Header":
        headers_list = [
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Content-Type-Options", "X-Frame-Options",
            "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy"
        ]
        for h in headers_list:
            if h.lower() in description.lower():
                return ("Missing Security Header", "", h.lower())
    return (
        str(vuln_type),
        str(vuln.get("severity", "")),
        str(description),
    )


def _dedupe_vulnerabilities(vulnerabilities: list[dict]) -> list[dict]:
    seen = set()
    deduped = []

    for vuln in vulnerabilities:
        key = _vuln_key(vuln)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(vuln)

    return deduped


def _filter_new_vulnerabilities(existing: list[dict], candidates: list[dict]) -> list[dict]:
    seen = {_vuln_key(v) for v in existing}
    new_vulns = []

    for vuln in candidates:
        key = _vuln_key(vuln)
        if key in seen:
            continue
        seen.add(key)
        new_vulns.append(vuln)

    return new_vulns


def _build_report_filename(target_url: str) -> str:
    parsed = urlparse(target_url or "")
    label = parsed.netloc or parsed.path or "garud-scan"
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("._") or "garud-scan"
    return f"{label}-{int(time.time())}.pdf"


def analyze_vulnerabilities(url, crawl_data, network_data, headers_data, sensitive_data, api_secrets):
    vulns = []

    if api_secrets:
        for secret in api_secrets:
            vulns.append({
                "type":        "Exposed Secret",
                "name":        secret.get("name", "Exposed Secret"),
                "severity":    secret.get("severity", "Critical"),
                "description": f"{secret.get('description')} (Match: {secret.get('match', '***')})"
            })

    if network_data and "summary" in network_data:
        open_ports = network_data["summary"].get("open_ports", [])
        if 21 in open_ports:
            vulns.append({"type": "Insecure FTP",       "severity": "High",     "description": "Port 21 (FTP) open — credentials sent in cleartext."})
        if 23 in open_ports:
            vulns.append({"type": "Telnet Exposed",     "severity": "Critical", "description": "Port 23 (Telnet) open — obsolete, insecure protocol."})
        if 80 in open_ports and 443 not in open_ports:
            vulns.append({"type": "No HTTPS",           "severity": "Medium",   "description": "Site accessible via HTTP only — no TLS."})
        if 3306 in open_ports or 5432 in open_ports:
            vulns.append({"type": "Database Port Open", "severity": "High",     "description": "Database ports (3306/5432) exposed to the public internet."})

    if headers_data.get("headers_missing"):
        for h in headers_data["headers_missing"]:
            sev = "Medium" if h in ("Content-Security-Policy", "Strict-Transport-Security") else "Low"
            vulns.append({"type": "Missing Security Header", "severity": sev,
                          "description": f"Header '{h}' is missing, reducing defence against XSS/Clickjacking."})

    if sensitive_data:
        vulns.append({"type": "Sensitive Input Exposure", "severity": "Critical",
                      "description": f"Found {len(sensitive_data)} sensitive input fields (password/token)."})

    forms          = crawl_data.get("forms", [])
    insecure_forms = sum(
        1 for form in forms
        if "csrf" not in str(form.get("fields", [])).lower()
        and "token" not in str(form.get("fields", [])).lower()
    )
    if insecure_forms:
        vulns.append({"type": "CSRF Risk", "severity": "Medium",
                      "description": f"{insecure_forms} form(s) detected without apparent Anti-CSRF tokens."})

    return vulns



@app.route("/api/sec-tools/health")
def sec_tools_health():
    result = _call_sec_tool("/", {}, timeout=5)
    return jsonify(result)


@app.route("/api/sec-tools/tools")
def sec_tools_list():
    """Proxy the /tools endpoint so the frontend can show which tools are live."""
    try:
        resp = http_requests.get(f"{SEC_TOOLS_URL.rstrip('/')}/tools", timeout=5)
        return jsonify(resp.json())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/report", methods=["POST"])
def download_report():
    scan_data = request.get_json() or {}

    if not scan_data.get("target"):
        return jsonify({"error": "Target is required"}), 400
    if not isinstance(scan_data.get("vulnerabilities"), list):
        return jsonify({"error": "Vulnerabilities list is required"}), 400

    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)
    filename = _build_report_filename(scan_data.get("target", ""))
    output_path = os.path.join(app.config["REPORTS_DIR"], filename)

    try:
        generate_pdf_report(scan_data, output_path)
        return send_file(
            output_path,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf",
        )
    except Exception as exc:
        logger.exception(f"Report generation failed: {exc}")
        return jsonify({"error": str(exc)}), 500


def _sse_event(checkpoint: int, name: str, data: dict) -> str:
    """Format a single SSE event line."""
    payload = {"checkpoint": checkpoint, "name": name, **data}
    return f"data: {json.dumps(payload)}\n\n"


@app.route("/api/scan", methods=["POST"])
def unified_scan():
    """SSE endpoint — streams 5 checkpoint events as each phase completes."""
    data = request.get_json()
    url  = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    def generate():
        try:
            start_time = time.time()
            logger.info(f"Unified scan starting for: {url}")

            # Kick off external tools in parallel while native scans run
            ext_ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            f_ext = ext_ex.submit(
                _call_sec_tool,
                "/scan/full",
                {
                    "target":   url,
                    "severity": "low,medium,high,critical",
                    "timeout":  300,
                },
                350,
            )


            # Checkpoint 1: Reconnaissance
            with concurrent.futures.ThreadPoolExecutor() as executor:
                f_crawl   = executor.submit(hybrid_crawler.run_hybrid_crawl, url)
                f_network = executor.submit(network_scanner.scan_target, url)

                crawl_response = f_crawl.result()
                network_res    = f_network.result() or {}


            if not isinstance(crawl_response, dict) or not crawl_response.get("success", False):
                logger.warning(f"Crawl failed for {url}")
                crawl_res   = {"engine": "hybrid", "url": url, "forms": [], "inputs": [], "links": {"total": 0}}
                crawl_error = crawl_response.get("error", "Unknown crawl failure") if isinstance(crawl_response, dict) else "Crawl failed"
            else:
                crawl_res   = crawl_response
                crawl_error = None

            crawl_res.setdefault('url', url)
            crawl_res.setdefault('inputs', [])
            crawl_res.setdefault('links', {'total': crawl_res.get('total_pages_crawled', 0)})
            crawl_res.setdefault('forms', [])
            crawl_res.setdefault('all_internal_links', [])
            crawl_res.setdefault('js_files', [])
            graph_data = crawl_res.get('graph', {'nodes': [], 'links': []})
            crawl_res.setdefault('graph', graph_data)

            for form in crawl_res.get("forms", []):
                if not form.get("action"):
                    form["action"] = url

            ip_address = "Unknown"
            if network_res.get("summary", {}).get("target_info", {}).get("ip_addresses"):
                ip_address = network_res["summary"]["target_info"]["ip_addresses"][0]

            yield _sse_event(1, "Reconnaissance", {
                "target": url,
                "ip_address": ip_address,
                "endpoints_found": crawl_res.get("total_pages_crawled", 0),
                "open_ports": network_res.get("summary", {}).get("open_ports", []),
                "graph_data": graph_data,
                "crawl_status": {
                    "success": bool(crawl_response.get("success") if isinstance(crawl_response, dict) else False),
                    "error": crawl_error,
                },
            })

            # Checkpoint 2: Surface Analysis
            with concurrent.futures.ThreadPoolExecutor() as executor:
                f_headers   = executor.submit(bs_crawler_util.check_response_headers, url)
                f_sensitive = executor.submit(bs_crawler_util.extract_sensitive_fields, url)
                f_api       = executor.submit(api_scanner.scan_url, url)

                headers_res   = f_headers.result() or {}
                sensitive_res = f_sensitive.result() or {}
                api_res       = f_api.result() or []

            injectable_params = set()
            for form in crawl_res.get("forms", []):
                for f in form.get("fields", []):
                    name = (f.get("name") or "").strip()
                    if name and (f.get("type") or "").lower() != "submit":
                        injectable_params.add(name)
            for inp in crawl_res.get("inputs", []):
                name = (inp.get("name") or "").strip()
                if name:
                    injectable_params.add(name)
            injectable_params = list(injectable_params)


            recon_vulns = analyze_vulnerabilities(
                url, crawl_res, network_res, headers_res, sensitive_res, api_res
            )
            _enrich_vulns_with_cwe(recon_vulns)

            yield _sse_event(2, "Surface Analysis", {
                "headers_found": headers_res.get("headers_found", {}),
                "headers_missing": headers_res.get("headers_missing", []),
                "sensitive_fields": len(sensitive_res) if isinstance(sensitive_res, list) else 0,
                "injectable_params": injectable_params,
                "vulnerabilities": recon_vulns,
            })

            # Checkpoint 3: Vulnerability Scanning
            sqli_res = xss_res = bac_res = ssrf_res = {"success": False, "results": []}
            dos_res  = {"success": False, "results": []}
            rate_res = {"vulnerability": "Rate Limiting Missing", "is_vulnerable": False, "details": ""}
            crypto_res = {"success": False, "findings": [], "status": "Secure"}
            integrity_res = {"success": False, "findings": [], "status": "Secure"}
            outdated_res = {"success": False, "vulnerabilities": []}
            xpath_res = {"success": False, "results": []}
            admin_res = {"success": False, "results": []}
            traversal_res = {"success": False, "results": []}
            dir_res = {"success": False, "results": []}

            with concurrent.futures.ThreadPoolExecutor() as ex2:
                f_sqli = ex2.submit(sqli_scanner.scan, {"target": crawl_res, "injectable_parameters": injectable_params})
                f_xss  = ex2.submit(xss_scanner.scan,  {"target": crawl_res, "injectable_parameters": injectable_params})
                f_bac  = ex2.submit(bac_scanner.scan,  {"target": crawl_res})
                f_ssrf = ex2.submit(ssrf_scanner.scan, {"target": crawl_res, "injectable_parameters": injectable_params})
                f_dos  = ex2.submit(dos_scanner.scan,  {"target": crawl_res, "url": url})
                f_rate = ex2.submit(RateLimitScanner({"url": url}).scan)
                f_crypto = ex2.submit(CryptographicFailuresScanner(crawl_res).scan)
                f_integrity = ex2.submit(IntegrityFailuresScanner(crawl_res).scan)
                f_outdated = ex2.submit(scan_outdated_components, url)
                f_xpath = ex2.submit(xpath_scanner.scan, {"target": crawl_res, "injectable_parameters": injectable_params})
                f_admin = ex2.submit(admin_panel_scanner.scan, {"target": crawl_res})
                f_traversal = ex2.submit(path_traversal_scanner.scan, {"target": crawl_res, "injectable_parameters": injectable_params})
                f_dir = ex2.submit(directory_listing_scanner.scan, {"target": crawl_res})

                for fut, name in (
                    (f_sqli, "sqli"), (f_xss, "xss"), (f_bac, "bac"),
                    (f_ssrf, "ssrf"), (f_dos, "dos"), (f_rate, "rate"),
                    (f_crypto, "crypto"), (f_integrity, "integrity"), (f_outdated, "outdated"),
                    (f_xpath, "xpath"), (f_admin, "admin"), (f_traversal, "traversal"), (f_dir, "dir"),
                ):
                    try:
                        result = fut.result()
                        if   name == "sqli": sqli_res = result or sqli_res
                        elif name == "xss":  xss_res  = result or xss_res
                        elif name == "bac":  bac_res  = result or bac_res
                        elif name == "ssrf": ssrf_res = result or ssrf_res
                        elif name == "dos":  dos_res  = result or dos_res
                        elif name == "rate": rate_res = result or rate_res
                        elif name == "crypto": crypto_res = result or crypto_res
                        elif name == "integrity": integrity_res = result or integrity_res
                        elif name == "outdated": outdated_res = result or outdated_res
                        elif name == "xpath": xpath_res = result or xpath_res
                        elif name == "admin": admin_res = result or admin_res
                        elif name == "traversal": traversal_res = result or traversal_res
                        elif name == "dir": dir_res = result or dir_res
                    except Exception as exc:
                        logger.exception(f"{name} scanner error: {exc}")

            scan_vulns = []
            for r in sqli_res.get("results", []):
                if r.get("vulnerable"):
                    scan_vulns.append({
                        "type": "SQL Injection", "severity": "Critical",
                        "description": f"SQLi on param '{r.get('parameter','?')}' (payload: {r.get('payload','')}) at {r.get('action', url)}"
                    })

            for r in xss_res.get("results", []):
                if r.get("vulnerable"):
                    xss_type = r.get("type", "reflected").capitalize()
                    sev = r.get("severity", "High").capitalize()
                    if sev not in _SEV_ORDER:
                        sev = "High"
                    scan_vulns.append({
                        "type": f"{xss_type} XSS", "severity": sev,
                        "description": f"XSS ({xss_type}) in param '{r.get('parameter','?')}' (payload: {r.get('payload','')}) at {r.get('action', url)}"
                    })

            for r in bac_res.get("results", []):
                if r.get("vulnerable"):
                    scan_vulns.append({
                        "type": r.get("type", "Broken Access Control"), "severity": "High",
                        "cwe": r.get("cwe"),
                        "description": f"{r.get('description','')} at {r.get('endpoint', url)}. {r.get('evidence','')}".strip()
                    })

            for r in ssrf_res.get("results", []):
                if r.get("vulnerable"):
                    scan_vulns.append({
                        "type": "Server-Side Request Forgery", "severity": "Critical",
                        "description": f"SSRF via param '{r.get('parameter','?')}' (payload: {r.get('payload','')}) at {r.get('endpoint', url)}"
                    })

            for r in dos_res.get("results", []):
                if r.get("vulnerable"):
                    scan_vulns.append({
                        "type":        r.get("type", "DoS Risk"),
                        "severity":    r.get("severity", "Medium"),
                        "description": r.get("description", ""),
                    })

            if rate_res.get("is_vulnerable"):
                scan_vulns.append({
                    "type":        rate_res.get("vulnerability", "Rate Limiting Missing"),
                    "severity":    "Medium",
                    "description": rate_res.get("details", "No rate limiting detected."),
                })

            scan_vulns.extend(_normalize_internal_findings(
                crypto_res.get("findings", []),
                "Garud",
            ))
            scan_vulns.extend(_normalize_internal_findings(
                integrity_res.get("findings", []),
                "Garud",
            ))
            scan_vulns.extend(_normalize_vulnerability_entries(
                outdated_res.get("vulnerabilities", []),
                "Garud",
            ))
            scan_vulns.extend(_normalize_internal_findings(
                xpath_res.get("results", []),
                "Garud",
            ))
            scan_vulns.extend(_normalize_internal_findings(
                admin_res.get("results", []),
                "Garud",
            ))
            scan_vulns.extend(_normalize_internal_findings(
                traversal_res.get("results", []),
                "Garud",
            ))
            scan_vulns.extend(_normalize_internal_findings(
                dir_res.get("results", []),
                "Garud",
            ))

            scan_vulns = _dedupe_vulnerabilities(scan_vulns)
            scan_vulns = _filter_new_vulnerabilities(recon_vulns, scan_vulns)
            _enrich_vulns_with_cwe(scan_vulns)

            yield _sse_event(3, "Vulnerability Scanning", {
                "vulnerabilities": scan_vulns,
                "scanner_results": {
                    "sqli":       sqli_res,
                    "xss":        xss_res,
                    "bac":        bac_res,
                    "ssrf":       ssrf_res,
                    "dos":        dos_res,
                    "rate_limit": rate_res,
                    "cryptographic_failures": crypto_res,
                    "integrity_failures": integrity_res,
                    "outdated_components": outdated_res,
                    "xpath":      xpath_res,
                    "admin":      admin_res,
                    "traversal":  traversal_res,
                    "dir":        dir_res,
                },
            })

            # Checkpoint 4: External Tools
            ext_findings: list[dict] = []
            tool_errors:  dict       = {}

            try:

                elapsed = time.time() - start_time
                wait_time = max(10, 360 - elapsed)
                ext_result   = f_ext.result(timeout=wait_time)
                ext_findings = ext_result.get("findings", [])
                tool_errors  = ext_result.get("tool_errors", {})
                if ext_findings:
                    logger.info(f"External tools returned {len(ext_findings)} findings")
            except concurrent.futures.TimeoutError:
                logger.warning("External security scan timed out")
            except Exception as exc:
                logger.warning(f"External security scan error: {exc}")
            finally:
                ext_ex.shutdown(wait=False)

            ext_vulns = _external_findings_to_vulns(ext_findings)
            ext_vulns = _dedupe_vulnerabilities(ext_vulns)
            ext_vulns = _filter_new_vulnerabilities(recon_vulns + scan_vulns, ext_vulns)
            _enrich_vulns_with_cwe(ext_vulns)

            yield _sse_event(4, "External Tools", {
                "vulnerabilities": ext_vulns,
                "external": {
                    "findings":    ext_findings,
                    "count":       len(ext_findings),
                    "tool_errors": tool_errors,
                    "by_tool": {
                        tool: [f for f in ext_findings if f.get("tool") == tool]
                        for tool in ("nuclei", "sqlmap", "nikto", "tsunami")
                    },
                },
            })

            # Checkpoint 5: Final Report
            all_vulns = _dedupe_vulnerabilities(recon_vulns + scan_vulns + ext_vulns)
            all_vulns.sort(key=lambda v: _SEV_ORDER.get(v.get("severity", "Info"), 5))

            duration       = round(time.time() - start_time, 2)
            endpoint_count = crawl_res.get("total_pages_crawled", 0)

            # Final scoring pass
            score_result = _compute_cwe_score(all_vulns)
            status = score_result["status"]

            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for v in all_vulns:
                sev_counts[v.get("severity", "Info")] = sev_counts.get(v.get("severity", "Info"), 0) + 1

            yield _sse_event(5, "Final Report", {
                "target":          url,
                "ip_address":      ip_address,
                "scan_duration":   f"{duration}s",
                "endpoints_found": endpoint_count,
                "status":          status,
                "security_score":  score_result["score"],
                "security_grade":  score_result["grade"],
                "severity_counts": sev_counts,
                "open_ports":      network_res.get("summary", {}).get("open_ports", []),
                "graph_data":      graph_data,
                "summary_text": (
                    f"Garud scan complete. Crawled {endpoint_count} nodes on {ip_address}. "
                    f"Found {len(all_vulns)} issues — "
                    f"{sev_counts['Critical']} Critical, {sev_counts['High']} High, "
                    f"{sev_counts['Medium']} Medium, {sev_counts['Low']} Low. "
                    f"({len(ext_findings)} from Nuclei/SQLMap/Nikto/Tsunami)"
                ),
                "vulnerabilities": all_vulns,
                "scanner_results": {
                    "sqli":       sqli_res,
                    "xss":        xss_res,
                    "api":        api_res,
                    "bac":        bac_res,
                    "ssrf":       ssrf_res,
                    "dos":        dos_res,
                    "rate_limit": rate_res,
                    "cryptographic_failures": crypto_res,
                    "integrity_failures": integrity_res,
                    "outdated_components": outdated_res,
                    "xpath":      xpath_res,
                    "admin":      admin_res,
                    "traversal":  traversal_res,
                    "dir":        dir_res,
                    "external": {
                        "findings":    ext_findings,
                        "count":       len(ext_findings),
                        "tool_errors": tool_errors,
                        "by_tool": {
                            tool: [f for f in ext_findings if f.get("tool") == tool]
                            for tool in ("nuclei", "sqlmap", "nikto", "tsunami")
                        },
                    },
                },
                "crawl_status": {
                    "success": bool(crawl_response.get("success") if isinstance(crawl_response, dict) else False),
                    "error":   crawl_error,
                },
                "complete": True,
            })

        except Exception as exc:
            logger.exception(f"Scan failed: {exc}")
            yield _sse_event(0, "Error", {"error": str(exc)})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
