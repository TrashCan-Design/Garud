import os
import re
import json
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


SEVERITY_ORDER = {
    "Critical": 0,
    "Medium": 1,
    "Low": 2,
    "Info": 3,
    "Suggestion": 4
}

DEFAULT_CVSS = {
    "Critical": 9.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Info": 0.0,
    "Suggestion": 0.0
}

EASE_MAP = {
    "Missing Security Header": "Easy",
    "CSRF Risk": "Medium",
    "Sensitive Input Exposure": "Medium",
    "SQL Injection": "Hard",
    "Reflected XSS": "Medium",
    "Stored XSS": "Hard",
    "Broken Access Control": "Hard",
    "Server-Side Request Forgery": "Hard",
    "Rate Limiting Missing": "Easy",
    "Missing DDoS/WAF Protection": "Medium",
    "Exposed Secret": "Hard",
    "Database Port Open": "Medium",
    "Telnet Exposed": "Easy",
    "Insecure FTP": "Easy",
    "Potential Denial of Service": "Medium",
    "XPath Injection": "Hard",
    "Exposed Admin Panel": "Medium",
    "Path Traversal": "Hard",
    "Directory Listing": "Easy"
}

CWE_MAP = {
    "SQL Injection": "CWE-89",
    "Reflected XSS": "CWE-79",
    "Stored XSS": "CWE-79",
    "Dom XSS": "CWE-79",
    "DOM XSS": "CWE-79",
    "Missing Security Header": "CWE-693",
    "CSRF Risk": "CWE-352",
    "Sensitive Input Exposure": "CWE-200",
    "Broken Access Control": "CWE-284",
    "Server-Side Request Forgery": "CWE-918",
    "Rate Limiting Missing": "CWE-770",
    "Missing DDoS/WAF Protection": "CWE-693",
    "Exposed Secret": "CWE-798",
    "Database Port Open": "CWE-200",
    "Telnet Exposed": "CWE-319",
    "Insecure FTP": "CWE-319",
    "Potential Denial of Service": "CWE-400",
    "Cryptographic Failure": "CWE-310",
    "Weak Cipher Suite": "CWE-310",
    "Mass Assignment / Parameter Pollution": "CWE-915",
    "Missing Authorization": "CWE-862",
    "IDOR": "CWE-639",
    "HTTP Verb Tampering": "CWE-284",
    "Header-Based Authorization Bypass": "CWE-285",
    "Path Confusion": "CWE-863",
    "Privilege Escalation": "CWE-269",
    "Missing Authentication": "CWE-306",
    "CORS Misconfiguration": "CWE-942",
    "XPath Injection": "CWE-643",
    "Exposed Admin Panel": "CWE-200",
    "Path Traversal": "CWE-22",
    "Directory Listing": "CWE-548"
}

# Load CWE ref data from disk
CWE_REF_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cwe_reference.json")
CWE_REFERENCE_CACHE = {}
if os.path.exists(CWE_REF_PATH):
    try:
        with open(CWE_REF_PATH, "r", encoding="utf-8") as f:
            CWE_REFERENCE_CACHE = json.load(f)
    except Exception:
        pass


def clean_cwe(cwe_str):
    if not cwe_str:
        return ""
    match = re.search(r'(?:CWE|cwe)[-_\s]?(\d+)', str(cwe_str))
    if match:
        return f"CWE-{match.group(1)}"
    return ""


def get_cvss_and_severity(vuln: dict) -> tuple[float, str]:
    cvss_val = vuln.get("cvss_score") if vuln.get("cvss_score") is not None else vuln.get("cvss")
    if cvss_val is not None and cvss_val != "":
        try:
            if isinstance(cvss_val, str) and "(" in cvss_val:
                cvss_val = cvss_val.split("(")[0].strip()
            cvss_float = float(cvss_val)
            if cvss_float >= 7.0:
                severity = "Critical"
            elif cvss_float >= 4.0:
                severity = "Medium"
            elif cvss_float >= 0.1:
                severity = "Low"
            else:
                severity = "Info"
            return cvss_float, severity
        except (ValueError, TypeError):
            pass

    cwe_id = clean_cwe(vuln.get("cwe"))
    if cwe_id and cwe_id in CWE_REFERENCE_CACHE:
        entry = CWE_REFERENCE_CACHE[cwe_id]
        cvss_fallback = float(entry.get("cvss", 0.0))
        severity = entry.get("classification", "Info")
        if severity == "High":
            severity = "Critical"
        return cvss_fallback, severity

    return 0.0, "Suggestion"


def clean_text(value):
    if value is None:
        return ""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def get_cvss(vuln):
    cvss, _ = get_cvss_and_severity(vuln)
    return cvss


def get_cwe(vuln):
    cwe = clean_cwe(vuln.get("cwe"))
    if cwe:
        return cwe
    vuln_type = vuln.get("type", "")
    cwe_raw = CWE_MAP.get(vuln_type)
    if not cwe_raw:
        for key, val in CWE_MAP.items():
            if key.lower() in vuln_type.lower():
                cwe_raw = val
                break
    return cwe_raw if cwe_raw else "—"


def get_ease(vuln):
    return EASE_MAP.get(vuln.get("type", ""), "Medium")


def normalize_source(vuln):
    source = vuln.get("source")
    if not source:
        return "Garud"
    source = str(source).strip()
    source_lower = source.lower()
    
    external_tools = ["nuclei", "sqlmap", "nikto", "tsunami", "nmap"]
    for tool in external_tools:
        if tool in source_lower:
            return tool.capitalize()
            
    return "Garud"


def is_external_tool(vuln):
    source = normalize_source(vuln).lower()
    return source in ["nuclei", "sqlmap", "nikto", "tsunami", "nmap"]


def enrich_findings(vulnerabilities):
    enriched = []
    for vuln in vulnerabilities:
        item = dict(vuln)
        cvss, severity = get_cvss_and_severity(item)
        item["severity"] = severity
        item["cvss_score"] = cvss
        item["cwe"] = get_cwe(item)
        item["ease_of_fix"] = get_ease(item)
        item["source"] = normalize_source(item)
        enriched.append(item)

    enriched.sort(
        key=lambda v: (
            SEVERITY_ORDER.get(v.get("severity", "Info"), 9),
            -float(v.get("cvss_score", 0))
        )
    )
    return enriched


def count_by_severity(findings):
    counts = {
        "Critical": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Suggestion": 0
    }
    for f in findings:
        sev = f.get("severity", "Info")
        if sev == "High":
            sev = "Critical"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def add_table(story, title, findings, styles):
    story.append(Paragraph(title, styles["Heading2"]))
    story.append(Spacer(1, 8))

    data = [[
        "Severity",
        "Finding",
        "CVSS",
        "CWE",
        "Ease",
        "Source",
        "Description"
    ]]

    if not findings:
        tool_name = "Garud"
        if "Internal" in title:
            tool_name = "Garud"
        elif "External" in title:
            tool_name = "External Tools"
        data.append(["—", f"✓ {tool_name} completed \u2014 no findings detected.", "—", "—", "—", "—", "—"])
    else:
        for v in findings:
            cwe_val = v.get("cwe", "—")
            if cwe_val and cwe_val != "—":
                num = cwe_val.split('-')[1] if '-' in cwe_val else ""
                url = f"https://cwe.mitre.org/data/definitions/{num}.html" if num else "https://cwe.mitre.org/data/definitions/"
                cwe_display = f'<a href="{url}"><font color="blue">{clean_text(cwe_val)}</font></a>'
            else:
                cwe_display = "—"

            data.append([
                Paragraph(clean_text(v.get("severity", "Info")), styles["BodyText"]),
                Paragraph(clean_text(v.get("type", "Unknown")), styles["BodyText"]),
                Paragraph(clean_text(f"{float(v.get('cvss_score', 0.0)):.1f}"), styles["BodyText"]),
                Paragraph(cwe_display, styles["BodyText"]),
                Paragraph(clean_text(v.get("ease_of_fix", "Medium")), styles["BodyText"]),
                Paragraph(clean_text(v.get("source", "Garud")), styles["BodyText"]),
                Paragraph(clean_text(v.get("description", "")), styles["BodyText"]),
            ])

    table = Table(
        data,
        repeatRows=1,
        colWidths=[60, 100, 45, 70, 55, 80, 250]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
    ]))

    story.append(table)
    story.append(Spacer(1, 18))


def generate_pdf_report(scan_data, output_path):
    vulnerabilities = scan_data.get("vulnerabilities", [])
    enriched = enrich_findings(vulnerabilities)

    internal_findings = [v for v in enriched if not is_external_tool(v)]
    external_findings = [v for v in enriched if is_external_tool(v)]

    counts = count_by_severity(enriched)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=landscape(A4),
        rightMargin=25,
        leftMargin=25,
        topMargin=25,
        bottomMargin=25
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Garud Security Scan Report", styles["Title"]))
    story.append(Spacer(1, 10))

    score = scan_data.get("security_score")
    grade = scan_data.get("security_grade")
    
    # Compute score if backend didn't provide one
    if score is None:
        seen_cwes = {}
        total_penalty = 0.0
        for vuln in enriched:
            cwe = vuln.get("cwe")
            cvss = vuln.get("cvss_score", 0.0)
            count = seen_cwes.get(cwe, 0)
            weight = 1.0 if count == 0 else 0.3
            seen_cwes[cwe] = count + 1
            total_penalty += cvss * weight
        score = max(0.0, round(100.0 - total_penalty, 1))
        
        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 25:
            grade = "D"
        else:
            grade = "F"

    summary = f"""
    <b>Target:</b> {clean_text(scan_data.get("target", "Unknown"))}<br/>
    <b>IP Address:</b> {clean_text(scan_data.get("ip_address", "Unknown"))}<br/>
    <b>Risk Level:</b> {clean_text(scan_data.get("status", "Unknown"))}<br/>
    <b>Scan Duration:</b> {clean_text(scan_data.get("scan_duration", "Unknown"))}<br/>
    <b>Endpoints Found:</b> {clean_text(scan_data.get("endpoints_found", 0))}<br/>
    <b>Generated On:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    """

    story.append(Paragraph(summary, styles["Normal"]))
    story.append(Spacer(1, 14))

    severity_summary = [
        ["Critical", "Medium", "Low", "Info", "Suggestion", "Total"],
        [
            counts.get("Critical", 0),
            counts.get("Medium", 0),
            counts.get("Low", 0),
            counts.get("Info", 0),
            counts.get("Suggestion", 0),
            len(enriched)
        ]
    ]

    sev_table = Table(severity_summary, colWidths=[90, 90, 90, 90, 100, 90])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))

    story.append(sev_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph(
        "This report separates Garud scanner findings from external tool findings. "
        "All findings are mapped with severity, approximate CVSS score, CWE category, and ease of fixing.",
        styles["Normal"]
    ))

    story.append(PageBreak())

    add_table(
        story,
        "1. Garud Findings",
        internal_findings,
        styles
    )

    add_table(
        story,
        "2. External Tool Findings",
        external_findings,
        styles
    )

    story.append(PageBreak())

    add_table(
        story,
        "3. Combined Severity View",
        enriched,
        styles
    )

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "Note: If an external tool does not provide a CVSS score, Garud assigns an approximate CVSS value based on severity.",
        styles["Italic"]
    ))

    doc.build(story)