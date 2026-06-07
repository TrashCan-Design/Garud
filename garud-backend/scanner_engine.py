import requests
from bs4 import BeautifulSoup
import time
import random
from crawler_manager import HybridCrawlerManager
from sqli_scanner import SQLiScanner
from xss_scanner import XSSScanner

def check_security_headers(headers):
    missing = []
    required = {
        "X-Frame-Options": "Prevents Clickjacking attacks.",
        "Content-Security-Policy": "Mitigates XSS and data injection.",
        "Strict-Transport-Security": "Enforces secure (HTTPS) connections."
    }
    for key, desc in required.items():
        if key not in headers:
            missing.append({
                "type": "Missing Header",
                "name": key,
                "severity": "Low",
                "description": desc,
                "recommendation": f"Configure the server to include the {key} header."
            })
    return missing

def check_heuristics(url, html_content):
    issues = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    inputs = soup.find_all('input')
    if len(inputs) > 0:
        has_csrf = any('csrf' in str(i).lower() for i in inputs)
        if not has_csrf:
            issues.append({
                "type": "CSRF Risk",
                "name": "Missing CSRF Token",
                "severity": "Medium",
                "description": "HTML forms found without apparent CSRF protection.",
                "recommendation": "Implement anti-CSRF tokens in all state-changing forms."
            })

    if "=" in url:
        issues.append({
            "type": "SQL Injection (Heuristic)",
            "name": "URL Parameter Risk",
            "severity": "High",
            "description": "URL parameters detected. Ensure inputs are sanitized.",
            "recommendation": "Use prepared statements and parameterized queries."
        })

    return issues

def perform_scan(target_url):
    time.sleep(random.uniform(0.5, 1.5)) 
    
    log = []
    vulnerabilities = []
    
    try:
        log.append(f"Initiating connection to {target_url}...")
        start_time = time.time()
        response = requests.get(target_url, timeout=5, verify=False)
        log.append(f"Connection established. Status: {response.status_code}")
        
        log.append("Analyzing HTTP Security Headers...")
        vulnerabilities.extend(check_security_headers(response.headers))
        
        log.append("Parsing HTML content for input vectors...")
        vulnerabilities.extend(check_heuristics(target_url, response.text))
        
        log.append("Running Hybrid Crawler to extract forms and links...")
        crawler = HybridCrawlerManager(max_depth=2)
        crawler_results = crawler.run_hybrid_crawl(target_url)
        forms = crawler_results.get('forms', [])
        
        log.append(f"Discovered {len(forms)} forms. Proceeding to deep scans...")
        scan_target = {
            "target": {
                "url": target_url,
                "forms": forms
            }
        }

        log.append("Executing SQL Injection Scanner...")
        sqli = SQLiScanner()
        sqli_res = sqli.scan(scan_target)
        if sqli_res.get("success"):
            for res in sqli_res.get("results", []):
                vulnerabilities.append({
                    "type": "SQL Injection",
                    "name": "SQL Injection Vulnerability",
                    "severity": "Critical",
                    "description": f"Parameter '{res['parameter']}' is vulnerable to SQLi at {res['action']}.",
                    "recommendation": "Use parameterized queries or prepared statements."
                })

        log.append("Executing XSS Scanner...")
        xss = XSSScanner()
        xss_res = xss.scan(scan_target)
        if xss_res.get("success"):
            for res in xss_res.get("results", []):
                vulnerabilities.append({
                    "type": "Cross-Site Scripting",
                    "name": "Reflected XSS",
                    "severity": "High",
                    "description": f"Parameter '{res['parameter']}' is vulnerable to XSS at {res['action']}.",
                    "recommendation": "Sanitize and encode user inputs contextually."
                })
        
        log.append("Scan completed successfully.")
        
        return {
            "status": "success",
            "target": target_url,
            "scan_duration": f"{time.time() - start_time:.2f}s",
            "vulnerabilities": vulnerabilities,
            "logs": log,
            "stats": {
                "critical": len([v for v in vulnerabilities if v['severity'] == 'Critical']),
                "high": len([v for v in vulnerabilities if v['severity'] == 'High']),
                "medium": len([v for v in vulnerabilities if v['severity'] == 'Medium']),
                "low": len([v for v in vulnerabilities if v['severity'] == 'Low']),
            }
        }
        
    except Exception as e:
        return {
            "status": "error",
            "logs": [f"Error connecting to target: {str(e)}"],
            "vulnerabilities": []
        }