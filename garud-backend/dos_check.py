import requests
import time
import logging
import urllib3
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

class DoSScanner:
    def __init__(self):
        self.threads = 10
        self.waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "Akamai": ["x-akamai-request-id", "akamai"],
            "AWS WAF / CloudFront": ["x-amz-cf-id", "awselb"],
            "Fastly": ["x-fastly-request-id", "fastly"],
            "Sucuri": ["x-sucuri-id", "sucuri/cloudproxy"],
            "Incapsula": ["x-cdn", "incapsula"],
            "F5 BIG-IP": ["bigipserver"]
        }

    def _probe(self, url: str):
        start = time.time()
        try:
            r = requests.get(url, timeout=10, verify=False)
            return time.time() - start, r.headers
        except Exception:
            return None, {}

    def scan(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        # Extract target URL
        url = target_data.get("target", {}).get("url")
        if not url:
            url = target_data.get("url") # Fallback if not nested
            
        if not url:
            return {"success": False, "results": []}

        logger.info(f"Starting DoS & WAF Scan on {url}")
        
        baseline_data = self._probe(url)
        if baseline_data[0] is None:
            return {"success": False, "results": []}

        baseline_time, headers = baseline_data
        
        # WAF and DDoS detection
        headers_str = str(headers).lower()
        server_header = headers.get("Server", "").lower()
        provider = "None"
        is_protected = False
        
        for prov, sigs in self.waf_signatures.items():
            if any(sig.lower() in headers_str or sig.lower() in server_header for sig in sigs):
                provider = prov
                is_protected = True
                break
        
        if is_protected:
            results.append({
                "vulnerable": True,
                "type": "Security Control Detected",
                "severity": "Suggestion",
                "description": f"DDoS/WAF Protection detected: {provider}. Active DoS testing may be blocked or rate-limited."
            })
        else:
            results.append({
                "vulnerable": True,
                "type": "Missing DDoS/WAF Protection",
                "severity": "Medium",
                "description": "No Web Application Firewall or Anti-DDoS provider detected in HTTP headers. Server IP is likely exposed."
            })

        # Latency check under load
        def load_probe(_):
            start = time.time()
            try:
                requests.get(url, timeout=10, verify=False)
                return time.time() - start
            except:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            latencies = list(executor.map(load_probe, range(self.threads)))

        valid_latencies = [l for l in latencies if l is not None]
        if valid_latencies:
            avg_load_latency = sum(valid_latencies) / len(valid_latencies)
            is_dos_vulnerable = avg_load_latency > (baseline_time * 3)

            if is_dos_vulnerable and not is_protected:
                results.append({
                    "vulnerable": True,
                    "type": "Potential Denial of Service",
                    "severity": "High",
                    "description": f"Resource Exhaustion detected. Baseline load: {baseline_time:.2f}s, Under load ({self.threads} threads): {avg_load_latency:.2f}s."
                })

        return {
            "success": True, 
            "engine": "dos_scanner",
            "results": results
        }