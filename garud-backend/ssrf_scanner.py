import requests
import uuid
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LISTENER_URL = "http://127.0.0.1:8002"

class SSRFScanner:
    def __init__(self):
        self.suspicious_params = [
            'url', 'uri', 'endpoint', 'path', 'dest', 'target', 
            'redirect', 'webhook', 'source', 'src', 'forward'
        ]

    def scan(self, data: dict):
        results = []
        target = data.get("target", {})
        injectable_parameters = data.get("injectable_parameters", [])
        forms = target.get("forms", [])
        
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            
            for field in form.get("fields", []):
                name = field.get("name", "")
                if not name:
                    continue
                
                if name.lower() in self.suspicious_params or name in injectable_parameters:
                    token = str(uuid.uuid4())
                    payload = f"{LISTENER_URL}/hit/{token}"
                    
                    try:
                        test_data = {name: payload}
                        if method == "POST":
                            requests.post(action, data=test_data, timeout=5, verify=False)
                        else:
                            requests.get(action, params=test_data, timeout=5, verify=False)
                        
                        check_req = requests.get(f"{LISTENER_URL}/check/{token}", timeout=3)
                        if check_req.json().get("hit"):
                            results.append({
                                "vulnerable": True,
                                "endpoint": action,
                                "parameter": name,
                                "payload": payload,
                                "description": f"OAST SSRF confirmed via parameter '{name}'",
                                "method": method
                            })
                    except Exception:
                        pass

        return {"success": True, "engine": "ssrf_scanner", "results": results}