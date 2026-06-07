import requests
import time

class RateLimitScanner:
    def __init__(self, target_data):

        self.target_url = target_data.get("url")
        self.limit_threshold = 15
        
    def scan(self):
        print(f"Starting Rate Limit Scan on {self.target_url}")
        results = []
        is_vulnerable = True
        
        for i in range(self.limit_threshold):
            try:
                response = requests.get(self.target_url, timeout=1)
                results.append(response.status_code)
                
                if response.status_code == 429:
                    is_vulnerable = False
                    break
            except Exception as e:
                return {"status": "error", "message": str(e)}

        return {
            "vulnerability": "Rate Limiting Missing",
            "is_vulnerable": is_vulnerable,
            "details": f"Sent {len(results)} requests. Status codes received: {results}",
            "recommendation": "Implement 429 Too Many Requests status codes and IP-based throttling."
        }