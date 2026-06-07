import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

class APIScanner:
    def __init__(self):
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36}',
            'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Publishable': r'pk_live_[0-9a-zA-Z]{24}',
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'Facebook Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Generic API Key': r'api[_-]?key[\'"\s:=]+[\'"\s]?[0-9a-zA-Z]{32,45}[\'"\s]?',
            'Private Key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
            'Firebase URL': r'.*firebaseio\.com',
            'MongoDB URI': r'mongodb(\+srv)?://[^\s]+:[^\s]+@[^\s]+',
            'Postgres URI': r'postgresql://[^\s]+:[^\s]+@[^\s]+',
            'OpenAI Key': r'sk-[a-zA-Z0-9]{48}'
        }

    def scan_url(self, target_url):
        """
        Scans HTML and linked JS files for secrets
        """
        findings = []
        try:
            logger.info(f"API Scanner checking: {target_url}")
            
            
            session = requests.Session()
            session.headers.update({'User-Agent': 'Garud-Scanner/2.0'})
            response = session.get(target_url, timeout=10, verify=False)
            
            if response.status_code != 200:
                return []

            
            findings.extend(self._scan_text(response.text, "Main HTML Page"))

            
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = [script.get('src') for script in soup.find_all('script', src=True)]

            
            for script_url in scripts[:10]:
                if not script_url.startswith('http'):
                    script_url = urljoin(target_url, script_url)
                
                try:
                    js_res = session.get(script_url, timeout=5, verify=False)
                    if js_res.status_code == 200:
                        findings.extend(self._scan_text(js_res.text, script_url))
                except:
                    continue

            return findings

        except Exception as e:
            logger.error(f"API Scan Error: {e}")
            return []

    def _scan_text(self, content, source):
        """
        Runs regex patterns on text content
        """
        results = []
        for key_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                secret = match.group()
                
                if self._is_false_positive(secret):
                    continue
                    
                results.append({
                    "type": "Exposed Secret",
                    "name": key_type,
                    "severity": "Critical", 
                    "description": f"Found {key_type} in {source}.",
                    "match": self._mask_secret(secret)
                })
        return results

    def _is_false_positive(self, match):
        """Simple filter for common dummy text"""
        dummies = ['YOUR_API_KEY', 'EXAMPLE', '123456789', 'abcdef', 'placeholder']
        return any(d.lower() in match.lower() for d in dummies)

    def _mask_secret(self, secret):
        """Masks secret for display"""
        if len(secret) < 8: return "****"
        return secret[:4] + "..." + secret[-4:]