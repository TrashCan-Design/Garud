
import ssl
import socket
import threading
import time
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs


_PROBE_TLS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
}


_WEAK_CIPHER_TOKENS = {
    "RC4":     ("RC4 stream cipher – multiple statistical biases", "Critical"),
    "DES":     ("Single DES – 56-bit key, brute-forceable", "Critical"),
    "3DES":    ("Triple DES – Sweet32 birthday attack (CVE-2016-2183)", "High"),
    "NULL":    ("NULL cipher – no encryption at all", "Critical"),
    "EXPORT":  ("Export-grade 40-bit encryption – trivially broken", "Critical"),
    "aNULL":   ("Anonymous auth – no server identity verification", "High"),
}


_DISCLOSURE_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
)


_SENSITIVE_PARAMS = (
    "password", "passwd", "token", "secret", "apikey",
    "api_key", "auth", "session", "sessid", "access_token",
    "private_key", "credential",
)



_tls_cache: dict = {}
_cache_lock = threading.Lock()
_CACHE_TTL  = 1800  # seconds


def _cache_get(hostname: str):
    with _cache_lock:
        entry = _tls_cache.get(hostname)
        if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
            return entry["data"]
    return None


def _cache_set(hostname: str, data: dict) -> None:
    with _cache_lock:
        _tls_cache[hostname] = {"data": data, "ts": time.time()}




def _probe_tls_versions(hostname: str, port: int = 443) -> dict:
    supported = {}
    for label, tls_ver in _PROBE_TLS.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = tls_ver
            ctx.maximum_version = tls_ver
            ctx.check_hostname  = False
            ctx.verify_mode     = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=hostname):
                    supported[label] = True
        except Exception:
            supported[label] = False
    return supported


def _probe_weak_ciphers(hostname: str, port: int = 443) -> list:
    accepted = []
    for token in _WEAK_CIPHER_TOKENS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.set_ciphers(token)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=hostname):
                    accepted.append(token)
        except Exception:
            pass
    return accepted


def _get_certificate_info(hostname: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                cert   = ss.getpeercert()
                cipher = ss.cipher()  # (name, protocol, bits)
                return {"cert": cert, "cipher": cipher, "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"cert": None, "cipher": None, "error": f"cert_verify:{e}"}
    except Exception as e:
        return {"cert": None, "cipher": None, "error": str(e)}


def _tls_data_for_host(hostname: str, port: int = 443) -> dict:
    """
    """
    cached = _cache_get(hostname)
    if cached:
        return cached

    data = {
        "tls_versions":  _probe_tls_versions(hostname, port),
        "weak_ciphers":  _probe_weak_ciphers(hostname, port),
        "cert_info":     _get_certificate_info(hostname, port),
    }
    _cache_set(hostname, data)
    return data




def _check_https(url: str) -> list:
    findings = []
    if urlparse(url).scheme != "https":
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "No HTTPS",
            "severity":       "Critical",
            "description":    f"The target URL uses HTTP, not HTTPS: {url}",
            "recommendation": "Enforce HTTPS site-wide. Redirect all HTTP traffic to HTTPS and set HSTS.",
        })
    return findings


def _check_tls_versions(tls_versions: dict) -> list:
    findings = []

    if tls_versions.get("TLSv1.0"):
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "Weak TLS Version: TLSv1.0",
            "severity":       "High",
            "description":    "The server accepts TLS 1.0, which is deprecated (PCI-DSS non-compliant since 2018).",
            "recommendation": "Disable TLS 1.0 in your server config. Enforce TLS 1.2 minimum.",
        })

    if tls_versions.get("TLSv1.1"):
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "Weak TLS Version: TLSv1.1",
            "severity":       "High",
            "description":    "The server accepts TLS 1.1, deprecated by RFC 8996 (2021).",
            "recommendation": "Disable TLS 1.1. Enforce TLS 1.2 minimum; prefer TLS 1.3.",
        })

    if not tls_versions.get("TLSv1.2"):
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "TLS 1.2 Not Available",
            "severity":       "High",
            "description":    "The server does not accept TLS 1.2, meaning clients may fall back to weaker protocols.",
            "recommendation": "Enable TLS 1.2 and TLS 1.3 as the only accepted versions.",
        })

    return findings


def _check_weak_ciphers(accepted_ciphers: list) -> list:
    findings = []
    for token in accepted_ciphers:
        desc, severity = _WEAK_CIPHER_TOKENS[token]
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           f"Weak Cipher Suite: {token}",
            "severity":       severity,
            "description":    f"Server accepted cipher token '{token}': {desc}.",
            "recommendation": "Configure server to accept only AEAD suites (AES-GCM, ChaCha20-Poly1305). "
                              "Use Mozilla SSL Configuration Generator for a safe preset.",
        })
    return findings


def _check_certificate(cert_info: dict, hostname: str) -> list:
    findings = []
    cert  = cert_info.get("cert")
    error = cert_info.get("error", "")

    if error:

        if "cert_verify" in str(error):
            findings.append({
                "type":           "Cryptographic Failure",
                "name":           "Certificate Validation Failed",
                "severity":       "Critical",
                "description":    f"SSL certificate for {hostname} failed validation: {error}",
                "recommendation": "Obtain a valid certificate from a trusted CA (e.g. Let's Encrypt).",
            })
        return findings

    if not cert:
        return findings


    not_after_raw = cert.get("notAfter")
    if not_after_raw:
        try:
            not_after = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
            days_left  = (not_after - datetime.utcnow()).days
            if days_left < 0:
                findings.append({
                    "type":           "Cryptographic Failure",
                    "name":           "Expired Certificate",
                    "severity":       "Critical",
                    "description":    f"Certificate expired {abs(days_left)} days ago ({not_after_raw}).",
                    "recommendation": "Renew the certificate immediately.",
                })
            elif days_left < 30:
                findings.append({
                    "type":           "Cryptographic Failure",
                    "name":           "Certificate Expiring Soon",
                    "severity":       "Medium",
                    "description":    f"Certificate expires in {days_left} days ({not_after_raw}).",
                    "recommendation": "Renew before expiry. Consider automating renewal with certbot/ACME.",
                })
        except ValueError:
            pass


    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    if subject.get("commonName") and subject == issuer:
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "Self-Signed Certificate",
            "severity":       "High",
            "description":    f"Certificate for {hostname} is self-signed and will not be trusted by browsers.",
            "recommendation": "Replace with a certificate from a trusted CA.",
        })


    cipher = cert_info.get("cipher")
    if cipher:
        cipher_name = cipher[0] if cipher else ""
        cipher_bits = cipher[2] if cipher and len(cipher) > 2 else 256
        if cipher_bits and cipher_bits < 128:
            findings.append({
                "type":           "Cryptographic Failure",
                "name":           f"Weak Cipher Negotiated: {cipher_name}",
                "severity":       "High",
                "description":    f"Live connection negotiated {cipher_name} with only {cipher_bits}-bit key material.",
                "recommendation": "Prioritise AES-256-GCM or ChaCha20-Poly1305 in your cipher order.",
            })

    return findings


def _check_hsts(response_headers: dict) -> list:
    findings = []
    hsts = response_headers.get("Strict-Transport-Security", "")
    if not hsts:
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "Missing HSTS Header",
            "severity":       "Medium",
            "description":    "The Strict-Transport-Security header is absent. Browsers may allow HTTP downgrade attacks.",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        })
    else:
        import re
        match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.I)
        if match and int(match.group(1)) < 31536000:
            findings.append({
                "type":           "Cryptographic Failure",
                "name":           "Weak HSTS max-age",
                "severity":       "Low",
                "description":    f"HSTS max-age is {match.group(1)}s — below the recommended 31536000s (1 year).",
                "recommendation": "Set max-age to at least 31536000 seconds.",
            })
    return findings


def _check_disclosure_headers(response_headers: dict) -> list:
    findings = []
    for h in _DISCLOSURE_HEADERS:
        val = response_headers.get(h)
        if val:
            findings.append({
                "type":           "Information Disclosure",
                "name":           f"Exposed Header: {h}",
                "severity":       "Low",
                "description":    f"{h}: {val!r} — reveals server stack details useful to attackers.",
                "recommendation": f"Remove or mask the {h} header in your server/framework config.",
            })
    return findings


def _check_sensitive_urls(urls: list) -> list:
    """Scan query parameters for sensitive keys."""
    findings = []
    seen_params: set = set()

    for url in urls:
        try:
            params = parse_qs(urlparse(url).query)
        except Exception:
            continue
        for param in params:
            key = param.lower()
            for kw in _SENSITIVE_PARAMS:
                if kw in key and param not in seen_params:
                    seen_params.add(param)
                    findings.append({
                        "type":           "Cryptographic Failure",
                        "name":           f"Sensitive Data in URL: {param}",
                        "severity":       "High",
                        "description":    f"Parameter '{param}' appears in a URL query string, which is logged by "
                                          f"servers, proxies, and browser history. Found in: {url}",
                        "recommendation": "Move sensitive values to POST body or Authorization header. "
                                          "Never pass credentials, tokens, or secrets in URL parameters.",
                    })

    return findings


def _check_mixed_content(js_files: list, links: list, base_scheme: str) -> list:
    #Flag HTTP sub-resources on HTTPS pages
    findings = []
    if base_scheme != "https":
        return findings  # site isn't HTTPS at all — flagged elsewhere

    http_js = [f for f in js_files if isinstance(f, str) and f.startswith("http://")]
    if http_js:
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "Mixed Content: HTTP JavaScript",
            "severity":       "High",
            "description":    f"{len(http_js)} JS file(s) loaded over HTTP on an HTTPS page. "
                              f"Example: {http_js[0]}",
            "recommendation": "Serve all sub-resources over HTTPS. Update script src URLs to use https://.",
        })

    http_links = [l for l in links if isinstance(l, str) and l.startswith("http://")]
    if http_links:
        findings.append({
            "type":           "Cryptographic Failure",
            "name":           "Mixed Content: HTTP Internal Links",
            "severity":       "Low",
            "description":    f"{len(http_links)} internal link(s) use HTTP on an HTTPS site. "
                              f"Example: {http_links[0]}",
            "recommendation": "Update all internal links to use HTTPS. Add a CSP upgrade-insecure-requests directive.",
        })

    return findings




class CryptographicFailuresScanner:
    """
    Stateless scanner instantiated once per request by server.py.

    Usage (Flask active flow):
        scanner = CryptographicFailuresScanner(crawl_res)
        result  = scanner.scan()

    Usage (standalone / older main.py path):
        scanner = CryptographicFailuresScanner({"url": "https://target.com"})
        result  = scanner.scan()
    """

    def __init__(self, target: dict):
        target_data = target if isinstance(target, dict) else {}


        if "url" in target_data:
            raw_url = target_data["url"]
        else:
            raw_url = str(target)

        self._url          = raw_url
        self._parsed       = urlparse(raw_url)
        self._hostname     = self._parsed.hostname or ""
        self._port         = self._parsed.port or 443
        self._scheme       = self._parsed.scheme


        self._js_files     = target_data.get("js_files", []) or []
        self._links        = target_data.get("all_internal_links", []) or []
        self._forms        = target_data.get("forms", []) or []


    def _all_urls(self) -> list:
        urls = [self._url]
        urls.extend(self._links)
        # Include form action URLs too
        for form in self._forms:
            action = form.get("action", "")
            if action:
                urls.append(action)
        return urls

    def scan(self) -> dict:
        result = {
            "success":       True,
            "vulnerability": "Cryptographic Failures (OWASP A02:2021)",
            "status":        "Secure",
            "findings":      [],
        }

        findings = []


        findings.extend(_check_https(self._url))


        findings.extend(_check_mixed_content(self._js_files, self._links, self._scheme))


        findings.extend(_check_sensitive_urls(self._all_urls()))


        if self._scheme == "https" and self._hostname:
            tls_data = _tls_data_for_host(self._hostname, self._port)

            findings.extend(_check_tls_versions(tls_data["tls_versions"]))
            findings.extend(_check_weak_ciphers(tls_data["weak_ciphers"]))
            findings.extend(_check_certificate(tls_data["cert_info"], self._hostname))


        try:
            resp = requests.get(
                self._url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=8,
                verify=True,
                allow_redirects=True,
            )
            findings.extend(_check_hsts(dict(resp.headers)))
            findings.extend(_check_disclosure_headers(dict(resp.headers)))
        except requests.RequestException:
            pass

        result["findings"] = findings
        if findings:
            result["status"] = "Vulnerable"

        return result



def scan_cryptographic_failures(target_url: str) -> dict:
    return CryptographicFailuresScanner({"url": target_url}).scan()


if __name__ == "__main__":
    import sys
    import json

    url = sys.argv[1] if len(sys.argv) > 1 else "https://expired.badssl.com"
    print(f"[*] Scanning: {url}\n")
    out = scan_cryptographic_failures(url)
    print(json.dumps(out, indent=2, default=str))
