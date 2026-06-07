import hashlib
import logging
import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


_INT_ID      = re.compile(r'^\d{1,10}$')
_UUID        = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_ALPHANUM_ID = re.compile(r'^[0-9a-zA-Z]{6,32}$')
_STATIC_EXT  = re.compile(r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map|webp|pdf|zip|eot)$', re.I)


_AUTH_WALL = re.compile(
    r'(sign[\s\-]?in|log[\s\-]?in|please\s+log|you\s+must\s+(be\s+)?(logged|authenticated)|'
    r'unauthorized|forbidden|access[\s\-]?denied|not\s+allowed|permission\s+denied|'
    r'authentication\s+required|members[\s\-]?only|session\s+expired|'
    r'you\s+do\s+not\s+have\s+(permission|access))',
    re.I
)


_PRIV_PARAM = re.compile(
    r'\b(role|admin|privilege|permission|group|level|rank|access|'
    r'is_admin|isAdmin|user_type|usertype|account_type|scope|tier)\b',
    re.I
)


def _is_id_value(v: str) -> bool:
    """True when a value looks like a resource identifier."""
    if _INT_ID.match(v):
        return True
    if _UUID.match(v):
        return True

    if _ALPHANUM_ID.match(v) and any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
        return True
    return False


def _is_static(path: str) -> bool:
    return bool(_STATIC_EXT.search(path))


def _behind_auth_wall(text: str) -> bool:
    return bool(_AUTH_WALL.search(text))


def _fingerprint(text: str) -> str:
    normalized = ' '.join(text.lower().split())[:8000]
    return hashlib.md5(normalized.encode()).hexdigest()


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()




class _SiteContext:
    """
    Analyses crawled URLs and forms to build a structural picture of the target site.
    All candidate endpoints, IDOR targets, and privilege parameters come from what the
    crawler actually found — not from a fixed vocabulary.
    """

    def __init__(self, target_url: str, internal_links: List[str], forms: List[dict]):
        self.target_url  = target_url
        self.base_domain = urlparse(target_url).netloc
        self.forms       = forms


        self.all_endpoints:         List[str]                  = []
        self.idor_param_candidates: List[Tuple[str, str, str]] = []  # (url, param, original_value)
        self.idor_path_candidates:  List[Tuple[str, str, str]] = []  # (original_url, tampered_url, note)
        self.priv_param_endpoints:  List[Tuple[str, str]]      = []  # (url, param_name)

        clean = [l for l in internal_links if self.base_domain in l]
        self._build(clean)

    @staticmethod
    def _neighbor_ints(n: int) -> List[int]:
        pool = {1, 2, 10, 100}
        if n > 1:
            pool.add(n - 1)
        pool.add(n + 1)
        pool.discard(n)
        return list(pool)[:5]

    def _build(self, links: List[str]):
        seen: set = set()

        for link in links:
            if link in seen:
                continue
            seen.add(link)

            parsed   = urlparse(link)
            path     = parsed.path

            if _is_static(path):
                continue

            self.all_endpoints.append(link)
            segments = path.split('/')

            # Check path segments for IDOR-style integer IDs
            for i, seg in enumerate(segments):
                if _INT_ID.match(seg):
                    for alt in self._neighbor_ints(int(seg)):
                        new_segs    = segments[:]
                        new_segs[i] = str(alt)
                        tampered    = urlunparse((
                            parsed.scheme, parsed.netloc,
                            '/'.join(new_segs),
                            parsed.params, parsed.query, ''
                        ))
                        self.idor_path_candidates.append(
                            (link, tampered, f"path[{i}]:{seg}→{alt}")
                        )


            for param, values in parse_qs(parsed.query).items():
                for val in values:
                    if _is_id_value(val):
                        self.idor_param_candidates.append((link, param, val))
                if _PRIV_PARAM.search(param):
                    self.priv_param_endpoints.append((link, param))


        for form in self.forms:
            action = form.get("action", "")
            if action and self.base_domain in action and action not in seen:
                seen.add(action)
                self.all_endpoints.append(action)


            for field in form.get("fields", []):
                name = field.get("name", "")
                if name and _PRIV_PARAM.search(name) and action:
                    self.priv_param_endpoints.append((action, name))




class BACScanner:

    def __init__(self):
        self.timeout      = 8
        self.base_headers = {"User-Agent": "Garud-BAC-Scanner/4.0"}
        self.max_per_check = 5   # Limit findings count


        self.alt_methods = ["HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE"]

        # Header bypass templates — {path} gets replaced at runtime
        self.bypass_headers = [
            {"X-Original-URL":              "{path}"},
            {"X-Rewrite-URL":               "{path}"},
            {"X-Custom-IP-Authorization":   "127.0.0.1"},
            {"X-Forwarded-For":             "127.0.0.1"},
            {"X-Remote-IP":                 "127.0.0.1"},
            {"X-Client-IP":                 "127.0.0.1"},
            {"X-Host":                      "localhost"},
            {"X-Forwarded-Host":            "localhost"},
            {"X-Real-IP":                   "127.0.0.1"},
            {"X-Override-URL":              "{path}"},
        ]


        self.path_suffixes = [
            "/.json", "/.xml", "/.", "/%2e", "//",
            "/./", ";/", "?debug=1", "?admin=1", "?internal=1", "%20",
        ]


        self.priv_escalation_vals = ["1", "true", "admin", "superuser", "root", "manager", "staff"]



    def _get(self, url: str, extra_headers: Optional[dict] = None) -> Optional[requests.Response]:
        try:
            return requests.get(
                url,
                headers={**self.base_headers, **(extra_headers or {})},
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _request(self, method: str, url: str, extra_headers: Optional[dict] = None) -> Optional[requests.Response]:
        try:
            return requests.request(
                method, url,
                headers={**self.base_headers, **(extra_headers or {})},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
        except Exception:
            return None

    def _post(self, url: str, form_data: dict) -> Optional[requests.Response]:
        try:
            return requests.post(
                url, data=form_data,
                headers=self.base_headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            return None



    @staticmethod
    def _finding(cwe: str, ftype: str, endpoint: str, method: str,
                 description: str, evidence: str) -> dict:
        return {
            "vulnerable":  True,
            "cwe":         cwe,
            "type":        ftype,
            "endpoint":    endpoint,
            "method":      method,
            "description": description,
            "evidence":    evidence,
        }



    def _check_unauth_access(self, endpoints: List[str]) -> List[dict]:
        findings = []
        for url in endpoints:
            if len(findings) >= self.max_per_check:
                break
            r = self._get(url)
            if not r or r.status_code != 200:
                continue
            if _behind_auth_wall(r.text):
                continue
            if len(r.text.strip()) < 150:  # skip near-empty pages
                continue
            findings.append(self._finding(
                "CWE-862", "Missing Authorization",
                url, "GET",
                "Endpoint accessible without authentication — no login wall detected.",
                f"HTTP 200, body={len(r.text)}B",
            ))
        return findings



    def _check_idor_params(self, candidates: List[Tuple[str, str, str]]) -> List[dict]:
        findings    = []
        tested_urls = set()

        for url, param, original_val in candidates:
            if len(findings) >= self.max_per_check:
                break
            if url in tested_urls:
                continue

            orig = self._get(url)
            if not orig or orig.status_code != 200 or _behind_auth_wall(orig.text):
                continue

            orig_fp   = _fingerprint(orig.text)
            orig_norm = ' '.join(orig.text.lower().split())

            for alt_val in self._alt_ids(original_val):
                parsed      = urlparse(url)
                qs          = parse_qs(parsed.query)
                qs[param]   = [alt_val]
                tampered    = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(qs, doseq=True), ''
                ))
                r = self._get(tampered)
                if not r or r.status_code != 200 or _behind_auth_wall(r.text):
                    continue

                sim          = _similarity(orig_norm, ' '.join(r.text.lower().split()))
                length_delta = abs(len(orig.text) - len(r.text))

                # Different fingerprint + meaningful content delta = likely IDOR
                if _fingerprint(r.text) != orig_fp and (sim < 0.98 or length_delta > 20):
                    findings.append(self._finding(
                        "CWE-639", "IDOR — Query Parameter Object Enumeration",
                        tampered, "GET",
                        f"Modifying '{param}' from '{original_val}' to '{alt_val}' returned distinct content.",
                        f"sim={sim:.3f}, Δbody={length_delta}B",
                    ))
                    tested_urls.add(url)
                    break

        return findings



    def _check_idor_paths(self, candidates: List[Tuple[str, str, str]]) -> List[dict]:
        findings         = []
        tested_originals = set()

        for original_url, tampered_url, note in candidates:
            if len(findings) >= self.max_per_check:
                break
            if original_url in tested_originals:
                continue

            orig = self._get(original_url)
            if not orig or orig.status_code != 200 or _behind_auth_wall(orig.text):
                continue

            r = self._get(tampered_url)
            if not r or r.status_code != 200 or _behind_auth_wall(r.text):
                continue

            sim          = _similarity(orig.text, r.text)
            length_delta = abs(len(orig.text) - len(r.text))

            if _fingerprint(r.text) != _fingerprint(orig.text) and (sim < 0.98 or length_delta > 20):
                findings.append(self._finding(
                    "CWE-639", "IDOR — Path Segment Object Enumeration",
                    tampered_url, "GET",
                    f"Swapping path ID ({note}) returned distinct content — object-level auth may be missing.",
                    f"sim={sim:.3f}, Δbody={length_delta}B",
                ))
                tested_originals.add(original_url)

        return findings



    def _check_verb_tampering(self, endpoints: List[str]) -> List[dict]:
        findings = []

        for url in endpoints[:20]:
            if len(findings) >= self.max_per_check:
                break
            baseline = self._get(url)
            if not baseline:
                continue
            baseline_code = baseline.status_code

            for method in self.alt_methods:
                r = self._request(method, url)
                if not r:
                    continue

                bypass = baseline_code in (401, 403) and r.status_code == 200
                dangerous = method in ("DELETE", "PUT", "PATCH") and r.status_code in (200, 201, 204)

                if bypass or dangerous:
                    reason = (
                        f"bypasses {baseline_code} on GET"
                        if bypass
                        else f"dangerous method accepted (no restriction)"
                    )
                    findings.append(self._finding(
                        "CWE-284", f"HTTP Verb Tampering — {method}",
                        url, method,
                        f"{method} {reason} → HTTP {r.status_code}.",
                        f"GET={baseline_code}, {method}={r.status_code}",
                    ))
                    break  # one per URL

        return findings



    def _check_header_bypass(self, endpoints: List[str]) -> List[dict]:
        findings = []


        restricted = [
            (url, r.status_code)
            for url in endpoints[:15]
            for r in [self._get(url)]
            if r and r.status_code in (401, 403)
        ]

        for url, base_code in restricted:
            if len(findings) >= self.max_per_check:
                break
            parsed = urlparse(url)
            for tmpl in self.bypass_headers:
                headers = {
                    k: v.replace("{path}", parsed.path) if "{path}" in v else v
                    for k, v in tmpl.items()
                }
                r = self._get(url, extra_headers=headers)
                if r and r.status_code == 200 and not _behind_auth_wall(r.text):
                    findings.append(self._finding(
                        "CWE-285", "Header-Based Authorization Bypass",
                        url, "GET",
                        f"Access control circumvented using header '{list(headers.keys())[0]}'.",
                        f"Baseline {base_code} → 200 with {headers}",
                    ))
                    break  # one bypass per URL

        return findings



    def _check_path_suffix_bypass(self, endpoints: List[str]) -> List[dict]:
        findings = []

        restricted = [
            (url, r.status_code)
            for url in endpoints[:15]
            for r in [self._get(url)]
            if r and r.status_code in (401, 403)
        ]

        for url, base_code in restricted:
            if len(findings) >= self.max_per_check:
                break
            for suffix in self.path_suffixes:
                test_url = url.rstrip('/') + suffix
                r        = self._get(test_url)
                if r and r.status_code == 200 and not _behind_auth_wall(r.text) and len(r.text.strip()) > 100:
                    findings.append(self._finding(
                        "CWE-863", "Path Confusion / Suffix Bypass",
                        test_url, "GET",
                        f"Appending '{suffix}' to a {base_code} endpoint returned HTTP 200.",
                        f"Original: {url} → {base_code}; Suffixed → 200",
                    ))
                    break

        return findings



    def _check_priv_param_tampering(self, priv_endpoints: List[Tuple[str, str]]) -> List[dict]:
        findings = []

        for url, param in priv_endpoints:
            if len(findings) >= self.max_per_check:
                break
            parsed = urlparse(url)
            qs     = parse_qs(parsed.query)

            for val in self.priv_escalation_vals:
                qs[param]  = [val]
                test_url   = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(qs, doseq=True), ''
                ))
                r = self._get(test_url)
                if r and r.status_code == 200 and not _behind_auth_wall(r.text):
                    findings.append(self._finding(
                        "CWE-269", "Privilege Escalation via Parameter Tampering",
                        test_url, "GET",
                        f"Setting '{param}={val}' yielded HTTP 200 — server may trust client-supplied privilege values.",
                        f"Param '{param}' set to '{val}'; HTTP 200 received",
                    ))
                    break

        return findings



    def _check_unauth_form_actions(self, forms: List[dict]) -> List[dict]:
        findings = []

        for form in forms:
            if len(findings) >= self.max_per_check:
                break
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            if not action or method != "POST":
                continue


            payload = {f.get("name", ""): "" for f in form.get("fields", []) if f.get("name")}
            r       = self._post(action, payload)
            if r and r.status_code == 200 and not _behind_auth_wall(r.text):
                findings.append(self._finding(
                    "CWE-306", "Missing Authentication for Critical Function",
                    action, "POST",
                    "POST form action accepted a blank submission without authentication.",
                    f"HTTP {r.status_code}, body={len(r.text)}B",
                ))

        return findings



    def _check_cors_misconfig(self, endpoints: List[str]) -> List[dict]:
        findings = []
        evil_origin = "https://evil.example.com"

        for url in endpoints[:10]:
            if len(findings) >= self.max_per_check:
                break
            r = self._get(url, extra_headers={"Origin": evil_origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

            # Reflected origin + credentials = exploitable CORS
            if acao == evil_origin and acac == "true":
                findings.append(self._finding(
                    "CWE-942", "CORS Misconfiguration — Credential Reflection",
                    url, "GET",
                    "Server reflects attacker-controlled Origin with Access-Control-Allow-Credentials: true.",
                    f"ACAO: {acao}, ACAC: {acac}",
                ))

        return findings



    def _check_mass_assignment(self, forms: List[dict]) -> List[dict]:
        """
        POST JSON with extra privilege fields to endpoints that accept JSON.
        If the server does not filter unknown fields it may honour them (CWE-915).
        """
        findings = []
        priv_fields = {"role": "admin", "is_admin": True, "admin": True,
                       "privilege": "superuser", "account_type": "admin"}

        seen_actions: set = set()
        for form in forms:
            if len(findings) >= self.max_per_check:
                break
            action = form.get("action", "")
            if not action or action in seen_actions:
                continue
            seen_actions.add(action)

            try:
                r = requests.post(
                    action,
                    json=priv_fields,
                    headers={**self.base_headers, "Content-Type": "application/json"},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if r.status_code == 200 and not _behind_auth_wall(r.text):

                    body_lower = r.text.lower()
                    if any(str(v).lower() in body_lower for v in priv_fields.values()):
                        findings.append(self._finding(
                            "CWE-915", "Mass Assignment / Parameter Pollution",
                            action, "POST",
                            "Server accepted JSON body with privilege fields and reflected a privileged value — mass assignment likely.",
                            f"HTTP 200; privilege field reflected in response",
                        ))
            except Exception:
                pass

        return findings



    @staticmethod
    def _alt_ids(original: str) -> List[str]:
        if _INT_ID.match(original):
            n    = int(original)
            pool = {str(v) for v in [1, 2, 10, 100, n - 1, n + 1] if v != n and v > 0}
            return list(pool)[:5]

        return []

    @staticmethod
    def _dedup(results: List[dict]) -> List[dict]:
        seen, out = set(), []
        for r in results:
            key = (r.get("cwe"), r.get("endpoint"), r.get("method"))
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out



    def scan(self, data: dict) -> dict:
        target = data.get("target", {})
        url    = target.get("url", "")
        forms  = target.get("forms", [])

        if not url:
            return {"success": False, "engine": "bac_scanner", "results": []}


        links_raw = target.get("links", {})
        if isinstance(links_raw, dict):
            internal_links = links_raw.get("internal_links", [])
        elif isinstance(links_raw, list):
            internal_links = links_raw
        else:
            internal_links = []


        if url not in internal_links:
            internal_links = [url] + internal_links

        # Seed typical ID params when crawler found none with query strings
        if not any("?" in l for l in internal_links):
            for p in ["id", "user_id", "account_id", "order_id", "customer_id", "item_id"]:
                for v in ["1", "2"]:
                    internal_links.append(f"{url.rstrip('/')}?{p}={v}")

        ctx = _SiteContext(url, internal_links, forms)

        results  = []
        results += self._check_unauth_access(ctx.all_endpoints)
        results += self._check_idor_params(ctx.idor_param_candidates)
        results += self._check_idor_paths(ctx.idor_path_candidates)
        results += self._check_verb_tampering(ctx.all_endpoints)
        results += self._check_header_bypass(ctx.all_endpoints)
        results += self._check_path_suffix_bypass(ctx.all_endpoints)
        results += self._check_priv_param_tampering(ctx.priv_param_endpoints)
        results += self._check_unauth_form_actions(forms)
        results += self._check_cors_misconfig(ctx.all_endpoints)
        results += self._check_mass_assignment(forms)

        return {
            "success": True,
            "engine":  "bac_scanner",
            "results": self._dedup(results),
        }