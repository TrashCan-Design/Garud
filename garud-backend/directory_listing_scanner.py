import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

_DIRECTORY_PATHS = [
    "/uploads/", "/backup/", "/files/", "/downloads/", "/data/", "/docs/",
    "/temp/", "/tmp/", "/cache/", "/logs/", "/log/",
    "/storage/", "/private/", "/config/", "/conf/", "/settings/", "/env/", "/secrets/",
    "/db/", "/database/", "/sql/", "/export/", "/imports/",
    "/archive/", "/archives/", "/old/", "/bak/", "/backup/",
    "/test/", "/tests/", "/dev/", "/staging/",
    "/wp-content/uploads/", "/wp-content/plugins/",
    "/sites/default/files/", "/app/", "/src/", "/dist/",
    "/build/", "/out/", "/output/", "/reports/", "/report/",
    "/attachments/", "/uploads/documents/", "/uploads/images/",
    "/.git/", "/.svn/", "/.env/",
]

_LISTING_INDICATORS = [
    "index of /",
    "directory listing for",
    "<title>index of",
    "parent directory",
    "[to parent directory]",
    "directory of /",
    "folder listing",
    "<a href=\"?c=n\">",
    "<a href=\"?n=d\">",
    "last modified",
    "apache server at",
    "nginx directory listing",
    "lighttpd directory listing",
    "</td><td align=\"right\">",
]

_STRONG_INDICATORS = {
    "index of /",
    "directory listing for",
    "<title>index of",
    "parent directory",
    "[to parent directory]",
}

_SENSITIVE_FILE_EXTENSIONS = {
    ".env", ".sql", ".bak", ".backup", ".key", ".pem",
    ".log", ".cfg", ".conf", ".config", ".ini", ".yml",
    ".yaml", ".json", ".xml", ".db", ".sqlite", ".tar",
    ".gz", ".zip", ".rar",
}


def _classify_severity(path: str, indicators_found: list[str]) -> str:
    path_lower = path.lower()
    if any(seg in path_lower for seg in ("backup", "bak", "config", "secret", "env", ".git", ".svn", "db", "sql", "log")):
        return "Critical"
    if any(ind in indicators_found for ind in _STRONG_INDICATORS):
        return "High"
    return "Medium"


def _extract_listed_files(html: str) -> list[str]:
    import re
    files = re.findall(r'href=["\']([^"\'?#]+)["\']', html, re.IGNORECASE)
    sensitive = [
        f for f in files
        if any(f.lower().endswith(ext) for ext in _SENSITIVE_FILE_EXTENSIONS)
    ]
    return sensitive[:20]


class DirectoryListingScanner:

    def __init__(self, timeout: float = 4.5, max_workers: int = 20):
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
        base_url = target.get("url", "")
        all_internal_links = target.get("all_internal_links", [])

        self._abort_scan = False

        logger.info("=" * 65)
        logger.info("DIRECTORY LISTING SCANNER — STARTING")
        logger.info(f"  Base URL  : {base_url}")
        logger.info("=" * 65)

        candidate_dirs = self._build_candidates(base_url, all_internal_links)
        logger.info(f"  Total candidates: {len(candidate_dirs)}")

        results: list[dict] = []
        seen: set[str] = set()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._check_directory, url): url for url in candidate_dirs}
            for fut in as_completed(futures):
                try:
                    finding = fut.result()
                    if not finding:
                        continue
                    with self._lock:
                        if finding["endpoint"] in seen:
                            continue
                        seen.add(finding["endpoint"])
                        self._abort_scan = True
                    results.append(finding)
                except Exception as exc:
                    logger.debug(f"Worker error: {exc}")

        results.sort(key=lambda r: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(r["severity"], 4))

        logger.info(f"DIRECTORY LISTING SCANNER COMPLETE — {len(results)} findings, {self._request_count} requests")
        return {
            "success": True,
            "engine": "directory_listing_scanner",
            "results": results,
            "total_requests": self._request_count,
        }

    def _build_candidates(self, base_url: str, all_internal_links: list) -> list[str]:
        candidates: set[str] = set()

        for path in _DIRECTORY_PATHS:
            if base_url:
                candidates.add(urljoin(base_url, path))

        for link in all_internal_links:
            if not isinstance(link, str) or not link:
                continue
            parsed = urlparse(link)
            path = parsed.path
            if path and path != "/":
                parts = path.rstrip("/").rsplit("/", 1)
                if len(parts) > 1 and parts[0]:
                    dir_path = parts[0] + "/"
                    dir_url = urljoin(link, dir_path)
                    candidates.add(dir_url)

        return list(candidates)

    def _check_directory(self, url: str) -> dict | None:
        if self._abort_scan:
            return None
        try:
            resp = self._session.get(url, timeout=self.timeout, allow_redirects=True)
            self._inc()

            if resp.status_code != 200:
                return None

            text_lower = resp.text.lower()
            indicators_found = [ind for ind in _LISTING_INDICATORS if ind in text_lower]

            if len(indicators_found) < 2:
                return None

            sensitive_files = _extract_listed_files(resp.text)
            severity = _classify_severity(url, indicators_found)

            if sensitive_files:
                severity = "Critical"

            return {
                "vulnerable": True,
                "type": "Directory Listing",
                "severity": severity,
                "endpoint": url,
                "status_code": resp.status_code,
                "indicators": indicators_found,
                "sensitive_files_exposed": sensitive_files,
                "description": f"Directory listing enabled at {url}",
                "evidence": f"Response contains listing indicators: {', '.join(indicators_found[:3])}",
                "cwe": "CWE-548",
                "owasp": "A05:2021 - Security Misconfiguration",
                "recommendation": (
                    "Disable directory listing in your web server configuration. "
                    "For Apache: add 'Options -Indexes'. For Nginx: remove 'autoindex on'. "
                    "Ensure sensitive directories are not web-accessible."
                ),
            }

        except requests.exceptions.RequestException:
            return None
        except Exception as exc:
            logger.debug(f"Directory check error [{url}]: {exc}")
            return None

    def _inc(self, n: int = 1) -> None:
        with self._lock:
            self._request_count += n
