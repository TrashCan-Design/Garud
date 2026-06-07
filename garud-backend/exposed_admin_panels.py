import logging
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/login.php",
    "/admin/index.php", "/admin/index.html", "/admin/dashboard",
    "/admin/console", "/administrator", "/administrator/",
    "/administrator/index.php", "/administrator/login",
    "/adminpanel", "/admin_panel", "/admin-panel",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-admin/admin.php",
    "/login", "/login.php", "/login.html", "/login/",
    "/signin", "/sign-in", "/sign_in",
    "/dashboard", "/dashboard/", "/dashboard/login",
    "/cpanel", "/cpanel/", "/whm", "/webmail",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/myadmin",
    "/manager", "/manager/html", "/manager/status",
    "/management", "/manage", "/manage/",
    "/panel", "/panel/", "/controlpanel", "/control-panel",
    "/control", "/webadmin", "/siteadmin", "/sitemanager",
    "/system", "/system/", "/system/admin",
    "/user/login", "/user/admin", "/users/admin",
    "/account/login", "/accounts/login",
    "/auth", "/auth/login", "/authentication",
    "/backend", "/backend/", "/backend/login",
    "/staff", "/staff/login", "/employee", "/internal",
    "/portal", "/portal/login", "/secure", "/private",
    "/moderator", "/mod", "/superadmin", "/superuser",
    "/root", "/root/login", "/webmaster",
    "/config", "/configuration", "/setup", "/install",
    "/console", "/console/", "/shell",
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/admin/api", "/rest/admin",
    "/joomla/administrator", "/drupal/admin", "/typo3",
    "/umbraco", "/umbraco/login.aspx",
    "/sitecore/login", "/episerver", "/kentico/admin",
    "/magento/admin", "/index.php/admin",
    "/adminer", "/adminer.php", "/database/admin",
    "/ams", "/cms", "/cms/admin", "/cms/login",
    "/ewa", "/owa", "/exchange/admin",
    "/_admin", "/_admin/", "/hidden/admin",
    "/secret/admin", "/private/admin",
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_LOGIN_KEYWORDS = [
    "password", "username", "login", "sign in", "signin",
    "log in", "admin", "authentication", "email", "user name",
    "forgot password", "remember me", "access", "credentials",
]

_ADMIN_KEYWORDS = [
    "dashboard", "admin panel", "administration", "manage users",
    "system settings", "site settings", "control panel", "back office",
    "content management", "user management", "analytics", "reports",
    "cms", "configuration", "maintenance", "server info",
]

_TECH_FINGERPRINTS = {
    "WordPress": ["wp-login", "wordpress", "/wp-content/", "wp-admin"],
    "Joomla": ["joomla", "com_users", "task=login"],
    "Drupal": ["drupal", "/sites/default/", "Powered by Drupal"],
    "phpMyAdmin": ["phpmyadmin", "pmaTheme", "PMA_token"],
    "Django": ["csrfmiddlewaretoken", "django", "__admin__"],
    "Laravel": ["laravel_session", "_token", "Laravel"],
    "Rails": ["authenticity_token", "ruby on rails"],
    "Tomcat": ["Apache Tomcat", "tomcat", "Manager App"],
}

_DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", ""), ("administrator", "administrator"),
    ("root", "root"), ("root", "toor"),
    ("admin", "admin123"), ("test", "test"),
]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


def _fingerprint_page(text: str) -> dict:
    text_lower = text.lower()
    is_login = sum(1 for kw in _LOGIN_KEYWORDS if kw in text_lower) >= 2
    is_admin = any(kw in text_lower for kw in _ADMIN_KEYWORDS)
    detected_tech = [
        tech for tech, patterns in _TECH_FINGERPRINTS.items()
        if any(p.lower() in text_lower for p in patterns)
    ]
    login_form = "<form" in text_lower and ("password" in text_lower or "passwd" in text_lower)
    return {
        "is_login": is_login,
        "is_admin": is_admin,
        "technologies": detected_tech,
        "has_login_form": login_form,
    }


def _classify_severity(fp: dict, path: str, status_code: int) -> str:
    path_lower = path.lower()
    if fp["technologies"]:
        return "Critical"
    if fp["has_login_form"] and status_code == 200:
        if any(seg in path_lower for seg in ("admin", "administrator", "manage", "backend", "dashboard")):
            return "Critical"
        return "High"
    if status_code == 200 and (fp["is_login"] or fp["is_admin"]):
        return "High"
    if status_code in (401, 403):
        return "Medium"
    return "Low"


class ExposedAdminScanner:

    def __init__(self, timeout: int = 8, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self._request_count = 0

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
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        return s

    def scan(self, data: dict) -> dict:
        target = data.get("target", {})
        base_url = target.get("url", "")

        logger.info("=" * 65)
        logger.info("EXPOSED ADMIN SCANNER — STARTING")
        logger.info(f"  Base URL  : {base_url}")
        logger.info("=" * 65)

        if not base_url:
            return {"success": False, "engine": "exposed_admin_scanner", "results": [], "total_requests": 0}

        candidates = list({urljoin(base_url, path) for path in _ADMIN_PATHS})
        logger.info(f"  Total candidates: {len(candidates)}")

        results: list[dict] = []
        seen: set[str] = set()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._check_path, url): url for url in candidates}
            for fut in as_completed(futures):
                try:
                    finding = fut.result()
                    if not finding:
                        continue
                    with self._lock:
                        if finding["endpoint"] in seen:
                            continue
                        seen.add(finding["endpoint"])
                    results.append(finding)
                except Exception as exc:
                    logger.debug(f"Worker error: {exc}")

        results.sort(key=lambda r: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(r["severity"], 4))

        logger.info(f"EXPOSED ADMIN SCANNER COMPLETE — {len(results)} findings, {self._request_count} requests")
        return {
            "success": True,
            "engine": "exposed_admin_scanner",
            "results": results,
            "total_requests": self._request_count,
        }

    def _check_path(self, url: str) -> dict | None:
        session = self._build_session()
        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            self._inc()
            return self._analyse(resp, url)
        except requests.exceptions.RequestException:
            return None
        except Exception as exc:
            logger.debug(f"Check error [{url}]: {exc}")
            return None

    def _analyse(self, resp: requests.Response, original_url: str) -> dict | None:
        status = resp.status_code
        final_url = resp.url
        parsed_path = urlparse(original_url).path

        if status == 404:
            if len(resp.text) < 500:
                return None
            if not any(kw in resp.text.lower() for kw in _LOGIN_KEYWORDS + _ADMIN_KEYWORDS):
                return None

        fp = _fingerprint_page(resp.text)

        if status == 200:
            if not fp["is_login"] and not fp["is_admin"] and not fp["has_login_form"] and not fp["technologies"]:
                return None
        elif status in (301, 302, 303, 307, 308):
            final_fp = _fingerprint_page(resp.text)
            if not final_fp["is_login"] and not final_fp["has_login_form"]:
                return None
        elif status not in (401, 403):
            return None

        severity = _classify_severity(fp, parsed_path, status)

        category = "Exposed" if status == 200 else "Protected"
        if status in (301, 302, 303, 307, 308):
            category = "Redirect-to-Login"

        description_parts = []
        if fp["technologies"]:
            description_parts.append(f"Technology detected: {', '.join(fp['technologies'])}")
        if fp["has_login_form"]:
            description_parts.append("Login form present")
        if status in (401, 403):
            description_parts.append("Access restricted (authentication required)")

        return {
            "vulnerable": status == 200,
            "type": "Exposed Admin Panel",
            "category": category,
            "severity": severity,
            "endpoint": original_url,
            "final_url": final_url,
            "status_code": status,
            "technologies": fp["technologies"],
            "has_login_form": fp["has_login_form"],
            "is_admin_panel": fp["is_admin"],
            "description": f"Admin panel {category.lower()} at {original_url}" + (
                f" — {'; '.join(description_parts)}" if description_parts else ""
            ),
            "evidence": f"HTTP {status} — {', '.join(description_parts) if description_parts else 'Admin path accessible'}",
            "cwe": "CWE-200",
            "owasp": "A05:2021 - Security Misconfiguration",
            "recommendation": (
                "Restrict admin panel access by IP allowlist, VPN, or network-level controls. "
                "Enforce strong authentication and MFA. Rename default admin paths where possible. "
                "Ensure admin interfaces are never exposed to the public internet."
            ),
        }

    def _inc(self, n: int = 1) -> None:
        with self._lock:
            self._request_count += n
