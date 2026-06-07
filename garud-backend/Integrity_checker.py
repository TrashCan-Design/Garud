"""OWASP A08:2021 — Software and Data Integrity Failures Scanner."""

import re
import time
import threading
import requests
from urllib.parse import urljoin, urlparse

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False



_SENSITIVE_PATHS = [
    # VCS metadata — critical if full source is downloadable
    (".git/config",             "Critical", "Git repository config — may expose remote URLs and credentials"),
    (".git/HEAD",               "Critical", "Git HEAD pointer — confirms live VCS exposure"),
    (".svn/entries",            "Critical", "SVN metadata — exposes repository structure"),

    # CI/CD configs often embed secrets
    (".github/workflows",       "Critical", "GitHub Actions workflow directory — may expose CI secrets"),
    (".gitlab-ci.yml",          "Critical", "GitLab CI config — may expose deployment secrets"),
    ("Jenkinsfile",             "High",     "Jenkins pipeline config — may reveal build secrets"),
    (".travis.yml",             "High",     "Travis CI config — may expose environment tokens"),
    ("azure-pipelines.yml",     "High",     "Azure Pipelines config — may expose cloud credentials"),

    # Package manifests expose dependency graph
    ("package.json",            "High",     "npm manifest — reveals full dependency tree"),
    ("package-lock.json",       "High",     "npm lock file — exact versions aid targeted CVE research"),
    ("yarn.lock",               "High",     "Yarn lock file — exact versions aid targeted CVE research"),
    ("composer.json",           "High",     "PHP Composer manifest"),
    ("composer.lock",           "High",     "PHP Composer lock file"),
    ("requirements.txt",        "High",     "Python dependency list"),
    ("Pipfile",                 "High",     "Python Pipenv manifest"),
    ("Pipfile.lock",            "High",     "Python Pipenv lock file"),
    ("pom.xml",                 "High",     "Maven project descriptor"),
    ("build.gradle",            "Medium",   "Gradle build script"),
    ("Gemfile",                 "High",     "Ruby dependency manifest"),
    ("Gemfile.lock",            "High",     "Ruby lock file"),


    ("Dockerfile",              "Medium",   "Docker build instructions — exposes base image and config"),
    ("docker-compose.yml",      "Medium",   "Docker Compose config — may expose service topology"),
    ("docker-compose.yaml",     "Medium",   "Docker Compose config (alternate extension)"),


    ("webpack.config.js",       "Medium",   "Webpack config — exposes bundler setup"),
    ("vite.config.js",          "Low",      "Vite config — exposes bundler setup"),
]


_TRUSTED_CDNS = frozenset({
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "code.jquery.com",
    "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
})


_INLINE_EVENT_RE = re.compile(r'\bon\w+\s*=\s*["\']', re.I)
_JS_HREF_RE      = re.compile(r'href\s*=\s*["\']javascript:', re.I)

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"



_probe_cache: dict  = {}
_cache_lock         = threading.Lock()
_CACHE_TTL          = 1800  # 30 minutes


def _cache_get(key: str):
    with _cache_lock:
        entry = _probe_cache.get(key)
        if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
            return entry["val"]
    return None


def _cache_set(key: str, val) -> None:
    with _cache_lock:
        _probe_cache[key] = {"val": val, "ts": time.time()}




def _check_sri_in_html(html: str, base_url: str) -> list:
    """Parse HTML and find external resources without SRI."""
    findings  = []
    base_host = urlparse(base_url).netloc

    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.find_all("script", src=True):
            src    = tag.get("src", "")
            host   = urlparse(src).netloc
            if not host or host == base_host:
                continue
            if not tag.get("integrity"):
                severity = "Medium" if host in _TRUSTED_CDNS else "High"
                findings.append(_sri_finding("script", src, host, severity))

        for tag in soup.find_all("link", rel=lambda r: r and "stylesheet" in r, href=True):
            href = tag.get("href", "")
            host = urlparse(href).netloc
            if not host or host == base_host:
                continue
            if not tag.get("integrity"):
                severity = "Low" if host in _TRUSTED_CDNS else "Medium"
                findings.append(_sri_finding("stylesheet", href, host, severity))

    else:
        # Regex fallback if BS4 unavailable
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html, re.I):
            src  = m.group(1)
            host = urlparse(src).netloc
            if not host or host == base_host:
                continue
            if "integrity=" not in m.group(0).lower():
                sev = "Medium" if host in _TRUSTED_CDNS else "High"
                findings.append(_sri_finding("script", src, host, sev))

        for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>', html, re.I):
            href = m.group(1)
            host = urlparse(href).netloc
            if not host or host == base_host:
                continue
            if 'rel="stylesheet"' not in m.group(0).lower() and "rel='stylesheet'" not in m.group(0).lower():
                continue
            if "integrity=" not in m.group(0).lower():
                sev = "Low" if host in _TRUSTED_CDNS else "Medium"
                findings.append(_sri_finding("stylesheet", href, host, sev))

    return findings


def _sri_finding(resource_type: str, url: str, host: str, severity: str) -> dict:
    trusted = host in _TRUSTED_CDNS
    return {
        "type":           "Missing SRI",
        "name":           f"Missing SRI on External {resource_type.capitalize()}: {host}",
        "severity":       severity,
        "description":    (
            f"External {resource_type} loaded from {'trusted CDN ' if trusted else 'third-party host '}"
            f"'{host}' without a Subresource Integrity hash. "
            f"If the CDN is compromised or the file is altered, malicious code executes in your users' browsers. "
            f"Resource: {url}"
        ),
        "recommendation": (
            "Add an integrity attribute with a SHA-384 hash and crossorigin='anonymous'. "
            "Generate with: openssl dgst -sha384 -binary FILE | openssl base64 -A "
            "or use https://www.srihash.org/"
        ),
    }




def _check_inline_scripts(html: str) -> list:
    """Check for high numbers of inline JS event handlers."""
    findings = []
    inline_events = len(_INLINE_EVENT_RE.findall(html))
    js_hrefs      = len(_JS_HREF_RE.findall(html))

    total = inline_events + js_hrefs
    if total >= 5:
        findings.append({
            "type":           "Inline Script Exposure",
            "name":           "Heavy Inline JavaScript",
            "severity":       "Low",
            "description":    (
                f"Page contains {total} inline JS execution points (event handlers / javascript: hrefs). "
                "Inline scripts bypass SRI and are incompatible with strict Content-Security-Policy."
            ),
            "recommendation": (
                "Move JavaScript to external files protected by SRI. "
                "Add a Content-Security-Policy that disallows 'unsafe-inline'."
            ),
        })
    return findings




def _check_js_files_sri(js_files: list, base_host: str) -> list:
    """Validate external crawled JS scripts for SRI hashes."""
    findings  = []
    flagged   = set()

    for src in js_files:
        if not isinstance(src, str):
            continue
        host = urlparse(src).netloc
        if not host or host == base_host or host in flagged:
            continue
        flagged.add(host)
        sev = "Medium" if host in _TRUSTED_CDNS else "High"
        findings.append({
            "type":           "External Script Without SRI (Crawl)",
            "name":           f"External JS from '{host}' (discovered by crawler)",
            "severity":       sev,
            "description":    (
                f"The crawler found JavaScript loaded from third-party host '{host}' "
                f"on one or more interior pages. Example: {src}"
            ),
            "recommendation": "Audit all dynamically loaded external scripts and add SRI hashes.",
        })

    return findings




def _probe_exposed_files(base_url: str) -> list:
    """Probe target for sensitive files with HEAD/GET."""
    cache_key = f"integrity_probe:{base_url}"
    cached    = _cache_get(cache_key)
    if cached is not None:
        return cached

    findings = []
    session  = requests.Session()
    session.headers.update({"User-Agent": _UA})


    parsed   = urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}/"

    for path, severity, note in _SENSITIVE_PATHS:
        probe_url = urljoin(root_url, path)
        try:
            resp = session.head(probe_url, timeout=4, verify=True, allow_redirects=True)

            # Fall back to GET if HEAD not supported
            if resp.status_code == 405:
                resp = session.get(probe_url, timeout=5, verify=True, stream=True)
                resp.close()

            if resp.status_code != 200:
                continue

            # Distinguish real files from custom 200 error pages
            ct = resp.headers.get("Content-Type", "").lower()
            if "html" in ct and severity not in ("Critical",):
                continue

            # Critical paths (e.g. .git) are flagged regardless of content type
            findings.append({
                "type":           "Exposed Sensitive File",
                "name":           f"Exposed File: {path}",
                "severity":       severity,
                "description":    f"{note}. Accessible at: {probe_url}",
                "recommendation": (
                    f"Block public access to '{path}' in your web server config. "
                    "Nginx: location ~* /\\.git { deny all; } "
                    "Apache: <FilesMatch '^\\.(git|env|htaccess)$'> Require all denied </FilesMatch>"
                ),
            })

        except requests.RequestException:
            continue

    _cache_set(cache_key, findings)
    return findings




def _check_graph_for_vcs(graph: dict, base_host: str) -> list:
    """Inspect crawler graph nodes for sensitive VCS paths."""
    findings = []
    suspicious_patterns = re.compile(
        r'/\.git/|/\.svn/|/node_modules/|/vendor/|/\.env|/\.github/', re.I
    )

    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    for node in nodes:
        url = node.get("id", "") if isinstance(node, dict) else str(node)
        if suspicious_patterns.search(url):
            findings.append({
                "type":           "VCS/Build Path in Crawler Graph",
                "name":           f"Sensitive Path Reachable: {url}",
                "severity":       "Critical",
                "description":    f"The crawler reached a sensitive infrastructure path: {url}",
                "recommendation": "Block this path immediately at the web server / CDN layer.",
            })

    return findings




class IntegrityFailuresScanner:
    """Stateless integrity failures scanner."""

    def __init__(self, target: dict):
        target_data     = target if isinstance(target, dict) else {}
        self._url       = target_data.get("url", "") if target_data else str(target)
        self._js_files  = target_data.get("js_files", [])           or []
        self._links     = target_data.get("all_internal_links", []) or []
        self._graph     = target_data.get("graph", {})              or {}
        self._base_host = urlparse(self._url).netloc

    def scan(self) -> dict:
        result = {
            "success":       True,
            "vulnerability": "Software and Data Integrity Failures (OWASP A08:2021)",
            "status":        "Secure",
            "findings":      [],
        }

        findings = []


        html = ""
        try:
            resp = requests.get(
                self._url,
                headers={"User-Agent": _UA},
                timeout=10,
                verify=True,
            )
            if resp.status_code == 200:
                html = resp.text
        except requests.RequestException:
            pass

        if html:
            findings.extend(_check_sri_in_html(html, self._url))
            findings.extend(_check_inline_scripts(html))

        # Also check crawler's JS corpus for external scripts on interior pages
        findings.extend(_check_js_files_sri(self._js_files, self._base_host))


        findings.extend(_probe_exposed_files(self._url))

        # Check the crawler graph for sensitive infra paths (zero extra HTTP calls)
        findings.extend(_check_graph_for_vcs(self._graph, self._base_host))

        # Deduplicate by (name, type)
        seen     = set()
        deduped  = []
        for f in findings:
            key = (f["type"], f["name"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        result["findings"] = deduped
        if deduped:
            result["status"] = "Vulnerable"

        return result



def scan_integrity_failures(target_url: str) -> dict:
    return IntegrityFailuresScanner({"url": target_url}).scan()



if __name__ == "__main__":
    import sys
    import json

    url = sys.argv[1] if len(sys.argv) > 1 else "https://pentest-ground.com/"
    print(f"[*] Scanning: {url}\n")
    out = scan_integrity_failures(url)
    print(json.dumps(out, indent=2, default=str))
