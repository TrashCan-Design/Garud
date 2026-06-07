
import re
import time
import threading
import requests

try:
    from packaging import version as pkg_version
    _HAS_PKG = True
except ImportError:
    _HAS_PKG = False



_LIBRARIES = {
    "jquery":     {"ecosystem": "npm", "package": "jquery",     "safe_version": "3.5.0"},
    "bootstrap":  {"ecosystem": "npm", "package": "bootstrap",  "safe_version": "5.3.0"},
    "angular":    {"ecosystem": "npm", "package": "angularjs",  "safe_version": "1.8.3"},
    "react":      {"ecosystem": "npm", "package": "react",      "safe_version": "18.0.0"},
    "vue":        {"ecosystem": "npm", "package": "vue",        "safe_version": "3.0.0"},
    "lodash":     {"ecosystem": "npm", "package": "lodash",     "safe_version": "4.17.21"},
    "axios":      {"ecosystem": "npm", "package": "axios",      "safe_version": "1.6.0"},
    "moment":     {"ecosystem": "npm", "package": "moment",     "safe_version": "2.29.4"},
    "d3":         {"ecosystem": "npm", "package": "d3",         "safe_version": "7.0.0"},
    "highcharts": {"ecosystem": "npm", "package": "highcharts", "safe_version": "11.0.0"},
    "handlebars": {"ecosystem": "npm", "package": "handlebars", "safe_version": "4.7.7"},
    "underscore": {"ecosystem": "npm", "package": "underscore", "safe_version": "1.13.6"},
}

_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


_DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")



class _Cache:
    """Thread-safe key-value store with per-entry TTL."""

    def __init__(self, ttl: int = 3600):
        self._store: dict = {}
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            entry = self._store.get(key)
            if entry and (time.time() - entry["ts"]) < self._ttl:
                return entry["val"]
        return None

    def set(self, key: str, val) -> None:
        with self._lock:
            self._store[key] = {"val": val, "ts": time.time()}

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            self._store = {k: v for k, v in self._store.items()
                          if (now - v["ts"]) < self._ttl}


_cache = _Cache(ttl=3600)



class _RateLimiter:
    def __init__(self, calls_per_second: float):
        self._interval = 1.0 / calls_per_second
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            gap = self._interval - (time.time() - self._last)
            if gap > 0:
                time.sleep(gap)
            self._last = time.time()



_osv_rl  = _RateLimiter(calls_per_second=5.0)
_nvd_rl  = _RateLimiter(calls_per_second=0.15)

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_SCAN_UA = "OWASP-Security-Scanner/2.0 (research)"



def _batch_osv(outdated: list) -> tuple[dict, int]:
    """
    Send one POST to OSV /v1/querybatch for all outdated libraries.
    """
    to_fetch, from_cache = [], {}

    for lib in outdated:
        key = f"osv:{lib['ecosystem']}:{lib['package']}:{lib['version']}"
        cached = _cache.get(key)
        if cached is not None:
            from_cache[lib["lib_key"]] = cached
        else:
            to_fetch.append(lib)

    if not to_fetch:
        return from_cache, 0

    payload = {
        "queries": [
            {
                "package": {"name": q["package"], "ecosystem": q["ecosystem"]},
                "version": q["version"],
            }
            for q in to_fetch
        ]
    }

    results = dict(from_cache)
    calls = 0

    try:
        _osv_rl.wait()
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json=payload,
            headers={"User-Agent": _SCAN_UA, "Content-Type": "application/json"},
            timeout=10,
        )
        calls = 1

        if resp.status_code == 200:
            batch = resp.json().get("results", [])
            for i, lib in enumerate(to_fetch):
                raw_vulns = batch[i].get("vulns", []) if i < len(batch) else []
                parsed = [_parse_osv_entry(v) for v in raw_vulns]
                cache_key = f"osv:{lib['ecosystem']}:{lib['package']}:{lib['version']}"
                _cache.set(cache_key, parsed)
                results[lib["lib_key"]] = parsed
        else:
            # Use empty list on OSV failure
            results.update({lib["lib_key"]: [] for lib in to_fetch})

    except requests.RequestException:
        results.update({lib["lib_key"]: [] for lib in to_fetch})

    return results, calls


def _parse_osv_entry(vuln: dict) -> dict:
    """Pull id, summary, and severity out of a raw OSV vuln object."""
    vuln_id  = vuln.get("id", "UNKNOWN")
    summary  = vuln.get("summary", "")[:150]
    severity = "Medium"  # sensible default

    # Try database_specific.severity first
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict) and db_specific.get("severity"):
        severity = str(db_specific["severity"]).capitalize()

    return {"id": vuln_id, "summary": summary, "severity": severity}



def _nvd_fallback(lib_key: str, package: str, version: str) -> list:
    """
    Query NVD for CVEs. Used only when OSV returns nothing.
    Rate-limited to ~1 call per 6.5 s to stay under the anonymous quota.
    """
    cache_key = f"nvd:{package}:{version}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        _nvd_rl.wait()
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": f"{package} {version}", "resultsPerPage": 5},
            headers={"User-Agent": _SCAN_UA},
            timeout=8,
        )
        if resp.status_code == 200:
            items = resp.json().get("vulnerabilities", [])
            parsed = []
            for item in items:
                cve   = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc  = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "",
                )

                sev = "Medium"
                metrics = cve.get("metrics", {})
                for m_list in metrics.values():
                    if m_list and isinstance(m_list[0], dict):
                        cvss_data = m_list[0].get("cvssData", {})
                        base_sev  = cvss_data.get("baseSeverity", "")
                        if base_sev:
                            sev = base_sev.capitalize()
                            break
                parsed.append({"id": cve_id, "summary": desc[:150], "severity": sev})

            _cache.set(cache_key, parsed)
            return parsed

    except requests.RequestException:
        pass

    return []



_SRC_RE      = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_VERSION_RE  = re.compile(r'[/@\-](\d+\.\d+\.\d+)(?:[.\-]min)?(?:\.js|\.css)?', re.I)
_COMMENT_RE  = re.compile(r'<!--(.*?)-->', re.DOTALL)
_CMT_VER_RE  = re.compile(r'v?(\d+\.\d+\.\d+)')


def _detect_libraries(html: str) -> list:
    """
    Pull library names and versions from script src attributes and HTML comments.
    No network involved — pure regex over the already-fetched HTML.
    """
    scripts  = _SRC_RE.findall(html)
    comments = _COMMENT_RE.findall(html)
    found    = []

    for lib_key, sig in _LIBRARIES.items():
        ver = src = None


        for s in scripts:
            if lib_key in s.lower():
                m = _VERSION_RE.search(s)
                if m:
                    ver, src = m.group(1), s
                    break

        # Fall back to HTML comments if no src match
        if not ver:
            for c in comments:
                if lib_key in c.lower():
                    m = _CMT_VER_RE.search(c)
                    if m:
                        ver, src = m.group(1), "html-comment"
                        break

        if ver:
            found.append({
                "lib_key": lib_key,
                "version": ver,
                "source":  src,
                **sig,  # ecosystem, package, safe_version
            })

    return found


def _is_outdated(detected: str, safe: str) -> bool:
    if _HAS_PKG:
        try:
            return pkg_version.parse(detected) < pkg_version.parse(safe)
        except Exception:
            pass
    try:
        return (
            tuple(int(x) for x in detected.split("."))
            < tuple(int(x) for x in safe.split("."))
        )
    except Exception:
        return False



def _check_headers(headers: dict) -> list:
    issues = []

    for h in _SECURITY_HEADERS:
        if h not in headers:
            issues.append({
                "type":           "Missing Security Header",
                "name":           f"Missing Header: {h}",
                "severity":       "Medium",
                "description":    f"The response is missing the {h} header.",
                "recommendation": f"Add the {h} header in your server or framework config.",
            })

    for h in _DISCLOSURE_HEADERS:
        val = headers.get(h)
        if val:
            issues.append({
                "type":           "Information Disclosure",
                "name":           f"Exposed {h} Header",
                "severity":       "Low",
                "description":    f"{h} is set to '{val}', which reveals stack details.",
                "recommendation": f"Remove or mask the {h} header.",
            })

    return issues



def scan_outdated_components(target_url: str) -> dict:
    """
    Called by server.py. Returns the standard vulnerability dict.

    Metrics returned alongside vulnerabilities:
      - api_calls_made  : total external API calls used (target: 1)
      - scan_summary    : library counts and cache hit rate
    """
    result = {
        "success":        True,
        "vulnerabilities": [],
        "api_calls_made": 0,
    }


    try:
        resp = requests.get(
            target_url,
            headers={"User-Agent": _UA},
            timeout=10,
            verify=True,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        return {"success": False, "error": str(e), "vulnerabilities": []}

    html         = resp.text
    resp_headers = dict(resp.headers)


    detected = _detect_libraries(html)


    outdated = [lib for lib in detected if _is_outdated(lib["version"], lib["safe_version"])]
    current  = [lib for lib in detected if not _is_outdated(lib["version"], lib["safe_version"])]

    total_api_calls = 0

    # Single batch call to OSV for CVE data
    cve_map, osv_calls = _batch_osv(outdated)
    total_api_calls += osv_calls

    # NVD fallback for packages OSV missed (capped at 3)
    nvd_calls = 0
    for lib in outdated:
        if not cve_map.get(lib["lib_key"]) and nvd_calls < 3:
            fallback = _nvd_fallback(lib["lib_key"], lib["package"], lib["version"])
            if fallback:
                cve_map[lib["lib_key"]] = fallback
            nvd_calls += 1

    total_api_calls += nvd_calls


    for lib in outdated:
        cves      = cve_map.get(lib["lib_key"], [])
        top_sev   = cves[0]["severity"] if cves else "Medium"
        cve_ids   = [c["id"] for c in cves[:5]]

        result["vulnerabilities"].append({
            "type":           "Outdated Component",
            "name":           f"Outdated Component ({lib['lib_key']})",
            "severity":       top_sev,
            "description":    (
                f"{lib['lib_key']} {lib['version']} detected "
                f"(minimum safe: {lib['safe_version']}). "
                + (f"Known CVEs: {', '.join(cve_ids)}." if cve_ids
                   else "No CVEs found in OSV or NVD for this version.")
            ),
            "recommendation": f"Upgrade {lib['lib_key']} to {lib['safe_version']} or later.",
            "cves":           cves[:5],  # extra context for the UI
        })


    result["vulnerabilities"].extend(_check_headers(resp_headers))

    result["api_calls_made"] = total_api_calls
    result["scan_summary"] = {
        "libraries_detected": len(detected),
        "outdated_count":     len(outdated),
        "current_count":      len(current),
        "api_calls_made":     total_api_calls,

        "osv_cache_hits":     len(outdated) - (osv_calls * len(outdated) // max(len(outdated), 1)),
    }

    return result



if __name__ == "__main__":
    import sys
    import json

    url = sys.argv[1] if len(sys.argv) > 1 else "https://demo.owasp-juice.shop"
    print(f"[*] Scanning: {url}\n")
    out = scan_outdated_components(url)
    print(json.dumps(out, indent=2, default=str))