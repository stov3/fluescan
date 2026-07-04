#!/usr/bin/env python3
"""
Metasploit & ExploitDB Fetcher

Two data sources (used together):

1. ExploitDB CSV (primary, no auth)
   https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
   - 47 k+ public exploits indexed by CVE in the `codes` column
   - .rb files = confirmed Metasploit modules submitted to ExploitDB
   - Downloaded once per session, cached with Last-Modified for free re-runs

2. GitHub code search in rapid7/metasploit-framework (secondary, needs GITHUB_TOKEN)
   - Searches the official MSF repo source for the CVE string
   - Authoritative for Metasploit coverage; requires authenticated GitHub API
   - Only attempted when a token is configured
"""

import csv
import io
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error

EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)

_EXPLOITDB_INDEX = None
_EXPLOITDB_CACHE_FILE = Path(".exploitdb_cache.json")
_EXPLOITDB_CSV_FILE  = Path(".exploitdb_data.csv")   # cached CSV on disk

GITHUB_MSF_REPO = "rapid7/metasploit-framework"
GITHUB_MSF_PATHS = "path:modules"
GITHUB_ACCEPT    = "application/vnd.github+json"
GITHUB_API_VER   = "2022-11-28"


def _load_exploitdb_cache():
    try:
        if _EXPLOITDB_CACHE_FILE.exists():
            return json.loads(_EXPLOITDB_CACHE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_exploitdb_cache(cache):
    try:
        _EXPLOITDB_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        pass


def _build_index(csv_text):
    index = {}
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        codes = row.get("codes", "")
        for token in codes.split(";"):
            token = token.strip().upper()
            if token.startswith("CVE-"):
                index.setdefault(token, []).append(row)
    return index


def _get_exploitdb_index():
    global _EXPLOITDB_INDEX
    if _EXPLOITDB_INDEX is not None:
        return _EXPLOITDB_INDEX

    disk_cache = _load_exploitdb_cache()
    headers = {"User-Agent": "fluescan/1.0"}
    if disk_cache.get("last_modified"):
        headers["If-Modified-Since"] = disk_cache["last_modified"]
    if disk_cache.get("etag"):
        headers["If-None-Match"] = disk_cache["etag"]

    req = urllib.request.Request(EXPLOITDB_CSV_URL, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            csv_bytes = r.read()
            csv_text = csv_bytes.decode("utf-8", errors="replace")
            new_cache = {}
            lm = r.headers.get("Last-Modified") or r.headers.get("last-modified")
            et = r.headers.get("ETag") or r.headers.get("etag")
            if lm:
                new_cache["last_modified"] = lm
            if et:
                new_cache["etag"] = et
            index = _build_index(csv_text)
            # Persist CSV and metadata so 304 responses can use the cached data
            try:
                _EXPLOITDB_CSV_FILE.write_bytes(csv_bytes)
            except Exception:
                pass
            _save_exploitdb_cache(new_cache)
    except urllib.error.HTTPError as e:
        if e.code == 304:
            # Server confirms data unchanged — rebuild index from our local copy
            if _EXPLOITDB_CSV_FILE.exists():
                try:
                    csv_text = _EXPLOITDB_CSV_FILE.read_bytes().decode("utf-8", errors="replace")
                    _EXPLOITDB_INDEX = _build_index(csv_text)
                    return _EXPLOITDB_INDEX
                except Exception:
                    pass
        _EXPLOITDB_INDEX = {}
        return _EXPLOITDB_INDEX
    except Exception:
        _EXPLOITDB_INDEX = {}
        return _EXPLOITDB_INDEX

    _EXPLOITDB_INDEX = index
    return _EXPLOITDB_INDEX


def _lookup_exploitdb(cve_id):
    return _get_exploitdb_index().get(cve_id.upper(), [])


def _is_msf_module(row):
    return row.get("file", "").endswith(".rb") or "Metasploit" in row.get("description", "")


def _row_to_module(row):
    eid = row.get("id", "")
    is_msf = _is_msf_module(row)
    verified = row.get("verified", "0") == "1"
    return {
        "id":       eid,
        "name":     row.get("description", ""),
        "type":     "metasploit" if is_msf else "exploit",
        "platform": row.get("platform", "Unknown"),
        "trusted":  is_msf,
        "verified": verified,
        "url":      f"https://www.exploit-db.com/exploits/{eid}",
        "author":   row.get("author", "Unknown"),
        "source":   "exploitdb",
    }


def _search_msf_github(cve_id, token):
    limiter = get_rate_limiter("github", has_api_key=True)
    limiter.acquire("github_search")

    query = (
        f"{urllib.parse.quote(cve_id)}"
        f"+repo:{GITHUB_MSF_REPO}"
        f"+{GITHUB_MSF_PATHS}"
    )
    url = f"https://api.github.com/search/code?q={query}&per_page=10"
    req = urllib.request.Request(url, headers={
        "User-Agent":           "fluescan/1.0",
        "Accept":               GITHUB_ACCEPT,
        "X-GitHub-Api-Version": GITHUB_API_VER,
        "Authorization":        f"Bearer {token}",
    })

    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            update_rate_limit_from_response("github", r.headers)
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code in (429, 403):
            handle_rate_limit_error("github", e.code, e.headers)
        return []
    except Exception:
        return []

    modules = []
    for item in data.get("items", []):
        path = item.get("path", "")
        if not path.endswith(".rb"):
            continue
        name = Path(path).stem.replace("_", " ").title()
        modules.append({
            "id":       path,
            "name":     f"MSF: {name}",
            "type":     "metasploit",
            "platform": "Multiple",
            "trusted":  True,
            "verified": True,
            "url":      item.get("html_url", ""),
            "author":   "Rapid7 / Metasploit Team",
            "source":   "msf_github",
        })
    return modules


def get_module_reliability(module):
    if module.get("source") == "msf_github":
        return "excellent"
    if module.get("trusted") and module.get("verified"):
        return "excellent"
    if module.get("verified"):
        return "great"
    if module.get("trusted"):
        return "good"
    return "normal"


def check_metasploit_module(cve_id):
    token = None
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from config import get_config
        token = get_config().get_github_token()
    except Exception:
        pass

    modules = []

    try:
        for row in _lookup_exploitdb(cve_id):
            modules.append(_row_to_module(row))
    except Exception:
        pass

    if token:
        try:
            existing_ids = {m["id"] for m in modules}
            for m in _search_msf_github(cve_id, token):
                if m["id"] not in existing_ids:
                    modules.append(m)
        except Exception:
            pass

    modules.sort(key=lambda m: (0 if m["type"] == "metasploit" else 1, m["name"]))

    return {
        "found":   len(modules) > 0,
        "modules": modules,
        "error":   None,
    }


def fetch_metasploit_info(cve_ids):
    _get_exploitdb_index()
    results = {}
    for cve_id in cve_ids:
        results[cve_id] = check_metasploit_module(cve_id)
    return results


if __name__ == "__main__":
    test_cves = ["CVE-2021-44228", "CVE-2023-44487", "CVE-2022-22965", "CVE-2099-9999"]
    data = fetch_metasploit_info(test_cves)
    print(json.dumps(data, indent=2, default=str))
