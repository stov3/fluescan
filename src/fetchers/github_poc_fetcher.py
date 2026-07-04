#!/usr/bin/env python3
"""
GitHub PoC (Proof of Concept) Fetcher

Searches GitHub for public exploits and PoCs related to CVEs.
Uses both exact CVE ID matching and keyword-based searching.
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error

# GitHub API best-practice headers
# https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api
GITHUB_API_VERSION = "2022-11-28"
GITHUB_ACCEPT       = "application/vnd.github+json"

# ETag cache file — conditional requests that return 304 do NOT count against rate limit.
# Each entry stores BOTH the ETag and the response items so a 304 can reuse the data.
ETAG_CACHE_FILE = Path(".github_etag_cache.json")

# Per-CVE result cache — fresh entries skip the GitHub API entirely on re-runs
POC_CACHE_FILE = Path(".github_poc_cache.json")
POC_CACHE_TTL = 24 * 3600  # 24 hours


def _load_etag_cache() -> dict:
    """Load ETag cache from disk. Ignores legacy entries without a body."""
    try:
        if ETAG_CACHE_FILE.exists():
            cache = json.loads(ETAG_CACHE_FILE.read_text())
            # Drop legacy string-only entries (etag without cached body)
            return {k: v for k, v in cache.items() if isinstance(v, dict)}
    except Exception:
        pass
    return {}


def _save_etag_cache(cache: dict) -> None:
    """Persist ETag cache to disk."""
    try:
        ETAG_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        pass


def _load_poc_cache() -> dict:
    """Load per-CVE PoC result cache from disk."""
    try:
        if POC_CACHE_FILE.exists():
            return json.loads(POC_CACHE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_poc_cache(cache: dict) -> None:
    """Persist per-CVE PoC result cache to disk."""
    try:
        POC_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        pass


def _github_headers(token: str = None) -> dict:
    """Build standard GitHub API headers per best-practice docs."""
    headers = {
        "User-Agent":          "vuln-prioritize/1.0",
        "Accept":              GITHUB_ACCEPT,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def is_data_repo(repo_name, description):
    """
    Filter out known CVE database/tracking repositories.
    Returns True if this appears to be a data repo (not an actual exploit).
    """
    data_keywords = [
        'cve-list', 'cve-tracker', 'cve-archive', 'cve-database',
        'vulnerability-list', 'vulnerability-tracker', 'vulnerability-database',
        'cve-monitor', 'cve-feed', 'nvd', 'awesome-cves', 'cve-data',
        'cve-collection', 'security-advisories', 'vulnerability-data'
    ]
    
    combined = f"{repo_name} {description}".lower()
    return any(keyword in combined for keyword in data_keywords)


def has_exploit_context(description, language):
    """
    Check if repo description suggests actual exploit/tool code (not just data).
    Returns True if keywords indicate this is likely a real PoC or security tool.
    """
    if not description:
        # No description is suspicious, but allow if it's code language
        return language and language.lower() in ['python', 'bash', 'shell', 'go', 'c', 'java', 'javascript']
    
    exploit_keywords = [
        'exploit', 'poc', 'proof of concept', 'proof-of-concept',
        'rce', 'remote code execution', 'payload', 'shellcode',
        'scanner', 'tool', 'framework', 'vulnerability',
        'malware', 'reverse shell', 'backdoor', 'dos', 'ddos',
        'attack', 'test', 'detection', 'vulnerable', 'bypass',
        'injection', 'xss', 'sql', 'csrf', 'ssrf',
        'scanning', 'checker', 'fuzzer', 'crawler'
    ]
    
    description_lower = description.lower()
    return any(keyword in description_lower for keyword in exploit_keywords)


def search_github_poc(cve_id):
    """
    Search GitHub for public PoCs and exploits for a CVE.
    
    Uses realistic filtering:
    - Searches in code files (not just metadata)
    - Filters by programming language (Python, Bash, Go, etc.)
    - Excludes known CVE database repos
    - Requires exploit context keywords
    - Prioritizes by stars (community validation)
    
    Args:
        cve_id (str): CVE ID (e.g., "CVE-2026-9999")
    
    Returns:
        dict: {
            "found": bool,
            "count": int,
            "repos": [
                {
                    "name": str,
                    "url": str,
                    "stars": int,
                    "description": str,
                    "language": str,
                    "poc_keywords": [str]
                }
            ],
            "error": str or None
        }
    """
    # Resolve token from config (determines rate-limit tier)
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(__file__).parent.parent))
        from config import get_config
        _cfg = get_config()
        token = _cfg.get_github_token()
    except Exception:
        token = None

    has_token = bool(token)
    limiter = get_rate_limiter("github", has_api_key=has_token)
    etag_cache = _load_etag_cache()

    try:
        # Single query per CVE (was 2) — PoC repos are almost always named
        # after the CVE ID, so matching the bare ID in name/description covers
        # both "exploit" and "poc" labelled repos. Exploit-context filtering
        # below removes database/tracker noise. This halves GitHub API usage.
        queries = [
            f'{cve_id} in:name,description',
        ]
        
        repos = []
        seen_urls = set()
        rate_limited = False

        # Use a single shared endpoint key so the local sliding window
        # correctly accumulates all GitHub requests across all CVEs/queries
        GITHUB_ENDPOINT = "github_search"
        
        for query in queries:
            if rate_limited:
                break  # Stop trying queries if we've hit rate limit
            
            try:
                # Enforce rate limit before each query (shared window)
                limiter.acquire(GITHUB_ENDPOINT)
                
                # GitHub Search API — best-practice headers + ETag conditional request.
                # per_page=50 costs the same 1 request as 20 but improves recall
                # for the broader single-query search.
                search_url = (
                    f"https://api.github.com/search/repositories"
                    f"?q={urllib.parse.quote(query)}"
                    f"&sort=stars&order=desc&per_page=50"
                )
                
                hdrs = _github_headers(token)
                # Add ETag/If-None-Match for conditional request (304 = free, no rate-limit cost)
                cache_key = search_url
                cached_entry = etag_cache.get(cache_key)
                if cached_entry and cached_entry.get("etag"):
                    hdrs["If-None-Match"] = cached_entry["etag"]

                req = urllib.request.Request(search_url, headers=hdrs)
                
                items = None
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        update_rate_limit_from_response("github", response.headers)
                        data = json.loads(response.read().decode('utf-8'))
                        items = data.get('items', [])
                        # Cache ETag AND response items so a future 304 can reuse the data
                        etag = response.headers.get("ETag") or response.headers.get("etag")
                        if etag:
                            etag_cache[cache_key] = {"etag": etag, "items": items}
                            _save_etag_cache(etag_cache)
                except urllib.error.HTTPError as http_err:
                    if http_err.code == 304 and cached_entry:
                        # Not Modified — reuse cached items (request was free)
                        items = cached_entry.get("items", [])
                    else:
                        raise
                
                # Process results (fresh or 304-cached)
                for item in items or []:
                    url = item.get('html_url')
                    name = item.get('name', 'Unknown')
                    description = item.get('description', '')
                    language = item.get('language', 'Unknown')
                    stars = item.get('stargazers_count', 0)
                    
                    # Skip already seen repos
                    if url in seen_urls:
                        continue
                    
                    # Skip known CVE database/tracker repos (metadata, not exploits)
                    if is_data_repo(name, description):
                        continue
                    
                    # Require exploit context — the query no longer includes
                    # explicit exploit/poc keywords, so filter every result
                    if not has_exploit_context(description, language):
                        continue
                    
                    seen_urls.add(url)
                    repos.append({
                        'name': name,
                        'url': url,
                        'stars': stars,
                        'description': description,
                        'language': language,
                        'poc_keywords': extract_matching_keywords(item, language)
                    })
            
            except urllib.error.HTTPError as e:
                if e.code == 429 or e.code == 403:
                    # Rate limit hit - pass error headers so we get the exact reset time
                    handle_rate_limit_error("github", e.code, e.headers)
                    rate_limited = True
                    # Don't retry further queries, just return what we have
                    break
                elif e.code == 422:
                    # Bad query - skip and continue
                    continue
                else:
                    # Other HTTP errors - skip this query
                    continue
            except Exception:
                # Other errors - skip query and continue
                continue
            
            time.sleep(0.1)
        
        # Sort by stars (higher = more trusted and validated)
        repos.sort(key=lambda x: x['stars'], reverse=True)
        repos = repos[:5]  # Top 5 most starred
        
        return {
            'found': len(repos) > 0,
            'count': len(repos),
            'repos': repos,
            'error': None
        }
    
    except Exception as e:
        return {
            'found': False,
            'count': 0,
            'repos': [],
            'error': f'GitHub search failed: {str(e)}'
        }


def extract_matching_keywords(repo_item, language):
    """Extract keywords from repo that indicate exploit code."""
    keywords = []
    repo_text = (
        f"{repo_item.get('name', '')} "
        f"{repo_item.get('description', '')}"
    ).lower()
    
    # Add language as a keyword (code language = executable, not data)
    if language and language.lower() != 'unknown':
        keywords.append(language.upper())
    
    # Check for exploit-related terms in repo
    if 'poc' in repo_text or 'proof of concept' in repo_text:
        keywords.append('PoC')
    if 'exploit' in repo_text:
        keywords.append('Exploit')
    if 'rce' in repo_text:
        keywords.append('RCE')
    if 'payload' in repo_text:
        keywords.append('Payload')
    if 'scanner' in repo_text:
        keywords.append('Scanner')
    
    return keywords if keywords else ['Code']


def fetch_github_pocs(cve_ids):
    """
    Fetch GitHub PoC information for multiple CVEs.
    
    Args:
        cve_ids (list): List of CVE IDs
    
    Returns:
        dict: {
            "CVE-XXXX-XXXXX": {
                "found": bool,
                "count": int,
                "repos": [...],
                "error": str or None
            },
            ...
        }
    """
    results = {}
    cache = _load_poc_cache()
    now = time.time()
    cache_dirty = False
    
    for cve_id in cve_ids:
        # Serve from cache if fresh (zero rate-limit cost on re-runs)
        cached = cache.get(cve_id)
        if cached and (now - cached.get("timestamp", 0)) < POC_CACHE_TTL:
            results[cve_id] = cached["result"]
            continue
        
        result = search_github_poc(cve_id)
        results[cve_id] = result
        # Only cache clean results — errors/rate-limits should retry next run
        if result.get("error") is None:
            cache[cve_id] = {"timestamp": now, "result": result}
            cache_dirty = True
    
    if cache_dirty:
        _save_poc_cache(cache)
    
    return results


if __name__ == "__main__":
    # Test
    test_cves = ["CVE-2026-9999", "CVE-2023-44487"]
    results = fetch_github_pocs(test_cves)
    print(json.dumps(results, indent=2))
