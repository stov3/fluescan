#!/usr/bin/env python3
"""Fetch VulnCheck KEV data and filter for specific CVEs."""

import json
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from config import get_config
from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error


VULNCHECK_KEV_CACHE_FILE = Path(".vulncheck_kev_cache.json")
VULNCHECK_KEV_CACHE_TTL = 6 * 3600  # 6 hours


def _load_cache() -> Dict[str, Any]:
    try:
        if VULNCHECK_KEV_CACHE_FILE.exists():
            return json.loads(VULNCHECK_KEV_CACHE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        VULNCHECK_KEV_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        pass


def _extract_entries(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("vulnerabilities"), list):
            return payload["vulnerabilities"]
        if isinstance(payload.get("data"), list):
            return payload["data"]
        if isinstance(payload.get("results"), list):
            return payload["results"]
    if isinstance(payload, list):
        return payload
    return []


def _extract_cve_id(entry: Dict[str, Any]) -> str:
    for key in ("cve", "cveID", "cve_id", "id"):
        value = entry.get(key)
        if isinstance(value, str) and value.upper().startswith("CVE-"):
            return value.upper()

    # Some providers nest identifiers under aliases/references.
    aliases = entry.get("aliases")
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, str) and alias.upper().startswith("CVE-"):
                return alias.upper()
    return ""


def fetch_vulncheck_kev_data() -> Dict[str, Any]:
    """
    Fetch VulnCheck KEV feed.

    Returns:
        Dict with keys:
          - vulnerabilities: list
          - source: str
          - error: optional str
    """
    config = get_config()
    token = config.get_vulncheck_api_token()

    if not token:
        return {
            "vulnerabilities": [],
            "source": "vulncheck",
            "error": "VULNCHECK_API_TOKEN not configured",
        }

    cache = _load_cache()
    now = time.time()
    if (
        isinstance(cache, dict)
        and cache.get("timestamp")
        and (now - float(cache.get("timestamp", 0))) < VULNCHECK_KEV_CACHE_TTL
        and isinstance(cache.get("vulnerabilities"), list)
    ):
        return {
            "vulnerabilities": cache["vulnerabilities"],
            "source": "vulncheck",
        }

    limiter = get_rate_limiter("vulncheck", has_api_key=True)
    limiter.acquire("vulncheck_kev")

    headers = {
        "User-Agent": "vuln-prioritize/1.0",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-API-Key": token,
    }

    request = Request(config.VULNCHECK_KEV_URL, headers=headers)

    try:
        with urlopen(request, timeout=20) as response:
            update_rate_limit_from_response("vulncheck", response.headers)
            data = json.loads(response.read().decode("utf-8"))
            vulnerabilities = _extract_entries(data)

            _save_cache(
                {
                    "timestamp": now,
                    "vulnerabilities": vulnerabilities,
                }
            )

            return {
                "vulnerabilities": vulnerabilities,
                "source": "vulncheck",
            }

    except HTTPError as exc:
        if exc.code in (403, 429):
            handle_rate_limit_error("vulncheck", exc.code, exc.headers)
        return {
            "vulnerabilities": [],
            "source": "vulncheck",
            "error": f"HTTP {exc.code}: {exc.reason}",
        }
    except (URLError, ValueError) as exc:
        return {
            "vulnerabilities": [],
            "source": "vulncheck",
            "error": str(exc),
        }


def filter_vulncheck_kev_by_cves(vulncheck_data: Dict[str, Any], cve_ids: List[str]) -> Dict[str, Any]:
    """Filter VulnCheck KEV data for specific CVEs."""
    results = {
        "found": {},
        "not_found": [],
        "source": "vulncheck",
        "error": vulncheck_data.get("error"),
    }

    entries = vulncheck_data.get("vulnerabilities", [])
    mapped = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve = _extract_cve_id(entry)
        if cve:
            mapped[cve] = entry

    for cve_id in cve_ids:
        cve_upper = cve_id.upper()
        if cve_upper in mapped:
            results["found"][cve_upper] = mapped[cve_upper]
        else:
            results["not_found"].append(cve_upper)

    return results
