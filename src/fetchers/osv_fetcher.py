#!/usr/bin/env python3
"""Fetch OSV data for CVEs for metadata fallback when NVD is missing."""

import json
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error


OSV_VULN_URL = "https://api.osv.dev/v1/vulns"


def _extract_numeric_score(vuln: Dict[str, Any]) -> float:
    severity_list = vuln.get("severity")
    if not isinstance(severity_list, list):
        return -1.0

    for item in severity_list:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if not isinstance(score, str):
            continue
        # Some records use a raw numeric score, others a vector string.
        try:
            return float(score)
        except ValueError:
            continue

    return -1.0


def _extract_severity_text(vuln: Dict[str, Any]) -> str:
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity")
        if isinstance(sev, str) and sev:
            return sev.upper()
    return "UNKNOWN"


def _query_single_cve(cve_id: str, limiter) -> Dict[str, Any]:
    cve_upper = cve_id.upper()
    request = Request(
        f"{OSV_VULN_URL}/{cve_upper}",
        headers={
            "User-Agent": "fluescan/1.0",
            "Accept": "application/json",
        },
        method="GET",
    )

    limiter.acquire("osv_query")
    try:
        with urlopen(request, timeout=20) as response:
            update_rate_limit_from_response("osv", response.headers)
            data = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code in (429, 403):
            handle_rate_limit_error("osv", exc.code, exc.headers)
            limiter.acquire("osv_query_retry")
            with urlopen(request, timeout=20) as response:
                update_rate_limit_from_response("osv", response.headers)
                data = json.loads(response.read().decode("utf-8"))
        else:
            raise

    if not isinstance(data, dict):
        return {
            "found": False,
            "score": -1.0,
            "severity": "UNKNOWN",
            "summary": "",
            "osv_id": "",
            "error": "Invalid OSV response",
        }

    if not data:
        return {
            "found": False,
            "score": -1.0,
            "severity": "UNKNOWN",
            "summary": "",
            "osv_id": "",
            "error": "CVE not found in OSV",
        }

    return {
        "found": True,
        "score": _extract_numeric_score(data),
        "severity": _extract_severity_text(data),
        "summary": data.get("summary", ""),
        "osv_id": data.get("id", ""),
        "error": None,
    }


def fetch_osv_for_cves(cve_ids: List[str]) -> Dict[str, Any]:
    """
    Query OSV in batch for a list of CVEs.

    Returns:
        Mapping keyed by upper-case CVE with fallback metadata:
        {
          "CVE-...": {
             "found": bool,
             "score": float,
             "severity": str,
             "summary": str,
             "osv_id": str,
             "error": str | None,
          }
        }
    """
    results: Dict[str, Any] = {}
    if not cve_ids:
        return results

    limiter = get_rate_limiter("osv", has_api_key=False)

    for cve in cve_ids:
        key = cve.upper()
        try:
            results[key] = _query_single_cve(key, limiter)
        except HTTPError as exc:
            results[key] = {
                "found": False,
                "score": -1.0,
                "severity": "UNKNOWN",
                "summary": "",
                "osv_id": "",
                "error": f"HTTP {exc.code}: {exc.reason}",
            }
        except (URLError, ValueError, json.JSONDecodeError) as exc:
            results[key] = {
                "found": False,
                "score": -1.0,
                "severity": "UNKNOWN",
                "summary": "",
                "osv_id": "",
                "error": str(exc),
            }

    return results
