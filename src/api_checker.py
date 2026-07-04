#!/usr/bin/env python3
"""
API Connectivity Checker and Configuration Tool

Tests connectivity to all required APIs and allows setting up private API keys.
"""

import sys
import json
import time
import urllib.parse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from typing import Dict, Tuple, Any

from config import ConfigManager, get_config


def test_nvd_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test NVD API connectivity.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        # Test with a known CVE
        test_cve = "CVE-2023-44487"
        url = config.get_nvd_url(test_cve)
        
        request = Request(url, headers={"User-Agent": "api-checker/1.0"})
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if data.get("vulnerabilities"):
                    status = "✓ Working"
                    if config.has_nvd_api_key():
                        status += " (with API key)"
                    else:
                        status += " (public, rate limited to 5 req/min)"
                    return True, status
                else:
                    return False, "API responded but no data returned"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        if e.code == 401:
            return False, "HTTP 401 Unauthorized (invalid API key?)"
        elif e.code == 429:
            return False, "HTTP 429 Too Many Requests (rate limited)"
        else:
            return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_epss_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test EPSS API connectivity.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        url = f"{config.EPSS_URL}?limit=1"
        request = Request(url, headers={"User-Agent": "api-checker/1.0"})
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if data.get("data"):
                    status = "✓ Working"
                    if config.has_epss_api_key():
                        status += " (with API key)"
                    else:
                        status += " (public)"
                    return True, status
                else:
                    return False, "API responded but no data returned"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_kev_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test CISA KEV API connectivity.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        request = Request(config.KEV_URL, headers={"User-Agent": "api-checker/1.0"})
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if data.get("vulnerabilities"):
                    count = len(data["vulnerabilities"])
                    return True, f"✓ Working ({count} exploited vulnerabilities in database)"
                else:
                    return False, "API responded but no data returned"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_vulncheck_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test VulnCheck KEV API connectivity.

    Returns:
        Tuple of (success, message)
    """
    token = config.get_vulncheck_api_token()
    if not token:
        return True, "◌ Skipped (VULNCHECK_API_TOKEN not configured)"

    try:
        headers = {
            "User-Agent": "api-checker/1.0",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "X-API-Key": token,
        }
        request = Request(config.VULNCHECK_KEV_URL, headers=headers)
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if isinstance(data, dict) and (
                    isinstance(data.get("data"), list)
                    or isinstance(data.get("vulnerabilities"), list)
                    or isinstance(data.get("results"), list)
                ):
                    return True, "✓ Working (VulnCheck KEV accessible)"
                return True, "✓ Working (VulnCheck reachable; schema accepted)"
            return False, f"HTTP {response.status}"
    except HTTPError as e:
        if e.code == 401:
            return False, "HTTP 401 Unauthorized (invalid VulnCheck token?)"
        if e.code == 403:
            return False, "HTTP 403 Forbidden (token lacks access or quota exceeded)"
        return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_osv_api(config: ConfigManager) -> Tuple[bool, str]:
    """Test OSV query API connectivity."""
    try:
        request = Request(
            "https://api.osv.dev/v1/vulns/CVE-2023-44487",
            headers={
                "User-Agent": "api-checker/1.0",
                "Accept": "application/json",
            },
            method="GET",
        )
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if isinstance(data, dict):
                    return True, "✓ Working (OSV query accessible)"
                return False, "API responded with unexpected schema"
            return False, f"HTTP {response.status}"
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_github_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test GitHub Search API connectivity.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        # Test with a simple search
        query = "exploit"
        url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&per_page=1"
        
        headers = {
            "User-Agent": "api-checker/1.0",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
        token = config.get_github_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        request = Request(url, headers=headers)
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if "total_count" in data:
                    status = "✓ Working"
                    if token:
                        status += " (with GitHub token — 30 req/min)"
                    else:
                        status += " (unauthenticated — 10 req/min)"
                    return True, status
                else:
                    return False, "API responded but no data returned"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        if e.code == 401:
            return False, "HTTP 401 Unauthorized (invalid GitHub token?)"
        elif e.code == 403:
            return False, "HTTP 403 Forbidden (rate limited or API rate limit exceeded)"
        elif e.code == 422:
            return False, "HTTP 422 Validation error (invalid query)"
        else:
            return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_exploitdb_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test ExploitDB CSV connectivity (used for Metasploit/exploit detection).
    
    Returns:
        Tuple of (success, message)
    """
    try:
        url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
        
        headers = {"User-Agent": "api-checker/1.0"}
        request = Request(url, headers=headers)
        
        with urlopen(request, timeout=15) as response:
            if response.status == 200:
                # Just check we can read the header
                sample = response.read(500).decode("utf-8", errors="replace")
                if "id,file,description" in sample:
                    return True, "✓ Working (ExploitDB CSV accessible)"
                else:
                    return False, "Unexpected CSV format"
            elif response.status == 304:
                return True, "✓ Working (cached via ETag)"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        if e.code == 304:
            return True, "✓ Working (cached)"
        else:
            return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def run_diagnostics() -> int:
    """Run API diagnostics and return exit code."""
    config = get_config()
    
    print("\n" + "=" * 70)
    print("Vulnerability Prioritization Tool - API Diagnostics")
    print("=" * 70)
    
    results = {}
    
    # Test each API
    print("\n1. Testing NVD API (CVSS)...")
    success, msg = test_nvd_api(config)
    results["NVD"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)  # Rate limiting
    
    print("\n2. Testing EPSS API (Exploit Prediction)...")
    success, msg = test_epss_api(config)
    results["EPSS"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)
    
    print("\n3. Testing CISA KEV API (Known Exploited)...")
    success, msg = test_kev_api(config)
    results["CISA KEV"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)

    print("\n4. Testing VulnCheck KEV API (Early Exploitation Signal)...")
    success, msg = test_vulncheck_api(config)
    results["VulnCheck KEV"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)

    print("\n5. Testing OSV API (NVD fallback metadata)...")
    success, msg = test_osv_api(config)
    results["OSV"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)
    
    print("\n6. Testing GitHub Search API (PoC detection)...")
    success, msg = test_github_api(config)
    results["GitHub Search"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)
    
    print("\n7. Testing ExploitDB CSV (Metasploit/exploit detection)...")
    success, msg = test_exploitdb_api(config)
    results["ExploitDB"] = (success, msg)
    print(f"   {msg}")
    
    # Print summary
    print("\n" + "-" * 70)
    all_working = all(success for success, _ in results.values())
    
    if all_working:
        print("✓ All APIs are accessible!")
    else:
        print("⚠ Some APIs are not accessible:")
        for api, (success, _) in results.items():
            if not success:
                print(f"  - {api}")
    
    # Print API key status
    print("\nOptional API Keys / Tokens:")
    print(f"  - NVD API Key: {'✓ Configured' if config.has_nvd_api_key() else '✗ Not configured'}")
    print(f"    Benefit: 5 req/sec instead of 5 req/min (60× faster for large batches)")
    print(f"  - GitHub Token: {'✓ Configured' if config.has_github_token() else '✗ Not configured'}")
    print(f"    Benefit: 30 req/min + Metasploit module detection via repo code search")
    print(f"  - VulnCheck Token: {'✓ Configured' if config.has_vulncheck_api_token() else '✗ Not configured'}")
    print(f"    Benefit: Early KEV signal coverage in addition to CISA KEV")
    
    print("=" * 70)
    
    return 0 if all_working else 1


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        # Run interactive setup
        config = get_config()
        config.prompt_for_keys()
        print("Running diagnostics after setup...\n")
        time.sleep(1)
        return run_diagnostics()
    else:
        # Just run diagnostics
        return run_diagnostics()


if __name__ == "__main__":
    sys.exit(main())
