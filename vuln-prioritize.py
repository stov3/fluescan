#!/usr/bin/env python3
"""
Vulnerability Prioritization Tool - Main Entry Point

This tool combines CVSS scores, EPSS predictions, dual KEV signals (CISA +
VulnCheck), public PoCs, and Metasploit modules to provide comprehensive
vulnerability prioritization with exploit availability analysis.

Usage:
    python3 vuln-prioritize.py CVE-2024-1234 CVE-2024-5678
    python3 vuln-prioritize.py --cves-file cves.txt
    python3 vuln-prioritize.py CVE-2024-1234 --output-json report.json
    python3 vuln-prioritize.py --check-apis
    python3 vuln-prioritize.py --setup
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import fetcher modules
from fetchers.cvss_fetcher import fetch_cvss_for_cves
from fetchers.epss_fetcher import fetch_epss_for_cves
from fetchers.kev_fetcher import fetch_kev_data, filter_kev_by_cves
from fetchers.vulncheck_kev_fetcher import fetch_vulncheck_kev_data, filter_vulncheck_kev_by_cves
from fetchers.osv_fetcher import fetch_osv_for_cves
from fetchers.github_poc_fetcher import fetch_github_pocs
from fetchers.metasploit_fetcher import fetch_metasploit_info, get_module_reliability
from config import get_config
from rate_limiter import get_apis_rate_limited_during_run
from console import (
    format_cve_table, header, success, error, info, Colors,
    print_title, print_disclaimer_and_author,
)


def load_cves_from_file(filepath: str) -> List[str]:
    """
    Load CVE IDs from a file (one CVE per line).
    
    Args:
        filepath: Path to file containing CVE IDs
        
    Returns:
        List of CVE IDs
    """
    with open(filepath, 'r') as f:
        cves = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return cves


def normalize_cve_inputs(values: List[str]) -> List[str]:
    """Normalize CVE input tokens from CLI/file into canonical uppercase IDs.

    Supports both space-separated and comma-separated formats and ignores
    accidental trailing punctuation.
    """
    normalized: List[str] = []
    pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")

    for raw in values:
        if not raw:
            continue
        for token in raw.split(','):
            cve = token.strip().upper().strip(';,')
            if cve and pattern.match(cve):
                normalized.append(cve)

    return normalized


def extract_cvss_score(cvss_data: Dict[str, Any]) -> Tuple[float, str]:
    """
    Extract CVSS score and severity from CVE data.

    Prefers v3.1, falls back to v3.0, then v2 (severity derived from score)
    so older CVEs without v3.x metrics still get scored.

    Args:
        cvss_data: CVE data from NVD

    Returns:
        Tuple of (score, severity)
    """
    if "error" in cvss_data:
        return 0.0, "UNKNOWN"

    metrics = cvss_data.get("metrics", {})

    # CVSS v3.x (v3.1 preferred)
    for key in ("cvssMetricV31", "cvssMetricV30"):
        try:
            data = metrics.get(key, [{}])[0].get("cvssData", {})
            if data.get("baseScore") is not None:
                return float(data["baseScore"]), data.get("baseSeverity", "UNKNOWN")
        except (ValueError, IndexError, TypeError):
            continue

    # CVSS v2 fallback — baseSeverity lives on the metric, not cvssData
    try:
        v2 = metrics.get("cvssMetricV2", [{}])[0]
        score = v2.get("cvssData", {}).get("baseScore")
        if score is not None:
            score = float(score)
            severity = v2.get("baseSeverity") or (
                "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
            )
            return score, severity
    except (ValueError, IndexError, TypeError):
        pass

    return 0.0, "UNKNOWN"


def extract_attack_vector(cvss_data: Dict[str, Any]) -> str:
    """Extract CVSS attack vector as one of N/A/L/P/UNKNOWN.

    Supports CVSS v3.x (attackVector), vectorString parsing fallback, and
    CVSS v2 (accessVector) mapped to AV-style values.
    """
    if "error" in cvss_data:
        return "UNKNOWN"

    metrics = cvss_data.get("metrics", {})

    # CVSS v3.x first (v3.1 preferred)
    for key in ("cvssMetricV31", "cvssMetricV30"):
        try:
            data = metrics.get(key, [{}])[0].get("cvssData", {})

            # Primary source in NVD schema
            attack_vector = str(data.get("attackVector", "")).strip().upper()
            if attack_vector:
                return {
                    "NETWORK": "N",
                    "ADJACENT_NETWORK": "A",
                    "LOCAL": "L",
                    "PHYSICAL": "P",
                }.get(attack_vector, "UNKNOWN")

            # Fallback: parse vector string
            vector = str(data.get("vectorString", "")).upper()
            for token in ("AV:N", "AV:A", "AV:L", "AV:P"):
                if token in vector:
                    return token[-1]
        except (IndexError, TypeError, AttributeError):
            continue

    # CVSS v2 fallback: accessVector is NETWORK / ADJACENT_NETWORK / LOCAL
    try:
        v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
        access_vector = str(v2.get("accessVector", "")).strip().upper()
        if access_vector:
            return {
                "NETWORK": "N",
                "ADJACENT_NETWORK": "A",
                "LOCAL": "L",
            }.get(access_vector, "UNKNOWN")

        vector_v2 = str(v2.get("vectorString", "")).upper()
        for token in ("AV:N", "AV:A", "AV:L"):
            if token in vector_v2:
                return token[-1]
    except (IndexError, TypeError, AttributeError):
        pass

    return "UNKNOWN"


def attack_vector_exposure_weight(attack_vector: str) -> float:
    """Return a soft exposure weight from CVSS AV metric.

    This signal intentionally has small impact and is used as a nudge:
    - N (Network): more internet-exposed potential
    - A (Adjacent): somewhat externally reachable
    - L (Local): likely more internal preconditioned
    - P (Physical): generally harder to exploit remotely
    """
    av = (attack_vector or "UNKNOWN").upper()
    if av == "N":
        return 1.07
    if av == "A":
        return 1.03
    if av == "L":
        return 0.96
    if av == "P":
        return 0.90
    return 1.00


def extract_epss_score(epss_data: Dict[str, Any]) -> Tuple[float, float]:
    """
    Extract EPSS score and percentile from EPSS data.
    
    Args:
        epss_data: EPSS data for a CVE
        
    Returns:
        Tuple of (epss_score, percentile) or (-1, -1) if not available
    """
    if "error" in epss_data:
        return -1.0, -1.0
    
    try:
        score = float(epss_data.get("epss", -1))
        percentile = float(epss_data.get("percentile", -1))
        # Return -1 if no data found
        if score < 0 and percentile < 0:
            return -1.0, -1.0
        return score, percentile
    except (ValueError, TypeError):
        return -1.0, -1.0


def get_kev_signals(
    cve_id: str,
    cisa_kev_results: Dict[str, Any],
    vulncheck_kev_results: Dict[str, Any],
) -> Tuple[bool, bool, float]:
    """
    Return KEV flags and score-impact KEV strength.

    Policy:
    - CISA KEV is a confirmed exploitation signal and affects scoring strongly
    - VulnCheck-only KEV is an early signal with reduced score impact
    """
    cve_upper = cve_id.upper()
    in_cisa = cve_upper in cisa_kev_results.get("found", {})
    in_vulncheck = cve_upper in vulncheck_kev_results.get("found", {})

    if in_cisa:
        return in_cisa, in_vulncheck, 1.0
    if in_vulncheck:
        return in_cisa, in_vulncheck, 0.4
    return in_cisa, in_vulncheck, 0.0


def apply_osv_fallback_to_cvss(
    cve_ids: List[str],
    cvss_results: Dict[str, Any],
    osv_results: Dict[str, Any],
) -> Dict[str, Any]:
    """Backfill missing NVD CVSS entries with OSV metadata when numeric score exists."""
    for cve_id in cve_ids:
        cvss_data = cvss_results.get(cve_id, {})
        cvss_score, _ = extract_cvss_score(cvss_data)
        if cvss_score > 0:
            continue

        osv = osv_results.get(cve_id.upper(), {})
        if not osv.get("found"):
            continue

        osv_score = osv.get("score", -1.0)
        if not isinstance(osv_score, (float, int)) or osv_score <= 0:
            continue

        cvss_results[cve_id] = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": float(osv_score),
                            "baseSeverity": str(osv.get("severity", "UNKNOWN")),
                        }
                    }
                ]
            },
            "source": "osv_fallback",
            "osv_id": osv.get("osv_id", ""),
            "osv_summary": osv.get("summary", ""),
        }

    return cvss_results


def extract_github_poc_data(github_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract GitHub PoC data for analysis.
    
    Args:
        github_results: Results from GitHub PoC fetcher
        
    Returns:
        Dict with PoC found status and top starred repos
    """
    return {
        "found": github_results.get("found", False),
        "count": github_results.get("count", 0),
        "top_repo": github_results.get("repos", [{}])[0] if github_results.get("repos") else None,
        "error": github_results.get("error")
    }


def extract_metasploit_data(msf_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract Metasploit data for analysis.
    
    Args:
        msf_results: Results from Metasploit fetcher
        
    Returns:
        Dict with module found status and reliability info
    """
    modules = msf_results.get("modules", [])
    
    if not modules:
        return {
            "found": False,
            "count": 0,
            "reliability": None,
            "error": msf_results.get("error")
        }
    
    # Get reliability of best (first) module
    best_module = modules[0]
    reliability = get_module_reliability(best_module)
    
    return {
        "found": True,
        "count": len(modules),
        "reliability": reliability,
        "best_module": best_module,
        "error": None
    }


def calculate_exploit_multiplier(
    github_data: Dict[str, Any],
    msf_data: Dict[str, Any]
) -> float:
    """
    Calculate a multiplier based on exploit availability and reliability.
    
    Multipliers:
    - Public PoC found: 1.2 (20% boost)
    - Metasploit module with reliability:
      - excellent: 1.35 (35% boost)
      - great: 1.30 (30% boost)
      - good: 1.25 (25% boost)
      - normal: 1.15 (15% boost)
    
    Multiple factors stack: multiplier = factor1 * factor2 * factor3
    (capped at reasonable levels)
    
    Args:
        github_data: GitHub PoC information
        msf_data: Metasploit module information
        
    Returns:
        Combined multiplier (e.g., 1.0, 1.2, 1.35, 1.50, etc.)
    """
    multiplier = 1.0
    
    # GitHub PoC boost
    if github_data.get("found"):
        multiplier *= 1.2
    
    # Metasploit reliability-based boost
    if msf_data.get("found"):
        reliability = msf_data.get("reliability")
        if reliability == "excellent":
            multiplier *= 1.35
        elif reliability == "great":
            multiplier *= 1.30
        elif reliability == "good":
            multiplier *= 1.25
        elif reliability == "normal":
            multiplier *= 1.15
    
    # Cap at reasonable level to avoid excessive boosting
    return min(multiplier, 1.75)


def calculate_priority_score(
    cvss_score: float,
    epss_score: float,
    kev_strength: float,
    cisa_confirmed_kev: bool,
    attack_vector: str = "UNKNOWN",
    github_poc_found: bool = False,
    metasploit_found: bool = False
) -> float:
    """
    Calculate vulnerability priority using a weighted risk blend.

    The score is intentionally simple and auditable:
    - Normalize each signal to [0, 1]
    - Blend with fixed weights
    - Apply a data completeness factor
    - Enforce a KEV-based critical floor when active exploitation is confirmed
    
    Args:
        cvss_score: CVSS v3.1 base score (0-10)
        epss_score: EPSS score (0-1) or -1 if not available
        kev_strength: KEV score-impact signal in [0,1] (CISA=1.0, VulnCheck-only=0.4)
        cisa_confirmed_kev: True only when CISA KEV confirms active exploitation
        attack_vector: CVSS attack vector (N/A/L/P/UNKNOWN)
        github_poc_found: Whether a public GitHub PoC was found
        metasploit_found: Whether a Metasploit module was found
        
    Returns:
        Priority score (0-100)
    """
    # Normalize to [0, 1]
    cvss_norm = min(max(cvss_score / 10.0, 0.0), 1.0) if cvss_score > 0 else 0.0
    epss_norm = min(max(epss_score, 0.0), 1.0) if epss_score >= 0 else 0.0
    kev_norm = min(max(kev_strength, 0.0), 1.0)

    # Exploit signal strength:
    # - 0.0: no exploit signal
    # - 0.5: GitHub PoC only
    # - 1.0: Metasploit present (with or without PoC)
    if metasploit_found:
        exploit_norm = 1.0
    elif github_poc_found:
        exploit_norm = 0.5
    else:
        exploit_norm = 0.0

    # Weighted linear blend
    raw_score = (
        (0.30 * cvss_norm)
        + (0.40 * epss_norm)
        + (0.20 * kev_norm)
        + (0.10 * exploit_norm)
    )

    # Completeness factor penalizes missing CVSS/EPSS while keeping binary KEV/exploit signals transparent.
    # KEV and exploit availability are always evaluated as explicit yes/no signals.
    data_sources_found = 0
    data_sources_found += 1 if cvss_score > 0 else 0
    data_sources_found += 1 if epss_score >= 0 else 0
    data_sources_found += 1
    data_sources_found += 1
    completeness_factor = data_sources_found / 4.0

    exposure_weight = attack_vector_exposure_weight(attack_vector)
    priority_score = raw_score * 100.0 * completeness_factor * exposure_weight

    # Active in-the-wild exploitation should never be ranked below critical.
    if cisa_confirmed_kev:
        priority_score = max(priority_score, 85.0)

    return min(max(priority_score, 0.0), 100.0)


def generate_report(
    cvss_results: Dict[str, Any],
    epss_results: Dict[str, Any],
    cisa_kev_results: Dict[str, Any],
    vulncheck_kev_results: Dict[str, Any],
    github_results: Dict[str, Any],
    msf_results: Dict[str, Any],
    cve_ids: List[str]
) -> List[Dict[str, Any]]:
    """
    Generate a comprehensive vulnerability prioritization report.
    
    Includes CVSS, EPSS, KEV, plus GitHub PoC, and Metasploit modules.
    
    Args:
        cvss_results: Results from CVSS fetcher
        epss_results: Results from EPSS fetcher
        cisa_kev_results: Results from CISA KEV fetcher
        vulncheck_kev_results: Results from VulnCheck KEV fetcher
        github_results: Results from GitHub PoC fetcher
        msf_results: Results from Metasploit fetcher
        cve_ids: List of requested CVE IDs
        
    Returns:
        List of prioritized vulnerability records
    """
    report = []
    
    for cve_id in cve_ids:
        cve_upper = cve_id.upper()
        
        # Extract data from each source
        cvss_data = cvss_results.get(cve_id, {})
        epss_data = epss_results.get(cve_upper, {})
        
        cvss_score, cvss_severity = extract_cvss_score(cvss_data)
        attack_vector = extract_attack_vector(cvss_data)
        epss_score, epss_percentile = extract_epss_score(epss_data)
        in_cisa_kev, in_vulncheck_kev, kev_strength = get_kev_signals(
            cve_id,
            cisa_kev_results,
            vulncheck_kev_results,
        )
        kev_status = "YES" if in_cisa_kev else ("EARLY" if in_vulncheck_kev else "NO")
        
        # Extract exploit data
        github_data = extract_github_poc_data(github_results.get(cve_id, {}))
        msf_data = extract_metasploit_data(msf_results.get(cve_id, {}))
        
        # Calculate exploit multiplier
        exploit_multiplier = calculate_exploit_multiplier(github_data, msf_data)
        
        # Calculate priority with exploit information
        priority_score = calculate_priority_score(
            cvss_score,
            epss_score,
            kev_strength,
            in_cisa_kev,
            attack_vector,
            github_data.get("found", False),
            msf_data.get("found", False),
        )
        
        # Build record with comprehensive data
        record = {
            "cve_id": cve_upper,
            "priority_score": round(priority_score, 2),
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "attack_vector": attack_vector,
            "exposure_weight": round(attack_vector_exposure_weight(attack_vector), 3),
            "epss_score": round(epss_score, 4),
            "epss_percentile": round(epss_percentile, 2),
            "epss_prev_7d": round(float(epss_data.get("epss_prev_7d", -1)), 4) if epss_data.get("epss_prev_7d") is not None else -1,
            "epss_delta_7d": round(float(epss_data.get("epss_delta_7d", 0)), 4) if epss_data.get("epss_delta_7d") is not None else 0,
            "in_kev": in_cisa_kev,
            "in_vulncheck_kev": in_vulncheck_kev,
            "kev_status": kev_status,
            "kev_signal_strength": kev_strength,
            "github_poc_found": github_data.get("found", False),
            "github_poc_count": github_data.get("count", 0),
            "metasploit_found": msf_data.get("found", False),
            "metasploit_reliability": msf_data.get("reliability"),
            "exploit_multiplier": round(exploit_multiplier, 2),
            "cvss_source": cvss_data.get("source", "nvd"),
            "cvss_error": cvss_data.get("error"),
            "epss_error": epss_data.get("error"),
            "vulncheck_error": vulncheck_kev_results.get("error"),
            "github_error": github_data.get("error"),
            "metasploit_error": msf_data.get("error"),
        }
        
        report.append(record)
    
    # Sort by priority score (descending)
    report.sort(key=lambda x: x["priority_score"], reverse=True)
    
    return report


def write_json_report(filepath: str, report: List[Dict[str, Any]]) -> None:
    """Write report to JSON file."""
    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"JSON report written to {filepath}")


def write_csv_report(filepath: str, report: List[Dict[str, Any]]) -> None:
    """Write report to CSV file with all fields including exploit data."""
    fieldnames = [
        "cve_id", "priority_score", "cvss_score", "cvss_severity", "attack_vector", "exposure_weight",
        "epss_score", "epss_percentile", "epss_prev_7d", "epss_delta_7d",
        "in_kev", "in_vulncheck_kev", "kev_status", "kev_signal_strength",
        "github_poc_found", "github_poc_count",
        "metasploit_found", "metasploit_reliability",
        "exploit_multiplier", "cvss_source",
        "cvss_error", "epss_error", "vulncheck_error", "github_error", "metasploit_error"
    ]
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report)
    print(f"CSV report written to {filepath}")


def print_table_report(report: List[Dict[str, Any]]) -> None:
    """Print formatted table report to console."""
    format_cve_table(report)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Vulnerability Prioritization Tool - Combine CVSS, EPSS, and KEV data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With individual CVE IDs
  python3 vuln-prioritize.py CVE-2024-1234 CVE-2024-5678
  
  # With CVE list from file
  python3 vuln-prioritize.py --cves-file cves.txt
  
  # With custom output paths
  python3 vuln-prioritize.py CVE-2024-1234 --output-json report.json --output-csv report.csv
  
  # Suppress console table
  python3 vuln-prioritize.py --cves-file cves.txt --no-table
  
  # Set up API keys
  python3 vuln-prioritize.py --setup
        """
    )
    
    parser.add_argument("cves", nargs="*", help="CVE IDs to analyze")
    parser.add_argument("--cves-file", help="File containing CVE IDs (one per line)")
    parser.add_argument("--output-json", default="vulnerability_report.json", help="JSON output file")
    parser.add_argument("--output-csv", default="vulnerability_report.csv", help="CSV output file")
    parser.add_argument("--no-table", action="store_true", help="Don't print table report to console")
    parser.add_argument("--setup", action="store_true", help="Configure API keys (interactive)")
    parser.add_argument("--check-apis", action="store_true", help="Check API connectivity")
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    # Handle setup flag (no title needed)
    if args.setup:
        config = get_config()
        config.prompt_for_keys()
        return 0
    
    # Handle API check flag (no title needed)
    if args.check_apis:
        import subprocess
        return subprocess.call([sys.executable, "src/api_checker.py"])
    
    # Display title and disclaimer for analysis mode only
    print_title()
    print_disclaimer_and_author()
    
    # Collect CVE IDs
    cve_ids = normalize_cve_inputs(list(args.cves) if args.cves else [])
    
    if args.cves_file:
        try:
            file_cves = normalize_cve_inputs(load_cves_from_file(args.cves_file))
            cve_ids.extend(file_cves)
        except FileNotFoundError:
            print(error(f"CVE file not found: {args.cves_file}"), file=sys.stderr)
            return 1
    
    # If no CVEs provided, offer interactive menu
    if not cve_ids:
        from console import interactive_menu
        cve_ids, json_out, csv_out, special_mode, no_table = interactive_menu()
        
        if special_mode == "check_apis":
            import subprocess
            return subprocess.call([sys.executable, "src/api_checker.py"])
        elif special_mode == "setup":
            config = get_config()
            config.prompt_for_keys()
            return 0
        elif not cve_ids:
            return 1
        
        # Override output options if user selected them
        if json_out:
            args.output_json = json_out
        if csv_out:
            args.output_csv = csv_out
    
    # Remove duplicates while preserving order
    cve_ids = list(dict.fromkeys(cve_ids))
    
    print(header(f"Analyzing {len(cve_ids)} CVE(s)..."))
    print("-" * 50)
    
    try:
        # Load configuration
        config = get_config()
        nvd_api_key = config.get_nvd_api_key()
        
        # Fetch data from all sources
        print("Fetching CVSS data...")
        cvss_results = fetch_cvss_for_cves(cve_ids, nvd_api_key)
        
        print("Fetching EPSS data...")
        epss_results = fetch_epss_for_cves(cve_ids)
        
        print("Fetching CISA KEV data...")
        cisa_kev_data = fetch_kev_data()
        cisa_kev_results = filter_kev_by_cves(cisa_kev_data, cve_ids)

        print("Fetching VulnCheck KEV data (early signal)...")
        vulncheck_kev_data = fetch_vulncheck_kev_data()
        vulncheck_kev_results = filter_vulncheck_kev_by_cves(vulncheck_kev_data, cve_ids)

        # OSV fallback: fill missing NVD CVSS values when OSV provides a numeric score.
        missing_cvss_ids = []
        for cve_id in cve_ids:
            cvss_score, _ = extract_cvss_score(cvss_results.get(cve_id, {}))
            if cvss_score <= 0:
                missing_cvss_ids.append(cve_id)

        if missing_cvss_ids:
            print(f"Fetching OSV fallback metadata for {len(missing_cvss_ids)} CVE(s)...")
            osv_results = fetch_osv_for_cves(missing_cvss_ids)
            cvss_results = apply_osv_fallback_to_cvss(missing_cvss_ids, cvss_results, osv_results)
        
        print("Searching for GitHub PoCs...")
        github_results = fetch_github_pocs(cve_ids)
        
        print("Checking Metasploit modules...")
        msf_results = fetch_metasploit_info(cve_ids)
        
        # Report any APIs that hit their rate limit during fetching
        # (acquire() automatically blocks and waits when limit is reached)
        rate_limited_apis = get_apis_rate_limited_during_run()
        if rate_limited_apis:
            api_names = ", ".join(sorted(set(rate_limited_apis)))
            print(f"\n{Colors.BRIGHT_YELLOW}✓ Rate limits encountered for {api_names}{Colors.RESET}")
            print(f"{Colors.DIM}  Tool automatically throttled and waited for reset(s). No data loss.{Colors.RESET}\n")

        # All data is local now — scoring is instant
        print(f"{Colors.BOLD}Processing vulnerabilities...{Colors.RESET}\n")

        report = generate_report(
            cvss_results, epss_results,
            cisa_kev_results, vulncheck_kev_results,
            github_results, msf_results,
            cve_ids,
        )

        print(f"{Colors.BOLD}Generating reports...{Colors.RESET}\n")
        
        # Write outputs
        write_json_report(args.output_json, report)
        write_csv_report(args.output_csv, report)
        
        # Print to console if requested
        if not args.no_table:
            print_table_report(report)
        
        # Print completion message
        if report:
            print(success(f"Analysis complete! {len(report)} CVE(s) prioritized"))
        
        return 0
    
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
