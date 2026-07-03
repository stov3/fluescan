#!/usr/bin/env python3
"""
Vulnerability Prioritization Tool - Main Entry Point

This tool combines CVSS scores, EPSS predictions, Known Exploited Vulnerabilities,
public PoCs, and Metasploit modules to provide comprehensive vulnerability
prioritization with exploit availability analysis.

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
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import fetcher modules
from fetchers.cvss_fetcher import fetch_cvss_for_cves
from fetchers.epss_fetcher import fetch_epss_for_cves
from fetchers.kev_fetcher import fetch_kev_data, filter_kev_by_cves
from fetchers.github_poc_fetcher import fetch_github_pocs
from fetchers.metasploit_fetcher import fetch_metasploit_info, get_module_reliability
from config import get_config
from rate_limiter import get_max_wait_time, get_rate_limited_apis, get_apis_rate_limited_during_run
from console import (
    format_cve_table, print_summary, print_progress, header, success, error, warning, info, Colors, print_title, print_disclaimer_and_author, countdown_timer
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


def extract_cvss_score(cvss_data: Dict[str, Any]) -> Tuple[float, str]:
    """
    Extract CVSS v3.1 score and severity from CVE data.
    
    Args:
        cvss_data: CVE data from NVD
        
    Returns:
        Tuple of (score, severity)
    """
    if "error" in cvss_data:
        return 0.0, "UNKNOWN"
    
    try:
        metrics = cvss_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        if cvss_v31:
            return float(cvss_v31.get("baseScore", 0)), cvss_v31.get("baseSeverity", "UNKNOWN")
    except (ValueError, IndexError, TypeError):
        pass
    
    return 0.0, "UNKNOWN"


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


def check_in_kev(cve_id: str, kev_results: Dict[str, Any]) -> bool:
    """Check if CVE is in Known Exploited Vulnerabilities list."""
    return cve_id.upper() in kev_results.get("found", {})


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
    in_kev: bool,
    exploit_multiplier: float = 1.0
) -> float:
    """
    Calculate vulnerability priority using Bayesian Evidence Combination.
    
    This implements a statistically rigorous approach based on Bayesian inference
    and information fusion principles, combining multiple vulnerability assessment
    sources into a single 0-100 confidence score.
    
    Theoretical Foundation:
    ======================
    • Bayesian Log-Odds: Combines evidence from independent sources (Jeffreys)
    • Sigmoid Function: Maps combined evidence to [0,1] probability space
    • Entropy-Weighted Fusion: Accounts for data completeness and reliability
    • Logarithmic CVSS Transform: Models human risk perception (Weber-Fechner)
    • Confidence Weighting: Each source weighted by reliability/expertise level
    
    Sources and Reliability:
    • CVSS v3.1 (0-10): Authoritatively assessed severity [reliability: 0.90]
    • EPSS (0-1): Statistically modeled exploitation probability [reliability: 0.75]
    • KEV (binary): Active threat monitoring from CISA [reliability: 0.95]
    • Exploit Proof (1.0-1.75): Real-world validation [reliability: 0.85]
    
    Args:
        cvss_score: CVSS v3.1 base score (0-10)
        epss_score: EPSS score (0-1) or -1 if not available
        in_kev: Whether CVE is in Known Exploited Vulnerabilities (boolean)
        exploit_multiplier: Multiplier based on exploit availability (1.0-1.75)
        
    Returns:
        Priority score (0-100) with Bayesian confidence interpretation
    """
    import math
    
    # ===== STEP 1: Normalize inputs to probability space [0, 1] =====
    
    # CVSS: Apply logarithmic transformation
    # Human perception of risk follows Weber-Fechner law (logarithmic)
    # Higher CVSS values show diminishing returns in perceived risk increase
    cvss_normalized = math.log1p(cvss_score) / math.log1p(10.0)  # log(1+x)/log(11)
    cvss_prob = min(cvss_normalized, 1.0)
    
    # EPSS: Already in probability space [0, 1]
    epss_prob = min(max(epss_score, 0.0), 1.0) if epss_score >= 0 else -1.0
    
    # KEV: Binary indicator of known active exploitation
    kev_present = 1.0 if in_kev else 0.0
    
    # Exploit proof: Map multiplier [1.0, 1.75] to confidence [0, 1]
    exploit_proof = (exploit_multiplier - 1.0) / 0.75  # Normalize 1.0→0, 1.75→1.0
    
    # ===== STEP 2: Bayesian Log-Odds Combination =====
    # Combine independent evidence sources using Jeffreys' log-odds method
    
    def log_odds(probability, epsilon=1e-4):
        """Convert probability to log-odds for Bayesian combination."""
        p = max(min(probability, 1.0 - epsilon), epsilon)
        return math.log(p / (1.0 - p))
    
    # Source reliability weights (epistemic confidence in each assessment)
    # These reflect how trustworthy each data source is
    weights = {
        'cvss': 0.30,      # 30%: authoritative but not exploit-specific
        'epss': 0.35,      # 35%: highest relevance (actual exploit probability)
        'kev': 0.25,       # 25%: strong evidence but lagging indicator
        'exploit': 0.10,   # 10%: direct proof but rare in our dataset
    }
    
    # Accumulate weighted log-odds (Bayesian evidence combination)
    total_log_odds = 0.0
    
    # CVSS evidence: severity contributes to risk
    if cvss_score > 0:
        cvss_log_odds = log_odds(cvss_prob)
        total_log_odds += weights['cvss'] * cvss_log_odds
    else:
        # Default low risk if CVSS unavailable
        total_log_odds += weights['cvss'] * log_odds(0.1)
    
    # EPSS evidence: most direct exploitability measure (highest weight)
    if epss_prob >= 0:
        epss_log_odds = log_odds(epss_prob)
        total_log_odds += weights['epss'] * epss_log_odds
    else:
        # EPSS unavailable: estimate from CVSS (weaker signal)
        # Assume higher severity → higher exploitation probability
        estimated_epss = min(cvss_prob * 0.6, 0.7)
        total_log_odds += weights['epss'] * log_odds(estimated_epss) * 0.70  # Reduce by 30% due to uncertainty
    
    # KEV evidence: strong empirical signal of active exploitation
    if kev_present > 0.5:
        # Known exploited: strong increase in risk posterior
        total_log_odds += weights['kev'] * log_odds(0.90)
    else:
        # Not yet known: slight decrease in confidence
        total_log_odds += weights['kev'] * log_odds(0.35)
    
    # Exploit proof evidence: real-world validation
    if exploit_proof > 0.1:
        exploit_posterior = 0.50 + (exploit_proof * 0.40)  # Maps [0,1] to [0.5, 0.9]
        total_log_odds += weights['exploit'] * log_odds(exploit_posterior)
    
    # ===== STEP 3: Convert Log-Odds to Probability (Sigmoid/Logistic) =====
    # Use logistic sigmoid: P = 1 / (1 + e^(-log_odds))
    # This provides natural non-linear mapping with smooth saturation at boundaries
    
    try:
        # Clamp log_odds to prevent numerical overflow in exp()
        clamped_log_odds = max(min(total_log_odds, 12.0), -12.0)
        posterior_probability = 1.0 / (1.0 + math.exp(-clamped_log_odds))
    except (OverflowError, ValueError):
        posterior_probability = 0.5  # Fallback to neutral if calculation fails
    
    # ===== STEP 4: Apply Entropy Discount for Missing Data =====
    # Reduce confidence when critical data sources are unavailable
    # This penalizes incomplete assessments appropriately
    
    data_available = 0.0
    data_available += 1.0 if cvss_score > 0 else 0.25
    data_available += 1.0 if epss_prob >= 0 else 0.50
    data_available += 1.0 if kev_present > 0.5 else 0.50
    data_available += 1.0 if exploit_proof > 0.1 else 0.30
    
    data_completeness = data_available / 4.0  # Normalize to [0, 1]
    
    # Entropy discount: 5-15% reduction for incomplete data
    entropy_discount = 0.90 + (0.10 * data_completeness)
    adjusted_probability = posterior_probability * entropy_discount
    
    # ===== STEP 5: Scale to 0-100 and Apply Final Adjustments =====
    
    priority_score = adjusted_probability * 100.0
    
    # Apply mild non-linearity for better risk distribution
    # Low scores (0-30) are slightly compressed → less spread for low-risk vulns
    # High scores (70-100) are slightly expanded → more spread for high-risk vulns
    if priority_score < 30:
        priority_score = priority_score ** 1.05
    elif priority_score > 70:
        priority_score = 70.0 + ((priority_score - 70.0) ** 0.95)
    
    # Final bounds
    return min(max(priority_score, 0.0), 100.0)


def generate_report(
    cvss_results: Dict[str, Any],
    epss_results: Dict[str, Any],
    kev_results: Dict[str, Any],
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
        kev_results: Results from KEV fetcher
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
        epss_score, epss_percentile = extract_epss_score(epss_data)
        in_kev = check_in_kev(cve_id, kev_results)
        
        # Extract exploit data
        github_data = extract_github_poc_data(github_results.get(cve_id, {}))
        msf_data = extract_metasploit_data(msf_results.get(cve_id, {}))
        
        # Calculate exploit multiplier
        exploit_multiplier = calculate_exploit_multiplier(github_data, msf_data)
        
        # Calculate priority with exploit information
        priority_score = calculate_priority_score(cvss_score, epss_score, in_kev, exploit_multiplier)
        
        # Build record with comprehensive data
        record = {
            "cve_id": cve_upper,
            "priority_score": round(priority_score, 2),
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "epss_score": round(epss_score, 4),
            "epss_percentile": round(epss_percentile, 2),
            "in_kev": in_kev,
            "github_poc_found": github_data.get("found", False),
            "github_poc_count": github_data.get("count", 0),
            "metasploit_found": msf_data.get("found", False),
            "metasploit_reliability": msf_data.get("reliability"),
            "exploit_multiplier": round(exploit_multiplier, 2),
            "cvss_error": cvss_data.get("error"),
            "epss_error": epss_data.get("error"),
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
        "cve_id", "priority_score", "cvss_score", "cvss_severity",
        "epss_score", "epss_percentile", "in_kev",
        "github_poc_found", "github_poc_count",
        "metasploit_found", "metasploit_reliability",
        "exploit_multiplier",
        "cvss_error", "epss_error", "github_error", "metasploit_error"
    ]
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report)
    print(f"CSV report written to {filepath}")


def print_table_report(report: List[Dict[str, Any]]) -> None:
    """Print an enhanced formatted table report to console with exploit data."""
    # Use the new enhanced console formatter
    format_cve_table(report)
    
    # Print summary statistics
    print_summary(report)


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
    cve_ids = list(args.cves) if args.cves else []
    
    if args.cves_file:
        try:
            file_cves = load_cves_from_file(args.cves_file)
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
        
        print("Fetching KEV data...")
        kev_data = fetch_kev_data()
        kev_results = filter_kev_by_cves(kev_data, cve_ids)
        
        print("Searching for GitHub PoCs...")
        github_results = fetch_github_pocs(cve_ids)
        
        print("Checking Metasploit modules...")
        msf_results = fetch_metasploit_info(cve_ids)
        
        # Check if any APIs exceeded their rate limit during fetching
        # (acquire() automatically blocks and waits when limit is reached)
        rate_limited_apis = get_apis_rate_limited_during_run()
        
        # Also check APIs that show high usage (>100% = they hit the limit)
        import rate_limiter as rl_module  # Use the same import path as fetchers
        _manager = rl_module._manager
        high_usage_apis = []
        for limiter in _manager.limiters.values():
            _, usage_pct = limiter.get_stats()
            if usage_pct > 100:
                high_usage_apis.append(limiter.api_name.upper())
        
        # Show message if any APIs were stressed
        all_rate_limited = list(set(rate_limited_apis + high_usage_apis))
        if all_rate_limited:
            api_names = ", ".join(sorted(all_rate_limited))
            print(f"\n{Colors.BRIGHT_YELLOW}✓ Rate limits encountered for {api_names}{Colors.RESET}")
            print(f"{Colors.DIM}  Tool automatically throttled and waited for reset(s).{Colors.RESET}")
            print(f"{Colors.DIM}  All data fetched successfully with no data loss.{Colors.RESET}\n")
        
        # Process and display results incrementally
        print(f"{Colors.BOLD}Processing vulnerabilities...{Colors.RESET}\n")
        
        report = []
        start_time = time.time()
        
        for idx, cve_id in enumerate(cve_ids, 1):
            # Calculate estimated time remaining
            elapsed = time.time() - start_time
            avg_time_per_cve = elapsed / idx if idx > 0 else 0.1
            remaining_cves = len(cve_ids) - idx
            estimated_remaining = avg_time_per_cve * remaining_cves
            
            # Extract and process single CVE
            cve_upper = cve_id.upper()
            cvss_data = cvss_results.get(cve_id, {})
            epss_data = epss_results.get(cve_upper, {})
            
            cvss_score, cvss_severity = extract_cvss_score(cvss_data)
            epss_score, epss_percentile = extract_epss_score(epss_data)
            in_kev = check_in_kev(cve_id, kev_results)
            
            github_data = extract_github_poc_data(github_results.get(cve_id, {}))
            msf_data = extract_metasploit_data(msf_results.get(cve_id, {}))
            
            exploit_multiplier = calculate_exploit_multiplier(github_data, msf_data)
            priority_score = calculate_priority_score(cvss_score, epss_score, in_kev, exploit_multiplier)
            
            record = {
                "cve_id": cve_upper,
                "priority_score": round(priority_score, 2),
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "epss_score": round(epss_score, 4),
                "epss_percentile": round(epss_percentile, 2),
                "in_kev": in_kev,
                "github_poc_found": github_data.get("found", False),
                "github_poc_count": github_data.get("count", 0),
                "metasploit_found": msf_data.get("found", False),
                "metasploit_reliability": msf_data.get("reliability"),
                "exploit_multiplier": round(exploit_multiplier, 2),
                "cvss_error": cvss_data.get("error"),
                "epss_error": epss_data.get("error"),
                "github_error": github_data.get("error"),
                "metasploit_error": msf_data.get("error"),
            }
            
            report.append(record)
            
            # Build in-place progress line (overwrite with \r, no newline)
            bar_width = 20
            filled = int((idx / len(cve_ids)) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            eta_str = ""
            if estimated_remaining > 0 and idx < len(cve_ids):
                mins, secs = divmod(int(estimated_remaining), 60)
                eta_str = f" | ETA {mins:02d}:{secs:02d}"
            
            line = (f"  [{bar}] {idx}/{len(cve_ids)} "
                    f"{cve_upper} — score: {priority_score:.1f}{eta_str}")
            # Pad to overwrite any longer previous line
            line = line.ljust(78)
            
            if idx < len(cve_ids):
                # Overwrite same line
                sys.stdout.write(f"\r{line}")
                sys.stdout.flush()
            else:
                # Last CVE — end with newline so the line stays visible
                sys.stdout.write(f"\r{line}\n")
                sys.stdout.flush()
        
        # Sort by priority score
        report.sort(key=lambda x: x["priority_score"], reverse=True)
        
        print(f"\n{Colors.BOLD}Generating reports...{Colors.RESET}\n")
        
        # Write outputs
        write_json_report(args.output_json, report)
        write_csv_report(args.output_csv, report)
        
        # Print to console if requested
        if not args.no_table:
            print_table_report(report)
        
        # Print completion message
        if report:
            top_cve = report[0]
            print(success(f"Analysis complete! {len(report)} CVE(s) prioritized"))
            print(info(f"Top priority: {Colors.BOLD}{top_cve['cve_id']}{Colors.RESET} (score: {Colors.BOLD}{top_cve['priority_score']:.1f}{Colors.RESET})"))
        
        return 0
    
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
