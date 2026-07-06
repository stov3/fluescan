#!/usr/bin/env python3
"""
Vulnerability Prioritization Tool - Main Entry Point

This tool combines CVSS scores, EPSS predictions, dual KEV signals (CISA +
VulnCheck), public PoCs, and Metasploit modules to provide comprehensive
vulnerability prioritization with exploit availability analysis.

Usage:
    python3 fluescan.py CVE-2024-1234 CVE-2024-5678
    python3 fluescan.py --cves-file cves.txt
    python3 fluescan.py CVE-2024-1234 --output-json report.json
    python3 fluescan.py --check-apis
    python3 fluescan.py --setup
"""

import argparse
import csv
import json
import re
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
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
    print_title, print_disclaimer_and_author, priority_color,
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


def extract_affected_component(cvss_data: Dict[str, Any]) -> str:
    """Extract a short affected vendor/product label from CVE data.

    Prefers NVD CPE criteria (configurations), falls back to the OSV summary
    when NVD data is missing. Returns "" when nothing usable exists.
    """
    if "error" in cvss_data and "configurations" not in cvss_data:
        return str(cvss_data.get("osv_summary", ""))[:80]

    products: List[str] = []
    seen = set()
    vendors = set()
    for config in cvss_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = str(match.get("criteria", ""))
                cpe_parts = criteria.split(":")
                # cpe:2.3:<part>:<vendor>:<product>:...
                if len(cpe_parts) >= 5:
                    vendor = cpe_parts[3].replace("_", " ").title()
                    product = cpe_parts[4].replace("_", " ").title()
                    vendors.add(vendor.lower())
                    label = product if vendor.lower() in product.lower() else f"{vendor} {product}"
                    key = label.lower()
                    if key not in seen:
                        seen.add(key)
                        products.append(label)

    # Widespread CVEs (many vendors, e.g. protocol-level flaws) are better
    # described by the NVD description than by an arbitrary CPE sample.
    if products and (len(vendors) <= 3 or len(products) <= 5):
        shown = ", ".join(products[:3])
        if len(products) > 3:
            shown += f" (+{len(products) - 3} more)"
        return shown

    # OSV fallback summary (short, human-readable)
    osv_summary = str(cvss_data.get("osv_summary", "")).strip()
    if osv_summary:
        return osv_summary[:80]

    # NVD description: first sentence names the affected component for
    # widespread CVEs and CVEs without CPE data.
    for desc in cvss_data.get("descriptions", []):
        if desc.get("lang") == "en":
            text = str(desc.get("value", "")).strip()
            if text:
                first = text.split(". ")[0]
                return (first[:77] + "...") if len(first) > 80 else first

    # Last resort: the CPE sample, even if multi-vendor.
    if products:
        return ", ".join(products[:3]) + f" (+{len(products) - 3} more)" if len(products) > 3 else ", ".join(products[:3])

    return ""


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


def calculate_priority_breakdown(
    cvss_score: float,
    epss_score: float,
    kev_strength: float,
    cisa_confirmed_kev: bool,
    attack_vector: str = "UNKNOWN",
    github_poc_found: bool = False,
    metasploit_found: bool = False,
    evidence_factor: float = 1.0,
) -> Dict[str, Any]:
    """Return deterministic, verbose score breakdown for explain mode."""
    cvss_norm = min(max(cvss_score / 10.0, 0.0), 1.0) if cvss_score > 0 else 0.0
    epss_norm = min(max(epss_score, 0.0), 1.0) if epss_score >= 0 else 0.0
    kev_norm = min(max(kev_strength, 0.0), 1.0)

    if metasploit_found:
        exploit_norm = 1.0
    elif github_poc_found:
        exploit_norm = 0.5
    else:
        exploit_norm = 0.0

    contrib_cvss = 0.30 * cvss_norm
    contrib_epss = 0.40 * epss_norm
    contrib_kev = 0.20 * kev_norm
    contrib_exploit = 0.10 * exploit_norm
    raw_score = contrib_cvss + contrib_epss + contrib_kev + contrib_exploit

    evidence_factor = min(max(evidence_factor, 0.0), 1.0)

    exposure_weight = attack_vector_exposure_weight(attack_vector)
    pre_floor_score = raw_score * 100.0 * evidence_factor * exposure_weight
    final_score = max(pre_floor_score, 85.0) if cisa_confirmed_kev else pre_floor_score
    final_score = min(max(final_score, 0.0), 100.0)

    return {
        "normalized": {
            "cvss_norm": round(cvss_norm, 4),
            "epss_norm": round(epss_norm, 4),
            "kev_norm": round(kev_norm, 4),
            "exploit_norm": round(exploit_norm, 4),
        },
        "weighted_contributions": {
            "cvss": round(contrib_cvss, 4),
            "epss": round(contrib_epss, 4),
            "kev": round(contrib_kev, 4),
            "exploit": round(contrib_exploit, 4),
        },
        "raw_score": round(raw_score, 4),
        "evidence_factor": round(evidence_factor, 4),
        "exposure_weight": round(exposure_weight, 4),
        "cisa_floor_applied": bool(cisa_confirmed_kev and pre_floor_score < 85.0),
        "pre_floor_score": round(pre_floor_score, 4),
        "final_score": round(final_score, 4),
    }


def calculate_confidence(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute evidence confidence (0-100) for a record's source signals.

    Confidence answers "how trustworthy is the evidence behind this ranking?".
    It feeds the score's evidence_factor (full trust at >= 85, smooth
    penalty below), so poorer data lowers the score gracefully. Weighted
    source quality (CVSS 28, EPSS 24, KEV 20, exploit intel 28) plus a small
    agreement adjustment when independent signals corroborate or conflict.
    """
    factors: List[str] = []

    # CVSS quality: NVD authoritative > OSV fallback > missing.
    if record.get("cvss_score", 0) > 0:
        if record.get("cvss_source") == "osv_fallback":
            cvss_q = 0.75
            factors.append("CVSS from OSV fallback (not NVD)")
        else:
            cvss_q = 0.92
    else:
        cvss_q = 0.30
        factors.append("CVSS missing")

    # EPSS quality: when present, confidence rises with percentile stability.
    epss_score = record.get("epss_score", -1)
    if epss_score >= 0:
        percentile = float(record.get("epss_percentile", -1))
        pct_norm = min(max(percentile, 0.0), 1.0) if percentile >= 0 else 0.5
        epss_q = 0.65 + (0.35 * pct_norm)
    elif "not found" in str(record.get("epss_error", "")).lower():
        epss_q = 0.45
        factors.append("Not in EPSS database (very new or rejected CVE)")
    else:
        epss_q = 0.25
        factors.append("EPSS lookup failed")

    # KEV quality: CISA confirmation is strongest, early-signal KEV is partial.
    if record.get("in_kev"):
        kev_q = 0.98
    elif record.get("in_vulncheck_kev"):
        kev_q = 0.88
    elif record.get("vulncheck_error"):
        kev_q = 0.65
        factors.append("VulnCheck KEV unavailable")
    else:
        kev_q = 0.78

    # Exploit intel quality: channel health + evidence quality gradient.
    failed_channels = bool(record.get("github_error")) + bool(record.get("metasploit_error"))
    if record.get("github_error"):
        factors.append("GitHub PoC search failed")
    if record.get("metasploit_error"):
        factors.append("Metasploit/ExploitDB check failed")

    exploit_q = (0.78, 0.55, 0.30)[failed_channels]
    if record.get("github_poc_found"):
        exploit_q += 0.08
    if record.get("metasploit_found"):
        reliability = str(record.get("metasploit_reliability") or "normal").lower()
        exploit_q += {
            "normal": 0.05,
            "good": 0.10,
            "great": 0.13,
            "excellent": 0.16,
        }.get(reliability, 0.05)
    exploit_q = min(exploit_q, 0.97)

    # Weighted source-quality blend (sums to 100).
    score = (28 * cvss_q) + (24 * epss_q) + (20 * kev_q) + (28 * exploit_q)

    # Agreement adjustment: corroboration slightly raises trust, strong conflict lowers it.
    corroborating = sum([
        bool(record.get("in_kev")),
        bool(record.get("in_vulncheck_kev")),
        record.get("epss_score", -1) >= 0.7,
        bool(record.get("metasploit_found")),
        bool(record.get("github_poc_found")),
    ])
    if corroborating >= 3:
        score += 4
        factors.append("Multiple independent sources corroborate exploitation")
    elif (record.get("cvss_score", 0) >= 9.0
          and 0 <= record.get("epss_score", -1) < 0.01
          and not record.get("in_kev")
          and not record.get("github_poc_found")):
        score -= 5
        factors.append("Signals conflict: critical CVSS but weak exploitation evidence")

    score = min(max(score, 0.0), 100.0)
    level = "HIGH" if score >= 85 else ("MEDIUM" if score >= 65 else "LOW")
    if factors:
        note = "; ".join(factors)
    elif level == "HIGH":
        note = "Strong source coverage and consistent exploitation signals"
    elif level == "MEDIUM":
        note = "Moderate source coverage; some indicators remain indirect"
    else:
        note = "Limited source coverage; manual validation recommended"

    return {
        "evidence_score": round(score, 1),
        "evidence_level": level,
        "evidence_note": note,
        "evidence_factors": factors,
    }


def build_explanation(cve: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """Build one concise deterministic paragraph explaining the score."""
    br = cve.get("score_breakdown", {})
    score = float(cve.get("priority_score", 0))
    kev = str(cve.get("kev_status", "NO")).upper()
    epss = cve.get("epss_score", -1)
    epss = float(epss) if isinstance(epss, (int, float)) else -1.0
    cvss = float(cve.get("cvss_score", 0) or 0)
    severity = str(cve.get("cvss_severity", "UNKNOWN")).capitalize()

    # Lead clause: what drives the score.
    drivers: List[str] = []
    if kev == "YES":
        drivers.append("confirmed active exploitation (CISA KEV)")
    elif kev == "EARLY":
        drivers.append("early exploitation reports (VulnCheck KEV)")
    if epss >= 0.2:
        drivers.append(f"a {epss:.0%} EPSS exploitation probability")
    if cve.get("metasploit_found"):
        rel = cve.get("metasploit_reliability") or "normal"
        drivers.append(f"a weaponized Metasploit module ({rel} reliability)")
    elif cve.get("github_poc_found"):
        drivers.append("public PoC code on GitHub")
    if cvss >= 9.0:
        drivers.append(f"critical CVSS {cvss:.1f}")

    if drivers:
        driver_txt = drivers[0] if len(drivers) == 1 else ", ".join(drivers[:-1]) + " and " + drivers[-1]
        parts = [f"Priority {score:.1f} driven by {driver_txt}."]
    elif cvss > 0 and epss >= 0:
        parts = [
            f"Priority {score:.1f} from base severity alone ({severity} CVSS {cvss:.1f}, "
            f"EPSS {epss:.0%}) with no exploitation evidence in KEV, Metasploit, or GitHub."
        ]
    else:
        parts = [f"Priority {score:.1f} on minimal signal: no exploitation evidence in KEV, Metasploit, or GitHub."]

    # Exposure clause: only when the attack vector is known.
    av = str(cve.get("attack_vector", "UNKNOWN")).upper()
    expw = float(cve.get("exposure_weight", 1.0))
    av_phrases = {
        "N": "Network-reachable (AV:N) raises exposure",
        "A": "Adjacent-network access (AV:A) slightly raises exposure",
        "L": "Local access required (AV:L) lowers exposure",
        "P": "Physical access required (AV:P) lowers exposure",
    }
    if av in av_phrases:
        parts.append(f"{av_phrases[av]} (x{expw:.2f}).")

    if br.get("cisa_floor_applied"):
        parts.append("Raised to the 85-point floor reserved for CISA-confirmed exploitation.")

    # Evidence clause: only when weaker evidence actually dampened the score.
    ev_factor = float(br.get("evidence_factor", 1.0))
    if ev_factor < 0.995:
        factors = evidence.get("evidence_factors") or []
        reason_txt = f" ({'; '.join(factors[:2])})" if factors else ""
        suffix = " — verify manually." if str(evidence.get("evidence_level")) == "LOW" else "."
        parts.append(f"Score dampened x{ev_factor:.2f} by weaker evidence{reason_txt}{suffix}")

    return " ".join(parts)


def print_explanations(report: List[Dict[str, Any]]) -> None:
    """Print deterministic verbose explanation for each CVE."""
    if not report:
        return

    def kev_color(status: str) -> str:
        if status == "YES":
            return Colors.GREEN
        if status == "EARLY":
            return Colors.BRIGHT_YELLOW
        return Colors.WHITE

    print(header("Score Explanations"))
    for cve in report:
        cve_id = str(cve.get("cve_id", "N/A"))
        score = float(cve.get("priority_score", 0))
        kev_status = str(cve.get("kev_status", "NO")).upper()
        av = str(cve.get("attack_vector", "UNKNOWN")).upper()
        epss = cve.get("epss_score", -1)
        epss_txt = f"{float(epss):.2f}" if isinstance(epss, (float, int)) and float(epss) >= 0 else "N/A"
        print(f"{Colors.DARK_SMOKE}{'-' * 78}{Colors.RESET}")
        print(
            f"{Colors.BOLD}{cve_id}{Colors.RESET}  "
            f"score={priority_color(score)}{score:.2f}{Colors.RESET}  "
            f"KEV={kev_color(kev_status)}{kev_status}{Colors.RESET}  "
            f"EPSS={Colors.BRIGHT_WHITE}{epss_txt}{Colors.RESET}  "
            f"AV={Colors.BRIGHT_WHITE}{av}{Colors.RESET}"
        )
        component = str(cve.get("affected_component", "")).strip()
        if component:
            print(f"{Colors.BRIGHT_ORANGE}affected{Colors.RESET}: {Colors.BRIGHT_WHITE}{component}{Colors.RESET}")
        for line in textwrap.wrap(str(cve.get("explain_summary", "")), width=78):
            print(f"{Colors.SMOKE}{line}{Colors.RESET}")
    print(f"{Colors.DARK_SMOKE}{'-' * 78}{Colors.RESET}")
    print()


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
        affected_component = extract_affected_component(cvss_data)
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
        
        # Build record with source signals first; evidence confidence must be
        # known before scoring because it drives the evidence factor.
        record = {
            "cve_id": cve_upper,
            "priority_score": 0.0,  # set after data-quality-aware scoring below
            "affected_component": affected_component,
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
            "score_breakdown": {},  # set after evidence-aware scoring below
            "explain_summary": "",  # set below using finalized record values
            "cvss_source": cvss_data.get("source", "nvd"),
            "cvss_error": cvss_data.get("error"),
            "epss_error": epss_data.get("error"),
            "vulncheck_error": vulncheck_kev_results.get("error"),
            "github_error": github_data.get("error"),
            "metasploit_error": msf_data.get("error"),
        }
        evidence = calculate_confidence(record)
        
        # Less/weaker evidence lowers the score: full trust at >= 85,
        # then a smooth proportional penalty (e.g. 57 -> x0.67).
        evidence_factor = min(1.0, float(evidence["evidence_score"]) / 85.0)
        breakdown = calculate_priority_breakdown(
            cvss_score,
            epss_score,
            kev_strength,
            in_cisa_kev,
            attack_vector,
            github_data.get("found", False),
            msf_data.get("found", False),
            evidence_factor,
        )
        record["priority_score"] = round(breakdown["final_score"], 2)
        record["score_breakdown"] = breakdown
        record["explain_summary"] = build_explanation(record, evidence)
        
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
        "cve_id", "priority_score", "affected_component", "cvss_score", "cvss_severity", "attack_vector", "exposure_weight",
        "epss_score", "epss_percentile", "epss_prev_7d", "epss_delta_7d",
        "in_kev", "in_vulncheck_kev", "kev_status", "kev_signal_strength",
        "github_poc_found", "github_poc_count",
        "metasploit_found", "metasploit_reliability",
        "exploit_multiplier", "explain_summary", "cvss_source",
        "cvss_error", "epss_error", "vulncheck_error", "github_error", "metasploit_error"
    ]
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
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
  python3 fluescan.py CVE-2024-1234 CVE-2024-5678
  
  # With CVE list from file
  python3 fluescan.py --cves-file cves.txt
  
  # With custom output paths
  python3 fluescan.py CVE-2024-1234 --output-json report.json --output-csv report.csv
  
  # Suppress console table
  python3 fluescan.py --cves-file cves.txt --no-table

    # Verbose deterministic score explanations
    python3 fluescan.py --cves-file cves.txt --explain
  
  # Set up API keys
  python3 fluescan.py --setup
        """
    )
    
    parser.add_argument("cves", nargs="*", help="CVE IDs to analyze")
    parser.add_argument("--cves-file", help="File containing CVE IDs (one per line)")
    parser.add_argument("--output-json", default="fluescan_report.json", help="JSON output file")
    parser.add_argument("--output-csv", default="fluescan_report.csv", help="CSV output file")
    parser.add_argument("--no-table", action="store_true", help="Don't print table report to console")
    parser.add_argument("--explain", action="store_true", help="Print deterministic verbose score explanations")
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
        
        # Fetch all independent sources in parallel batches. EPSS/KEV are
        # single batched downloads; per-CVE fetchers (NVD, GitHub, Metasploit)
        # each keep their own rate limiter and local cache, so running the
        # stages concurrently is safe and removes sequential dead time.
        print("Fetching Data...")
        with ThreadPoolExecutor(max_workers=6) as pool:
            cvss_future = pool.submit(fetch_cvss_for_cves, cve_ids, nvd_api_key)
            epss_future = pool.submit(fetch_epss_for_cves, cve_ids)
            cisa_future = pool.submit(fetch_kev_data)
            vulncheck_future = pool.submit(fetch_vulncheck_kev_data)
            github_future = pool.submit(fetch_github_pocs, cve_ids)
            msf_future = pool.submit(fetch_metasploit_info, cve_ids)

            cvss_results = cvss_future.result()
            epss_results = epss_future.result()
            cisa_kev_results = filter_kev_by_cves(cisa_future.result(), cve_ids)
            vulncheck_kev_results = filter_vulncheck_kev_by_cves(vulncheck_future.result(), cve_ids)
            github_results = github_future.result()
            msf_results = msf_future.result()

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

        if args.explain:
            print_explanations(report)
        
        # Print completion message
        if report:
            print(success(f"Analysis complete! {len(report)} CVE(s) prioritized"))
        
        return 0
    
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
