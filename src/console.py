#!/usr/bin/env python3
"""
Enhanced Console UI with colors, formatting, and interactive menus.
Uses ANSI color codes (no external dependencies for core functionality).
"""

import sys
from typing import List, Dict, Any

try:
    from pyfiglet import Figlet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False

# ANSI Color codes
class Colors:
    # Foreground
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    
    # Formatting
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'
    STRIKETHROUGH = '\033[9m'
    
    # Reset
    RESET = '\033[0m'
    END = '\033[0m'


def severity_color(severity: str) -> str:
    """Return color code based on severity level."""
    severity_upper = severity.upper() if severity else ""
    if severity_upper == "CRITICAL":
        return Colors.BRIGHT_MAGENTA
    elif severity_upper == "HIGH":
        return Colors.RED
    elif severity_upper == "MEDIUM":
        return Colors.BRIGHT_YELLOW
    elif severity_upper == "LOW":
        return Colors.YELLOW
    else:
        return Colors.WHITE


def priority_color(score: float) -> str:
    """Return color based on priority score."""
    if score >= 80:
        return Colors.BRIGHT_MAGENTA
    elif score >= 60:
        return Colors.RED
    elif score >= 40:
        return Colors.BRIGHT_YELLOW
    elif score >= 20:
        return Colors.YELLOW
    else:
        return Colors.GREEN


def print_title() -> None:
    """Display title banner for the application."""
    if HAS_PYFIGLET:
        try:
            fig = Figlet(font='slant', width=100)
            title_text = fig.renderText('fluescan')
            print(f"{Colors.BRIGHT_CYAN}{title_text}{Colors.RESET}")
        except:
            # Fallback if pyfiglet fails
            print_title_fallback()
    else:
        print_title_fallback()
    print()


def print_title_fallback() -> None:
    """Fallback title if pyfiglet unavailable."""
    print(f"{Colors.BRIGHT_CYAN}fluescan{Colors.RESET}\n")


def print_disclaimer_and_author() -> None:
    """Display disclaimer and author information."""
    disclaimer = f"""
{Colors.BRIGHT_YELLOW}⚠ DISCLAIMER{Colors.RESET}
{Colors.DIM}This tool provides vulnerability prioritization guidance based on multiple data
sources (CVSS, EPSS, KEV, PoCs, Metasploit). While efforts are made to
ensure accuracy, the results should be verified independently. This tool is
provided AS-IS without warranty. Always perform thorough security assessments
before making remediation decisions.{Colors.RESET}

{Colors.BRIGHT_GREEN}📖 OPEN SOURCE{Colors.RESET}
{Colors.DIM}This project is open-source and community-driven. Contributions, bug reports,
and feature requests are welcome! Visit the GitHub repository for more information.{Colors.RESET}

{Colors.BRIGHT_CYAN}👤 Author{Colors.RESET}
{Colors.DIM}Created by: {Colors.BRIGHT_CYAN}https://github.com/stov3{Colors.RESET}
{Colors.DIM}Repository:  {Colors.BRIGHT_CYAN}https://github.com/stov3/fluescan{Colors.RESET}
"""
    print(disclaimer)


def header(text: str) -> str:
    """Format header text."""
    return f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.RESET}"


def subheader(text: str) -> str:
    """Format subheader text."""
    return f"{Colors.BRIGHT_CYAN}{text}{Colors.RESET}"


def success(text: str) -> str:
    """Format success message."""
    return f"{Colors.BRIGHT_GREEN}✓ {text}{Colors.RESET}"


def error(text: str) -> str:
    """Format error message."""
    return f"{Colors.BRIGHT_RED}✗ {text}{Colors.RESET}"


def warning(text: str) -> str:
    """Format warning message."""
    return f"{Colors.BRIGHT_YELLOW}⚠ {text}{Colors.RESET}"


def info(text: str) -> str:
    """Format info message."""
    return f"{Colors.BRIGHT_BLUE}ℹ {text}{Colors.RESET}"


def print_box(title: str, content: str = "", width: int = 80) -> None:
    """Print a formatted box with title and content."""
    print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title.center(width)}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
    if content:
        print(content)
    print()


def print_table_header(columns: List[str], widths: List[int]) -> None:
    """Print a colored table header."""
    header_row = ""
    for col, width in zip(columns, widths):
        header_row += f"{Colors.BOLD}{col.ljust(width)}{Colors.RESET}  "
    
    print(f"{Colors.CYAN}{'=' * sum(widths)}{Colors.RESET}")
    print(header_row)
    print(f"{Colors.CYAN}{'=' * sum(widths)}{Colors.RESET}")


def print_table_row(values: List[Any], widths: List[int], colors_list: List[str] = None) -> None:
    """Print a table row with optional colors."""
    row = ""
    for i, (val, width) in enumerate(zip(values, widths)):
        color = colors_list[i] if colors_list and i < len(colors_list) else Colors.WHITE
        row += f"{color}{str(val).ljust(width)}{Colors.RESET}  "
    print(row)


def print_table_footer(width: int) -> None:
    """Print table footer."""
    print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}\n")


def print_menu(title: str, options: List[tuple]) -> int:
    """
    Print an interactive menu and return user's choice.
    
    Args:
        title: Menu title
        options: List of (number, description) tuples
    
    Returns:
        Selected option number
    """
    print_box(title)
    
    for num, desc in options:
        print(f"  {Colors.BOLD}{num}{Colors.RESET}. {desc}")
    
    print()
    while True:
        try:
            choice = input(f"{Colors.BOLD}Select option (1-{len(options)}): {Colors.RESET}").strip()
            choice_num = int(choice)
            if 1 <= choice_num <= len(options):
                return choice_num
            print(error(f"Please enter a number between 1 and {len(options)}"))
        except ValueError:
            print(error("Please enter a valid number"))


def format_cve_table(cves: List[Dict[str, Any]]) -> None:
    """
    Format and print CVE results in an enhanced table.
    
    Args:
        cves: List of CVE dictionaries
    """
    if not cves:
        print(warning("No CVEs to display"))
        return
    
    # Sort by priority score (descending)
    cves_sorted = sorted(cves, key=lambda x: x.get('priority_score', 0), reverse=True)
    
    # Column definitions - adjusted widths for readability
    columns = ["Rank", "CVE ID", "Priority", "CVSS", "Severity", "EPSS", "AV", "ExpW", "KEV", "PoC", "Multiplier"]
    widths = [5, 17, 10, 7, 12, 8, 3, 6, 5, 5, 12]
    
    print_box(f"Vulnerability Remediation Priority ({len(cves_sorted)} CVEs)")
    print_table_header(columns, widths)
    
    for rank, cve in enumerate(cves_sorted, 1):
        cve_id = cve.get('cve_id', 'N/A')[:16]
        priority = cve.get('priority_score', 0)
        cvss = cve.get('cvss_score', 0)
        severity = cve.get('cvss_severity', 'UNKNOWN')[:11]
        epss = cve.get('epss_score', -1)
        kev = str(cve.get('kev_status', '')).upper()
        if kev not in {"YES", "EARLY", "NO"}:
            if cve.get('in_kev'):
                kev = "YES"
            elif cve.get('in_vulncheck_kev'):
                kev = "EARLY"
            else:
                kev = "NO"
        attack_vector = str(cve.get('attack_vector', 'UNKNOWN')).upper()
        av = attack_vector if attack_vector in {"N", "A", "L", "P"} else "?"
        exposure_weight = cve.get('exposure_weight', 1.0)
        poc = "YES" if cve.get('github_poc_found') else "NO"
        multiplier = cve.get('exploit_multiplier', 1.0)
        
        # Format EPSS value
        epss_str = f"{epss:.2f}" if epss >= 0 else "N/A"
        exp_weight_str = f"{float(exposure_weight):.2f}x"
        multiplier_str = f"{multiplier:.2f}x"
        
        # Apply colors
        colors = [
            priority_color(priority),  # Rank - colored by priority
            Colors.BRIGHT_CYAN,  # CVE ID
            priority_color(priority),  # Priority
            Colors.WHITE,  # CVSS
            severity_color(severity),  # Severity
            Colors.WHITE,  # EPSS
            Colors.BRIGHT_MAGENTA if av == "N" else (Colors.BRIGHT_BLUE if av == "A" else (Colors.BRIGHT_YELLOW if av == "L" else (Colors.GREEN if av == "P" else Colors.WHITE))),  # AV
            Colors.BRIGHT_MAGENTA if float(exposure_weight) > 1.0 else (Colors.GREEN if float(exposure_weight) < 1.0 else Colors.WHITE),  # ExpW
            Colors.GREEN if kev == "YES" else (Colors.BRIGHT_YELLOW if kev == "EARLY" else Colors.WHITE),  # KEV
            Colors.BRIGHT_GREEN if poc == "YES" else Colors.WHITE,  # PoC
            priority_color(priority),  # Multiplier
        ]
        
        values = [rank, cve_id, f"{priority:.1f}", f"{cvss:.1f}", severity, epss_str, av, exp_weight_str, kev, poc, multiplier_str]
        print_table_row(values, widths, colors)
    
    print_table_footer(sum(widths) + (len(widths) - 1) * 2)


def print_summary(cves: List[Dict[str, Any]]) -> None:
    """Print summary statistics of CVE analysis."""
    if not cves:
        return
    
    scores = [cve.get('priority_score', 0) for cve in cves]
    avg_score = sum(scores) / len(scores) if scores else 0
    max_score = max(scores) if scores else 0
    min_score = min(scores) if scores else 0
    
    critical_count = sum(1 for cve in cves if cve.get('cvss_severity', '').upper() == 'CRITICAL')
    high_count = sum(1 for cve in cves if cve.get('cvss_severity', '').upper() == 'HIGH')
    poc_count = sum(1 for cve in cves if cve.get('github_poc_found'))
    kev_count = sum(1 for cve in cves if cve.get('in_kev'))
    early_kev_count = sum(1 for cve in cves if (not cve.get('in_kev')) and cve.get('in_vulncheck_kev'))
    
    print_box("Analysis Summary")
    print(f"  Total CVEs:          {Colors.BOLD}{len(cves)}{Colors.RESET}")
    print(f"  Average Priority:    {Colors.BOLD}{avg_score:.1f}{Colors.RESET}")
    print(f"  Priority Range:      {Colors.BOLD}{min_score:.1f}{Colors.RESET} - {Colors.BOLD}{max_score:.1f}{Colors.RESET}")
    print()
    print(f"  Critical Severity:   {Colors.BRIGHT_RED}{critical_count}{Colors.RESET}")
    print(f"  High Severity:       {Colors.RED}{high_count}{Colors.RESET}")
    print(f"  Public PoCs:         {Colors.BRIGHT_GREEN}{poc_count}{Colors.RESET}")
    print(f"  Known Exploited:     {Colors.BRIGHT_YELLOW}{kev_count}{Colors.RESET}")
    print(f"  Early KEV Signals:   {Colors.BRIGHT_YELLOW}{early_kev_count}{Colors.RESET}")
    print()


def interactive_menu() -> tuple:
    """
    Display interactive menu and return user's choice.
    
    Returns:
        Tuple of (cves, output_json, output_csv, cves_file, no_table)
    """
    print_box("Welcome to fluescan", "Vulnerability Prioritization Tool")
    
    options = [
        (1, "Analyze specific CVE IDs"),
        (2, "Analyze CVEs from file"),
        (3, "Check API connectivity"),
        (4, "Configure API keys"),
        (5, "Exit"),
    ]
    
    choice = print_menu("Main Menu", options)
    
    cves = []
    cves_file = None
    output_json = None
    output_csv = None
    no_table = False
    
    if choice == 1:
        print("\nEnter CVE IDs (comma-separated, e.g., CVE-2024-1234,CVE-2024-5678):")
        print(f"{Colors.DIM}Leave blank and press Enter to go back to menu{Colors.RESET}")
        cves_input = input(f"{Colors.BOLD}CVE IDs: {Colors.RESET}").strip()
        
        if cves_input:
            cves = [cve.strip().upper() for cve in cves_input.split(',') if cve.strip()]
        else:
            return interactive_menu()  # Return to menu
    
    elif choice == 2:
        print(f"\nEnter path to CVE file (one CVE per line):")
        print(f"{Colors.DIM}Leave blank and press Enter to go back to menu{Colors.RESET}")
        cves_file = input(f"{Colors.BOLD}File path: {Colors.RESET}").strip()
        
        if not cves_file:
            return interactive_menu()  # Return to menu
        
        try:
            with open(cves_file, 'r') as f:
                cves = [line.strip().upper() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(error(f"File not found: {cves_file}"))
            return interactive_menu()  # Return to menu
    
    elif choice == 3:
        # API connectivity check will be handled by caller
        return ([], None, None, "check_apis", False)
    
    elif choice == 4:
        # API key setup will be handled by caller
        return ([], None, None, "setup", False)
    
    elif choice == 5:
        print(f"\n{Colors.BRIGHT_CYAN}Goodbye!{Colors.RESET}")
        sys.exit(0)
    
    if cves:
        # Ask about output formats
        print(f"\n{Colors.BOLD}Output Options:{Colors.RESET}")
        
        json_choice = input(f"{Colors.BOLD}Export JSON report? (y/n) [{Colors.DIM}n{Colors.RESET}{Colors.BOLD}]: {Colors.RESET}").strip().lower()
        if json_choice == 'y':
            output_json = "fluescan_report.json"
        
        csv_choice = input(f"{Colors.BOLD}Export CSV report? (y/n) [{Colors.DIM}n{Colors.RESET}{Colors.BOLD}]: {Colors.RESET}").strip().lower()
        if csv_choice == 'y':
            output_csv = "fluescan_report.csv"
    
    return (cves, output_json, output_csv, None, False)
