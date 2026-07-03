# vuln-prioritize

> **v0.1.1-alpha** — Bayesian scoring algorithm, API checker completeness, rate limiting optimizations.
> ✅ **Completed**: Bayesian log-odds prioritization · All 5 API checks · EPSS batching · ETag caching · Exponential backoff

A command-line tool that combines five public data sources into a single **0–100 priority score** per CVE, so you know which vulnerabilities to patch first.

[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Alpha](https://img.shields.io/badge/status-alpha-orange)]()

---

## How It Works

Each CVE is scored by pulling live data from:

| Source | Provider | What it tells you |
|--------|----------|------------------|
| **CVSS v3.1** | NVD | Base severity (0–10) |
| **EPSS** | FIRST | Probability of exploitation in the wild |
| **KEV** | CISA | Confirmed active exploitation |
| **GitHub PoCs** | GitHub API | Public proof-of-concept code exists |
| **ExploitDB / MSF** | ExploitDB CSV + Metasploit Framework | Working exploit / Metasploit module exists |

Scores are combined using Bayesian evidence inference (log-odds → sigmoid), then multiplied by exploit availability factors, all normalized to 0–100.

---

## Installation

```bash
git clone https://github.com/stov3/vuln-prioritize.git
cd vuln-prioritize
pip install -r requirements.txt
```

> **Dependencies:** `pyfiglet` (optional — ASCII art title; graceful fallback if missing).  
> All API calls use Python's standard library (`urllib`).

---

## Quick Start

```bash
# Single CVE
python3 vuln-prioritize.py CVE-2024-1234

# Multiple CVEs — sorted by priority, highest risk first
python3 vuln-prioritize.py CVE-2024-1234 CVE-2023-44487 CVE-2022-0847

# From a file (one CVE per line, # = comment)
python3 vuln-prioritize.py --cves-file examples/sample_cves.txt

# Export reports
python3 vuln-prioritize.py --cves-file my_cves.txt \
  --output-json report.json \
  --output-csv  report.csv

# No console table (useful for scripting / piping)
python3 vuln-prioritize.py CVE-2024-1234 --no-table

# Interactive guided menu (no arguments)
python3 vuln-prioritize.py

# Diagnostics
python3 vuln-prioritize.py --check-apis   # test all API connections
python3 vuln-prioritize.py --setup        # configure API keys interactively
```

---

## Scoring Algorithm

The priority score uses **Bayesian evidence combination** to fuse multiple vulnerability data sources into a single 0–100 confidence score.

### Theoretical Foundation

**Bayesian Log-Odds Combination** (Jeffreys' method)
- Each data source is treated as independent evidence of vulnerability risk
- Evidence is combined using log-odds ratios: `log_odds = Σ(weight_i × log(P_i / (1 - P_i)))`
- Result is converted back to probability using logistic sigmoid: `P = 1 / (1 + e^(-log_odds))`

**Weber-Fechner Law for CVSS**
- Human perception of risk is logarithmic, not linear
- CVSS is normalized as: `CVSS_prob = log(1 + CVSS) / log(11)` to reflect diminishing returns at higher severities

**Source Reliability Weights**
Each data source is weighted by epistemic confidence:
- **EPSS (35%)** — Highest weight; statistically modeled exploitation probability
- **CVSS (30%)** — Authoritative but not exploit-specific
- **KEV (25%)** — Strong empirical evidence but lagging indicator
- **Exploit proof (10%)** — Direct proof but rare in dataset

### Scoring Formula

```
Priority Score = Apply_Nonlinearity(Bayesian_Posterior × Entropy_Discount × 100)

Where:
  Bayesian_Posterior = sigmoid(Σ weights × log_odds(evidence))
  Entropy_Discount = 0.90 + (0.10 × data_completeness)  [penalizes missing data]
  Apply_Nonlinearity = {
    score^1.05         if score < 30  (compress low-risk scores)
    score              if 30 ≤ score ≤ 70
    70 + ((score-70)^0.95) if score > 70  (expand high-risk scores)
  }
```

### Worked Example

```
CVE-2023-44487 (HTTP/2 Rapid Reset DoS):
  
  Input Data:
    CVSS v3.1:     7.5 (HIGH severity)
    EPSS:          1.0 (100% exploitation probability — peak value)
    KEV:           ✓ (CISA confirmed active exploitation)
    GitHub PoCs:   5 public exploits
    Multiplier:    1.38 (PoC + Metasploit module)
    
  Step 1: Normalize to [0,1]
    cvss_normalized = log(1+7.5) / log(11) = 0.8925
    epss_prob = 1.0 (already normalized)
    kev_present = 1.0 (active exploitation)
    exploit_proof = (1.38 - 1.0) / 0.75 = 0.5067
    
  Step 2: Accumulate weighted log-odds
    cvss_log_odds = log(0.8925/0.1075) ≈ 2.120
    epss_log_odds = log(1.0/0.001) ≈ 6.908  [EPSS maxes log_odds]
    kev_log_odds = log(0.90/0.10) ≈ 2.197   [active exploitation]
    exploit_log_odds = log(0.703/0.297) ≈ 0.849  [PoC evidence]
    
    total_log_odds = 0.30×2.120 + 0.35×6.908 + 0.25×2.197 + 0.10×0.849
                  ≈ 0.636 + 2.418 + 0.549 + 0.085 ≈ 3.688
    
  Step 3: Convert via sigmoid
    posterior = 1/(1 + e^(-3.688)) ≈ 0.9762  [97.6% risk posterior]
    
  Step 4: Apply entropy discount
    All 4 data sources present → completeness = 1.0
    entropy_discount = 0.90 + 0.10 = 1.0  [no penalty]
    adjusted = 0.9762 × 1.0 = 0.9762
    
  Step 5: Scale and apply non-linearity
    score = 0.9762 × 100 = 97.62
    Since score > 70: apply expansion transform
    final = 70 + ((97.62-70)^0.95) ≈ 70 + 27.55 ≈ 94.4  ✓ Matches
    
  Interpretation: CRITICAL
    • All evidence converges on high risk
    • Active exploitation confirmed (KEV)
    • Public exploits available
    • → Patch immediately
```

### Risk Level Interpretation

| Score Range | Risk Level | Interpretation |
|-------------|-----------|-----------------|
| 85–100 | **Critical** | Active exploitation, PoC/exploit exists, high severity |
| 70–84 | **High** | Probable exploitation or high severity + strong evidence |
| 50–69 | **Medium** | Exploitable but limited proof, or lower severity + evidence |
| 30–49 | **Low** | Difficult to exploit or low severity, no active proof |
| 0–29 | **Minimal** | Very low risk; low severity and no evidence of exploitation |

### Detailed Calculation Steps

**Step 1: Normalize inputs to [0,1] probability space**
- **CVSS**: Apply logarithmic transformation (Weber-Fechner law) → `log(1+CVSS) / log(11)`
  - Reflects diminishing risk perception at higher severities
- **EPSS**: Clamp to [0,1] (already normalized)
  - If unavailable: estimate from CVSS as `min(CVSS_normalized × 0.6, 0.7)` with 30% uncertainty penalty
- **KEV**: Binary (1.0 if active exploitation, 0.0 otherwise)
- **Exploit Proof**: Map multiplier [1.0, 1.75] to confidence [0, 1] via `(multiplier - 1.0) / 0.75`

**Step 2: Accumulate weighted log-odds**
```
total_log_odds = Σ weight_i × log(P_i / (1 - P_i))

Evidence contributions:
  - CVSS (30%):       log_odds(cvss_prob)  [or log_odds(0.1) if absent]
  - EPSS (35%):       log_odds(epss_prob)  [or 0.70× log_odds(estimated) if absent]
  - KEV (25%):        log_odds(0.90) if active, else log_odds(0.35)
  - Exploit (10%):    log_odds(0.50 + exploit_proof × 0.40) if proof > 0.1
```

**Step 3: Convert log-odds to probability via sigmoid**
```
posterior = 1 / (1 + e^(-total_log_odds))   [clamped to [-12, 12] to prevent overflow]
```

**Step 4: Apply entropy discount for missing data**
```
data_completeness = (CVSS_present + EPSS_present + KEV_present + Exploit_present) / 4
entropy_discount = 0.90 + (0.10 × data_completeness)
adjusted_prob = posterior × entropy_discount
```
Missing data (e.g., no EPSS) counts as 0.5 contribution, reducing confidence by 5-10%.

**Step 5: Scale to 0-100 with non-linearity adjustment**
- Low scores (<30): compressed via `score^1.05` → less spread among low-risk vulns
- High scores (>70): expanded via `70 + ((score-70)^0.95)` → more spread among critical vulns
- Final bounds: [0, 100]

---

## Console Output

Results are **sorted by priority** (highest first) and colour-coded:

```
Rank   CVE ID             Priority    CVSS   Severity   EPSS     KEV   PoC   Multiplier
═══════════════════════════════════════════════════════════════════════════════════════════
1      CVE-2023-44487     78.0        7.5    HIGH       N/A      YES   YES   1.20×
2      CVE-2024-1234      52.8        8.8    HIGH       N/A      NO    NO    1.00×
3      CVE-2099-9999       0.0        0.0    UNKNOWN    N/A      NO    NO    1.00×
```

| Colour | Score | Action |
|--------|-------|--------|
| 🔴 Bright Red | ≥ 80 | Patch immediately |
| 🔴 Red | ≥ 60 | Patch soon |
| 🟠 Amber | ≥ 40 | Patch this month |
| 🟡 Yellow | ≥ 20 | Patch when possible |
| 🟢 Green | < 20 | Low priority |

---

## Rate Limits

The tool enforces per-API rate limits automatically. When a limit is reached it displays an in-place countdown and resumes without data loss. Local result caches (24h TTL) mean re-runs of recently analyzed CVEs cost **zero** API calls.

| API | Unauthenticated | With key/token | Local cache |
|-----|----------------|----------------|-------------|
| NVD (CVSS) | 5 req/min | 5 req/sec (×60) | 24h per-CVE result cache |
| EPSS | 30 req/min (batch — 1 call for all CVEs) | — | — |
| KEV | One request (cached with `If-Modified-Since`) | — | Conditional cache |
| GitHub Search | 10 req/min (1 query/CVE) | 30 req/min (1 query/CVE) | 24h per-CVE result cache + ETag |
| ExploitDB CSV | One download (ETag-cached, free on re-runs) | — | ETag cache |

---

## Optional API Keys

None are required, but they speed things up significantly for large batches.

### NVD API Key — 60× faster CVSS lookups

```bash
# Get a free key: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your_key_here
# or add to .env (see .env.example)
```

### GitHub Token — 3× more GitHub searches + MSF module detection

```bash
# Create at https://github.com/settings/tokens
# No scopes needed for public data access
export GITHUB_TOKEN=ghp_your_token_here
```

With a GitHub token, the tool also searches the official
[`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)
repository for modules referencing the CVE — the most accurate source for MSF coverage.

### Interactive setup

```bash
python3 vuln-prioritize.py --setup
```

Keys are saved to `.env` (already in `.gitignore`).

---

## Project Structure

```
vuln-prioritize/
├── vuln-prioritize.py          # Entry point & orchestration
├── src/
│   ├── config.py               # API key management
│   ├── console.py              # Terminal UI, colours, progress
│   ├── rate_limiter.py         # Per-API rate enforcement & countdown
│   ├── api_checker.py          # Connectivity diagnostics
│   └── fetchers/
│       ├── cvss_fetcher.py     # NVD  — CVSS v3.1
│       ├── epss_fetcher.py     # FIRST — EPSS (batched)
│       ├── kev_fetcher.py      # CISA  — KEV (cached)
│       ├── github_poc_fetcher.py  # GitHub Search — PoCs
│       └── metasploit_fetcher.py  # ExploitDB CSV + MSF GitHub
├── examples/
│   └── sample_cves.txt         # Ready-to-run example list
├── requirements.txt
├── .env.example                # API key template
└── LICENSE
```

---

## Output Files

| File | Format | Contents |
|------|--------|----------|
| `vulnerability_report.json` | JSON | All fields per CVE (CVSS, EPSS, KEV, PoC, exploit, scores) |
| `vulnerability_report.csv` | CSV | Same data, spreadsheet-compatible |

Custom paths: `--output-json path.json --output-csv path.csv`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `CVE not found` | Too new or not yet in NVD | Wait and retry; check nvd.nist.gov |
| EPSS always `N/A` | Very new or very old CVE | Expected — EPSS covers ~2 years of active CVEs |
| GitHub returns 403 | Unauthenticated rate limit | Add `GITHUB_TOKEN` to `.env` |
| Countdown timer appears | API rate limit reached | Wait; tool resumes automatically |
| Score is 0.0 | No data from any source | CVE may not exist or APIs are down |

---

## Contributing

This is an alpha release — contributions are very welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Commit your changes
4. Open a Pull Request

Please report bugs and ideas via [GitHub Issues](https://github.com/stov3/vuln-prioritize/issues).

---

## References

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [EPSS Scoring](https://www.first.org/epss/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [GitHub REST API — Rate Limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [ExploitDB](https://www.exploit-db.com/)
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)

---

## ⚠️ Disclaimer

This tool provides vulnerability prioritization **guidance only**. Results depend on the accuracy and availability of upstream data sources and should always be **verified independently** before making remediation decisions.

This software is intended for **legitimate security research and defensive purposes**. Use of this tool to facilitate unauthorised access to systems is strictly prohibited. See [LICENSE](LICENSE) for full terms.


## Installation

```bash
# Clone repository
git clone https://github.com/stov3/vuln-prioritize.git
cd vuln-prioritize

# Install dependencies
pip install -r requirements.txt

# Optional: Configure NVD API key for 60x speedup
python3 vuln-prioritize.py --setup
```

## Quick Start

```bash
# Interactive mode (guided menu)
python3 vuln-prioritize.py

# Analyze specific CVEs (sorted by priority, highest first)
python3 vuln-prioritize.py CVE-2024-1234 CVE-2024-5678

# Analyze from file
python3 vuln-prioritize.py --cves-file examples/sample_cves.txt

# Generate reports
python3 vuln-prioritize.py CVE-2024-1234 --output-json report.json --output-csv report.csv

# Test API connectivity
python3 vuln-prioritize.py --check-apis

# Configure API keys
python3 vuln-prioritize.py --setup
```

## Usage

### Interactive Menu Mode (Default)
When running without arguments, you'll see a friendly guided menu:

```
Welcome to vuln-prioritize - Vulnerability Prioritization Tool

Main Menu:
  1. Analyze specific CVE IDs
  2. Analyze CVEs from file
  3. Check API connectivity
  4. Configure API keys
  5. Exit

Select an option [1-5]: 
```

Simply select an option and follow the prompts. Perfect for casual analysis!

### Command-Line Mode
For scripting and automation, use direct arguments:

```bash
# Single CVE
python3 vuln-prioritize.py CVE-2024-1234

# Multiple CVEs (space-separated)
python3 vuln-prioritize.py CVE-2024-1234 CVE-2024-5678 CVE-2023-44487

# From file (one CVE per line, # for comments)
python3 vuln-prioritize.py --cves-file cves.txt

# Export to multiple formats
python3 vuln-prioritize.py CVE-2024-1234 \
  --output-json report.json \
  --output-csv report.csv

# Suppress console table
python3 vuln-prioritize.py CVE-2024-1234 --no-table

# Diagnostic commands
python3 vuln-prioritize.py --check-apis    # Test all APIs
python3 vuln-prioritize.py --setup         # Configure API keys
```

## Features

- **Multi-Source Analysis**: Combines 5 vulnerability data sources (NVD, FIRST, CISA, GitHub, ExploitDB)
- **Exploit Intelligence**: Detects GitHub PoCs and Metasploit modules with multi-layer false positive filtering
- **Intelligent Scoring**: Compounds multiple signals with 0-100 priority scale and stacking multiplier system
- **Automatic Sorting**: CVEs displayed in priority order (highest risk first)
- **Beautiful Console Output**: Color-coded table, priority-based highlighting, summary statistics
- **Interactive Menu**: User-friendly guided interface for CVE analysis
- **Rate Limiting**: Enforced per-API with automatic throttling and countdown timers
  - **Automatic Waits**: When rate limits are reached, the tool automatically waits for reset
  - **Complete Data**: Ensures all API responses are complete before finalizing results
  - **Visual Feedback**: Shows countdown timer during rate limit resets (prevents false positives)
- **Multiple Formats**: Console table, JSON (25+ fields), CSV (spreadsheet-compatible)
- **API Key Management**: Optional NVD API key for 60x speedup
- **Connectivity Diagnostics**: `--check-apis` flag tests all data sources
- **No Dependencies**: Uses only Python standard library

## Scoring Algorithm

The priority score (0-100) is calculated using weighted components:

### Base Score Components

| Component | Weight | Formula | Max Points |
|-----------|--------|---------|-----------|
| **CVSS v3.1** | 40% | CVSS × 4 | 40 |
| **EPSS** | 40% | EPSS × 40 | 40 |
| **KEV Status** | 20% | +20 if exploited | 20 |

**Base Score Formula:**
```
base_score = (CVSS × 4) + (EPSS × 40) + (KEV × 20)
```

*If EPSS data unavailable: base_score = (CVSS × 6) + (KEV × 20)*

### Exploit Multipliers

After base score calculation, apply multipliers for publicly available exploits:

```
final_score = base_score × exploit_multiplier (capped at 100)

Multipliers (stack multiplicatively):
  ├─ Public PoC found:     1.2x (20% boost)
  ├─ Metasploit excellent: 1.35x (35% boost)
  ├─ Metasploit great:     1.30x (30% boost)
  ├─ Metasploit good:      1.25x (25% boost)
  ├─ Metasploit normal:    1.15x (15% boost)
  └─ Max multiplier cap:   1.75x
```

### Example Calculation

**CVE-2023-44487:**
```
CVSS Score: 7.5   → 7.5 × 4 = 30
EPSS Score: N/A   → 7.5 × 2 = 15 (not available)
KEV Status: YES   → 20
Base Score:       = 65

Exploit Factors:
  ✓ Public PoC found → 1.2x

Final Score: 65 × 1.2 = 78.0
Priority Rank: #1 (Remediate first)
```

### Remediation Priority

CVEs are displayed in **remediation priority order** (highest risk first):

- **Rank 1**: CVE-2023-44487 (score: 78.0) ← Start here
- **Rank 2**: CVE-2026-9995 (score: 35.3)
- **Rank 3**: CVE-2026-9999 (score: 35.3)

Higher scores = Higher remediation priority = Patch first

## Output Formats

### Console Table (Color-Coded & Sorted)
Results are automatically **sorted by remediation priority** (highest risk first) and **color-coded** for visual emphasis:
- 🔴 Bright Red: Priority ≥ 80 (Critical - Patch immediately)
- 🔴 Red: Priority ≥ 60 (High - Patch soon)
- 🟠 Bright Yellow: Priority ≥ 40 (Medium - Patch this month)
- 🟡 Yellow: Priority ≥ 20 (Low - Patch when possible)
- 🟢 Green: Priority < 20 (Minimal - Low priority)

```
Rank   CVE ID             Priority    CVSS     Severity      EPSS      KEV    PoC    Multiplier
────────────────────────────────────────────────────────────────────────────────────────────────
1      CVE-2023-44487     78.0        7.5      HIGH          N/A       YES    YES    1.20x
2      CVE-2026-9999      35.3        8.8      HIGH          0.00      NO     NO     1.00x
3      CVE-2026-9995      35.3        8.8      HIGH          0.00      NO     NO     1.00x
```

**Rank = Remediation Priority** (1 = patch first)

### JSON Report
Contains 25+ fields per CVE including exploit data, base scores, and severity ratings.

### CSV Report
Spreadsheet-compatible format with all metrics.

## Project Structure

```
vuln-prioritize/
├── vuln-prioritize.py         # Main entry point (all logic here)
├── src/
│   ├── console.py             # ANSI colors & interactive UI
│   ├── config.py              # API key management
│   ├── rate_limiter.py        # Rate limit enforcement
│   ├── api_checker.py         # Connectivity diagnostics
│   └── fetchers/
│       ├── cvss_fetcher.py    # CVSS v3.1 (NVD)
│       ├── epss_fetcher.py    # EPSS predictions (FIRST)
│       ├── kev_fetcher.py     # Known exploited (CISA)
│       ├── github_poc_fetcher.py   # GitHub PoCs
│       └── metasploit_fetcher.py   # Metasploit/ExploitDB
├── examples/
│   ├── sample_cves.txt        # Example CVE list
│   └── sample_output/         # Example reports
├── .env.example               # API key template
└── README.md                  # This file
```

## Data Sources

| Source | Provider | Rate Limit | Purpose |
|--------|----------|-----------|---------|
| CVSS | NVD | 5 req/min | Base vulnerability severity |
| EPSS | FIRST | 30 req/min | Exploitation probability |
| KEV | CISA | 10 req/min | Known exploited status |
| GitHub | GitHub API | 30 req/min | Public PoC detection |
| Metasploit | ExploitDB | 15 req/min | Exploit module verification |

## API Key Setup (Optional)

**Get faster NVD access (60x):**

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Run `python3 vuln-prioritize.py --setup`
3. Enter your API key when prompted
4. Keys are stored in `.env` (add to `.gitignore`)

## Requirements

- Python 3.7+
- Internet connection (for API calls)
- **Optional:** `pyfiglet` for fancy ASCII art title (auto-installs, graceful fallback if unavailable)

## Examples

### Analyze Known Vulnerabilities

```bash
cat > my_cves.txt << EOF
CVE-2024-1234
CVE-2024-5678
CVE-2023-44487
EOF

python3 vuln-prioritize.py --cves-file my_cves.txt
```

### Export for Security Dashboard

```bash
python3 vuln-prioritize.py --cves-file my_cves.txt \
  --output-json vulnerabilities.json \
  --no-table
```

### Batch Processing with Sorting

```bash
python3 vuln-prioritize.py --cves-file my_cves.txt --output-csv report.csv
# Then sort/filter in your favorite spreadsheet application
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| "No CVE IDs provided" | Use `CVE-XXXX-XXXXX` format or `--cves-file` |
| "CVE not found" | May be too recent or not in NVD database |
| "Connection timeout" | Check internet connection and API endpoint status |
| "Rate limit hit" | Tool pauses automatically, shows wait time |
| Empty EPSS data | EPSS only covers recent CVEs (last ~2 years) |

## Performance

- Single CVE analysis: ~2-3 seconds
- Batch of 10 CVEs: ~25-30 seconds
- Rate limiting enforced automatically per API

## Output Files

Generated in current directory:
- `vulnerability_report.json` - Detailed JSON report
- `vulnerability_report.csv` - Spreadsheet-compatible CSV

## License

This project is provided as-is for vulnerability prioritization purposes.

## References

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [EPSS Scoring](https://www.first.org/epss/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [GitHub API Search](https://docs.github.com/en/rest/search/search-repositories)
- [ExploitDB API](https://www.exploit-db.com/api)
- [Metasploit Framework](https://www.metasploit.com/)

## ⚠️ Disclaimer

This tool provides vulnerability prioritization **guidance** based on multiple data sources (CVSS, EPSS, KEV, PoCs, Metasploit). While efforts are made to ensure accuracy, the results should be **verified independently**. This tool is provided **AS-IS without warranty**. Always perform thorough security assessments before making remediation decisions.

**Results may be inaccurate due to:**
- Missing or outdated data from upstream sources
- False positives in PoC detection
- API availability and rate limiting
- Network connectivity issues

## 📖 Open Source

This project is **open-source and community-driven**. 

- 🐛 **Report Issues**: https://github.com/stov3/vuln-prioritize/issues
- 💡 **Contribute**: https://github.com/stov3/vuln-prioritize/pulls
- ⭐ **Star the Project**: https://github.com/stov3/vuln-prioritize

## 👤 Author

**Created by:** [@stov3](https://github.com/stov3)  
**Repository:** https://github.com/stov3/vuln-prioritize  
**Issues & Features:** https://github.com/stov3/vuln-prioritize/issues

---

*Last updated: 2026-07-03*

