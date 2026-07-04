## Fluescan

**Fluescan** *(noun)* /ˈfluː.skæn/

> A tool for surfacing risks that quietly accumulate until they ignite — named after the *flue*, the chimney passage where dangerous buildup collects unnoticed until it flashes over.


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
| **KEV (Confirmed)** | CISA | Confirmed active exploitation |
| **KEV (Early signal)** | VulnCheck | Earlier exploitation evidence before CISA inclusion |
| **GitHub PoCs** | GitHub API | Public proof-of-concept code exists |
| **ExploitDB / MSF** | ExploitDB CSV + Metasploit Framework | Working exploit / Metasploit module exists |
| **OSV fallback** | OSV.dev | Metadata/CVSS fallback when NVD is missing or delayed |

Scores are combined using a weighted risk blend with KEV signal weighting and a CISA-confirmed critical floor, normalized to 0–100.

---

## Installation

```bash
git clone https://github.com/stov3/fluescan.git
cd fluescan
pip install -r requirements.txt
```

> **Dependencies:** `pyfiglet` (optional — ASCII art title; graceful fallback if missing).  
> All API calls use Python's standard library (`urllib`).

---

## Quick Start

```bash
# Single CVE
python3 fluescan.py CVE-2024-1234

# Multiple CVEs — sorted by priority, highest risk first
python3 fluescan.py CVE-2024-1234 CVE-2023-44487 CVE-2022-0847

# Multiple CVEs (comma-separated also supported)
python3 fluescan.py CVE-2024-1234, CVE-2023-44487, CVE-2022-0847

# From a file (one CVE per line, # = comment)
python3 fluescan.py --cves-file examples/sample_cves.txt

# Export reports
python3 fluescan.py --cves-file my_cves.txt \
  --output-json report.json \
  --output-csv  report.csv

# No console table (useful for scripting / piping)
python3 fluescan.py CVE-2024-1234 --no-table

# Interactive guided menu (no arguments)
python3 fluescan.py

# Diagnostics
python3 fluescan.py --check-apis   # test all API connections
python3 fluescan.py --setup        # configure API keys interactively
```

Positional CVE input accepts both space-separated and comma-separated formats.

---

## Scoring Algorithm

The priority score uses a **weighted risk blend with exploitation override** to keep scoring transparent and practical.

### Scoring Formula

```
raw_score = (0.30 × cvss_norm)
          + (0.40 × epss_norm)
          + (0.20 × kev_strength)
          + (0.10 × exploit_norm)

priority_score = raw_score × 100 × completeness_factor × exposure_weight

if cisa_kev_confirmed:
    priority_score = max(priority_score, 85)
```

### Normalization Rules

- **cvss_norm** = `CVSS / 10` (clamped to [0,1])
- **epss_norm** = `EPSS` (already [0,1], or unavailable)
- **kev_strength**:
  - `1.0` = in CISA KEV (confirmed exploitation)
  - `0.4` = VulnCheck-only KEV early signal (reduced confidence weight)
  - `0.0` = no KEV signal
- **exploit_norm**:
  - `0.0` = no exploit signal
  - `0.5` = GitHub PoC only
  - `1.0` = Metasploit module present (with or without PoC)
- **exposure_weight** (from CVSS `AV:` soft signal):
  - `1.07` = `AV:N` (network reachable)
  - `1.03` = `AV:A` (adjacent network)
  - `0.96` = `AV:L` (local)
  - `0.90` = `AV:P` (physical)
  - `1.00` = unknown/unavailable

### Completeness Factor

To avoid overconfidence when data is missing:

```
completeness_factor = data_sources_found / 4
```

In practice:
- CVSS missing reduces confidence
- EPSS missing reduces confidence
- KEV and exploit channels are always evaluated as explicit yes/no signals

### Worked Example

```
CVE-2023-44487 (HTTP/2 Rapid Reset DoS):

Input:
  CVSS = 7.5
  EPSS = 1.00
  CISA KEV = YES
  VulnCheck KEV = YES
  PoC = YES
  Metasploit = YES

Normalize:
  cvss_norm = 7.5 / 10 = 0.75
  epss_norm = 1.00
  kev_strength = 1.0
  exploit_norm = 1.0
  exposure_weight = 1.07   # AV:N

Weighted blend:
  raw_score = (0.30×0.75) + (0.40×1.00) + (0.20×1.0) + (0.10×1.0)
            = 0.225 + 0.400 + 0.200 + 0.100
            = 0.925

Completeness:
  completeness_factor = 4/4 = 1.0
  score = 0.925 × 100 × 1.0 × 1.07 = 98.975

Critical override (CISA-confirmed only):
  score = max(98.975, 85) = 98.975
```

### Risk Level Interpretation

| Score Range | Risk Level | Interpretation |
|-------------|-----------|-----------------|
| 85–100 | **Critical** | Active exploitation, PoC/exploit exists, high severity |
| 70–84 | **High** | Probable exploitation or high severity + strong evidence |
| 50–69 | **Medium** | Exploitable but limited proof, or lower severity + evidence |
| 30–49 | **Low** | Difficult to exploit or low severity, no active proof |
| 0–29 | **Minimal** | Very low risk; low severity and no evidence of exploitation |

### Design Rationale

- Linear blending is easy to audit and explain to operators.
- EPSS gets the largest weight as the strongest forward-looking exploitation signal.
- CISA KEV remains the hard-confirmation signal and enforces a critical floor.
- VulnCheck KEV adds earlier exploitation evidence with a reduced confidence weight.
- CVSS `AV:` adds a small exposure nudge to distinguish likely internet-facing vs internal-only paths.
- EPSS includes optional 7-day delta enrichment for trend-aware triage.
- Missing data is handled transparently by the completeness factor instead of synthetic priors.

---

## Console Output

Results are **sorted by priority** (highest first) and colour-coded.
Console output now shows the prioritized table and completion line only.

```
Rank   CVE ID             Priority    CVSS   Severity   EPSS   AV   ExpW    KEV    PoC   Multiplier
══════════════════════════════════════════════════════════════════════════════════════════════════════
1      CVE-2023-44487     98.97       7.5    HIGH       1.00   N    1.07x   YES    YES   1.38x
2      CVE-2020-1472      85.00       5.5    MEDIUM     1.00   L    0.96x   YES    YES   1.38x
3      CVE-2024-50379     55.50       9.8    CRITICAL   0.44   N    1.07x   NO     YES   1.20x
```

- `KEV` values are explicit: `YES` (CISA confirmed), `EARLY` (VulnCheck-only), `NO` (no KEV signal).
- `AV` and `ExpW` show CVSS attack vector and the soft exposure weight used in scoring.

| Colour | Score | Action |
|--------|-------|--------|
| 🟣 Bright Purple | ≥ 80 | Patch immediately |
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
| EPSS (+ trend) | 30 req/min (batch) | — | — |
| CISA KEV | One request (cached with `If-Modified-Since`) | — | Conditional cache |
| VulnCheck KEV | — | 60 req/min (token) | 6h cache |
| OSV fallback | 60 req/min | — | — |
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

### VulnCheck Token — early KEV signal coverage

```bash
# Free community signup
export VULNCHECK_API_TOKEN=your_token_here
```

This token is optional. If not configured, the tool still runs normally using CISA KEV and other sources.

With a GitHub token, the tool also searches the official
[`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)
repository for modules referencing the CVE — the most accurate source for MSF coverage.

### Interactive setup

```bash
python3 fluescan.py --setup
```

Keys are saved to `.env` (already in `.gitignore`).

---

## Project Structure

```
fluescan/
├── fluescan.py          # Entry point & orchestration
├── src/
│   ├── config.py               # API key management
│   ├── console.py              # Terminal UI, colours, progress
│   ├── rate_limiter.py         # Per-API rate enforcement & countdown
│   ├── api_checker.py          # Connectivity diagnostics
│   └── fetchers/
│       ├── cvss_fetcher.py     # NVD  — CVSS v3.1
│       ├── epss_fetcher.py     # FIRST — EPSS (batched)
│       ├── kev_fetcher.py      # CISA  — KEV (cached)
│       ├── vulncheck_kev_fetcher.py # VulnCheck KEV (early signal)
│       ├── osv_fetcher.py      # OSV.dev fallback metadata
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
| `fluescan_report.json` | JSON | All fields per CVE (CVSS, EPSS, KEV, PoC, exploit, scores) |
| `fluescan_report.csv` | CSV | Same data, spreadsheet-compatible |

Custom paths: `--output-json path.json --output-csv path.csv`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `CVE not found` | Too new or not yet in NVD | Wait and retry; check nvd.nist.gov |
| EPSS always `N/A` | Very new or very old CVE | Expected; score still computed with completeness penalty |
| CVSS is missing from NVD | NVD lag for new CVE | OSV fallback is attempted automatically |
| VulnCheck KEV unavailable | Missing/invalid token | Set `VULNCHECK_API_TOKEN` in `.env` |
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

Please report bugs and ideas via [GitHub Issues](https://github.com/stov3/fluescan/issues).

---

## References

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [EPSS Scoring](https://www.first.org/epss/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [VulnCheck KEV](https://vulncheck.com/kev)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [OSV.dev API](https://google.github.io/osv.dev/api/)
- [GitHub REST API — Rate Limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [ExploitDB](https://www.exploit-db.com/)
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)

---

## ⚠️ Disclaimer

This tool provides vulnerability prioritization **guidance only**. Results depend on the accuracy and availability of upstream data sources and should always be **verified independently** before making remediation decisions.

This software is intended for **legitimate security research and defensive purposes**. Use of this tool to facilitate unauthorised access to systems is strictly prohibited. See [LICENSE](LICENSE) for full terms.


