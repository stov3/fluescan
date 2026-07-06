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

Scores are combined using a weighted risk blend with KEV signal weighting and a CISA-confirmed exploitation boost, normalized to 0–100.

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

# Concise per-CVE score explanations
python3 fluescan.py --cves-file examples/sample_cves.txt --explain

# Interactive guided menu (no arguments)
python3 fluescan.py

# Diagnostics
python3 fluescan.py --check-apis   # test all API connections
python3 fluescan.py --setup        # configure API keys interactively
```
`--explain` prints a concise deterministic explanation per CVE with an `affected:` component line plus a one-paragraph score rationale.

---
## Scoring Algorithm

The priority score uses a **weighted risk blend with bounded context multipliers** to keep scoring practical, explainable, and close to real-world triage behavior.
### Scoring Formula

```
raw_score = (0.30 × cvss_norm)
          + (0.40 × epss_norm)
          + (0.20 × kev_strength)
          + (0.10 × exploit_norm)

priority_score = raw_score × 100 × evidence_factor × exposure_weight
               × cwe_weight × cisa_alert_weight

if cisa_kev_confirmed:
    priority_score = priority_score × 1.15   # proportional urgency boost, capped at 100

priority_score = min(priority_score, 100)
```

### Normalization Rules
- **kev_strength**:
  - `1.0` = in CISA KEV (confirmed exploitation)
  - `0.4` = VulnCheck-only KEV early signal (reduced confidence weight)
  - `0.0` = no KEV signal
- **exploit_norm**:
  - `0.0` = no exploit signal
  - `0.5` = GitHub PoC only
  - `1.0` = Metasploit module present (with or without PoC)
- **exposure_weight** (from CVSS `AV:` attacker-reachability signal):
  - `1.10` = `AV:N` (network reachable — remotely exploitable at scale)
  - `1.00` = `AV:A` (adjacent network — requires LAN position, neutral)
  - `0.80` = `AV:L` (local — requires existing foothold or user-assisted execution)
  - `0.70` = `AV:P` (physical — requires on-site access)
  - `1.00` = unknown/unavailable
- **cwe_weight** (from NVD CWE classification):
  - `1.05` = high-impact weakness class (e.g., command injection / unsafe deserialization classes)
  - `1.02` = medium-impact weakness class
  - `1.00` = generic/unknown CWE
- **cisa_alert_weight** (from CISA KEV recency context):
  - `1.05` = added to KEV in last 30 days
  - `1.03` = added to KEV in last 90 days
  - `1.01` = in KEV but older
  - `1.00` = not in CISA KEV

### Evidence Factor

Less (or weaker) evidence lowers the score. Each CVE's evidence confidence (see below) is converted into a smooth multiplier:

```
evidence_factor = min(1.0, confidence / 85)
```

In practice:
- Full trust (factor 1.0) at confidence ≥ 85 — well-documented CVEs are not penalized
- Below that, the penalty grows proportionally (e.g. confidence 57 → ×0.67)
- CVSS from OSV fallback, missing EPSS, or failed API lookups all reduce the factor
- CISA-confirmed exploitation applies a ×1.15 urgency boost — proportional, so reachability and severity still differentiate KEV entries instead of pinning them to a fixed score
- CWE and CISA alert-context weights are intentionally bounded, so they refine priority without overwhelming core CVSS/EPSS/KEV/exploit signals

### Why These Variables (Human Triage Logic)

This mirrors how a vulnerability management team actually thinks under remediation pressure:
- **Base technical risk (CVSS)**: "How bad is impact if exploited?"
- **Observed exploit likelihood (EPSS)**: "How likely is this to be exploited soon in the wild?"
- **Known active exploitation (CISA KEV / VulnCheck early KEV)**: "Is this already being exploited by real attackers?"
- **Exploit availability (PoC / Metasploit)**: "How much attacker effort is needed right now?"
- **Reachability (AV)**: "Can this be hit remotely, or does it require foothold/physical presence?"
- **Weakness class (CWE)**: "Does the flaw pattern historically lead to high-impact compromise paths?"
- **Alert recency (CISA dateAdded)**: "Is this currently hot in defender/adversary workflows?"
- **Evidence quality (confidence -> evidence_factor)**: "How much should we trust this rank given source coverage and agreement?"

In short: severity alone is not enough, exploitability alone is not enough, and threat context alone is not enough. The score combines all three, then scales by evidence quality.

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
Evidence:
  evidence_factor = 1.0   # confidence ≥ 85, full trust
  score = 0.925 × 100 × 1.0 × 1.10 = 101.75 → capped at 100

KEV urgency boost (CISA-confirmed only):
  score = min(100 × 1.15, 100) = 100
```

### Risk Level Interpretation

| Score Range | Risk Level | Interpretation |
| 0–29 | **Minimal** | Very low risk; low severity and no evidence of exploitation |

### Design Rationale

- Linear blending is easy to audit and explain to operators.
- Bounded multipliers (AV/CWE/CISA-alert) add operational context without destabilizing baseline risk.
- EPSS includes optional 7-day delta enrichment for trend-aware triage.
- Missing data is handled transparently by the evidence factor instead of synthetic priors.

### Confidence & Evidence Scoring

Fluescan outputs a **single priority score** — exploitability signals (KEV, EPSS, PoC, Metasploit) are already blended into it. Each CVE's **evidence confidence (0–100%)** is computed from source authority and health, then folded into the score via the `evidence_factor`: less or weaker evidence means a lower score.

```
confidence = (28 × cvss_quality) + (24 × epss_quality)
           + (20 × kev_quality)  + (28 × exploit_intel_quality)
           ± agreement adjustment
```

- **Source quality** distinguishes authority: NVD CVSS (0.92) > OSV fallback (0.75) > missing (0.30); a verified "not in EPSS" (0.45) is better evidence than a failed lookup (0.25).
- **Errors ≠ absence**: a failed API check lowers confidence more than a verified negative result.
- **Agreement adjustment**: +4 when ≥3 independent sources corroborate exploitation; −5 when signals conflict (critical CVSS but very weak exploitation evidence).
- Levels: `HIGH` ≥ 85, `MEDIUM` 65–84, `LOW` < 65 (verify manually).
- Each CVE's `--explain` output includes `affected:` and `cwe:` orientation lines plus a concise paragraph covering score drivers (KEV, EPSS, exploit artifacts, CVSS), attack-vector exposure, KEV urgency boost, and evidence dampening.
- `affected_component`, `cwe_ids`, `cwe_category`, `cwe_weight`, `cisa_alert_status`, `cisa_alert_days`, `cisa_alert_weight`, and `explain_summary` are exported in JSON/CSV for triage and ownership workflows.

---

## Console Output

Results are **sorted by priority** (highest first) and colour-coded.
Console output now shows the prioritized table and completion line only.

<img width="1540" height="1076" alt="image" src="https://github.com/user-attachments/assets/9cf83a93-df51-4a3b-84dc-1e0bcb8de63c" />


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

All data sources are fetched in **parallel batches** (EPSS and KEV feeds are single batched downloads; per-CVE lookups run concurrently per source), so total fetch time is bounded by the slowest source instead of the sum of all of them.

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
| `fluescan_report.json` | JSON | All report fields per CVE, including component, CWE, CISA alert-context, and explanation fields |
| `fluescan_report.csv` | CSV | Spreadsheet-friendly export with component, CWE, CISA alert-context, and explanation fields |

Custom paths: `--output-json path.json --output-csv path.csv`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `CVE not found` | Too new or not yet in NVD | Wait and retry; check nvd.nist.gov |
| EPSS always `N/A` | Very new or very old CVE | Expected; score still computed with evidence-based dampening |
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


