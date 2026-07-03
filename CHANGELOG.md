# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1-alpha] — 2026-07-03

### Added
- **Bayesian Scoring Algorithm**: Replaced elementary linear weighted sum with statistically rigorous Bayesian evidence combination using log-odds (Jeffreys' method) and logistic sigmoid mapping
  - Logarithmic CVSS normalization (Weber-Fechner law) to reflect human risk perception
  - Source reliability weights: EPSS 35% (highest), CVSS 30%, KEV 25%, Exploit proof 10%
  - Entropy discount for missing data (5-15% penalty) to avoid false confidence on incomplete assessments
  - Improved score distribution: low EPSS no longer artificially boosted by high CVSS

- **Complete API Checker**: Enhanced `api_checker.py` to test all 5 required data sources:
  - NVD API (CVSS v3.1)
  - EPSS API (exploitation probability)
  - CISA KEV API (known exploited vulnerabilities)
  - GitHub Search API (proof-of-concept detection)
  - ExploitDB CSV (Metasploit/exploit detection)
  - Real-time status display for each API with rate limit info

- **Comprehensive Documentation**: Updated README with theoretical foundation for Bayesian scoring
  - Weber-Fechner law explanation
  - Jeffreys' log-odds method
  - Evidence interpretation guide (0-100 confidence mapping to risk levels)
  - Example walkthrough of CVE-2023-44487 scoring calculation

### Changed
- **Priority Score Formula**: Old formula was linear addition `(CVSS × 4) + (EPSS × 40) + (KEV × 20)` × multiplier
  - New formula uses Bayesian posterior: `sigmoid(Σ weights × log_odds(evidence)) × entropy_discount × 100`
  - Better reflects actual vulnerability threat based on exploitation probability
  - Prevents artificial score inflation from theoretical severity scores

- **README Version Badge**: Updated to `v0.1.1-alpha` with completed features listed

- **API Checker Output**: Enhanced with per-API rate limit display and token status

### Fixed
- API checker no longer partially checks APIs (was missing GitHub Search and ExploitDB)
- Improved score accuracy for high CVSS + low EPSS vulnerabilities (e.g., CVE-2026-28779: 65 → 30.3)
- **Console spam from repeated rate limit messages**: Rate limiter now announces each rate limit period only once, not repeatedly for each acquire() call
- **Removed unhelpful statistics**: Removed "Rate Limit Statistics (>80% usage)" output that cluttered console
- **CRITICAL: GitHub PoC fetcher was skipping all results**: Results processing code was unreachable (placed after `raise` in exception handler) — fixed by moving result processing outside the exception handler. GitHub PoCs are now correctly detected and included in prioritization scores.

### Performance
- No measurable performance impact from new Bayesian calculation
- Scoring still completes in O(1) per CVE
- **NVD result cache (24h)**: CVSS lookups are served locally on re-runs — zero NVD API calls for recently analyzed CVEs
- **GitHub PoC result cache (24h)**: PoC search results served locally on re-runs — zero GitHub API calls for recently analyzed CVEs
- **GitHub queries halved**: 1 search query per CVE instead of 2 (single `in:name,description` query with exploit-context filtering, `per_page=50` for recall)
- **Fixed ETag 304 handling**: response body now cached alongside ETag, so free 304 revalidations actually return data (previously a 304 silently produced zero results)
- Measured: 9-CVE batch went from ~72s (cold) to ~5s (warm cache)

### Tested
- CVE-2023-44487 (high EPSS + KEV): 100.0 ✓
- CVE-2026-28779 (high CVSS + low EPSS): 30.3 ✓
- Multiple test runs show consistent sorting and score distribution

### Known Issues
- Rate limiting mechanism is far from perfect and requires much tuning.

---

## [0.1.0-alpha] — 2026-06-XX

### Initial Release
- First public alpha release
- Combined CVSS, EPSS, KEV, GitHub PoCs, and Metasploit modules into prioritization scores
- Rate limiting with exponential backoff
- ETag/Last-Modified caching for efficient API usage
- Interactive setup for optional API keys
- JSON and CSV report export
