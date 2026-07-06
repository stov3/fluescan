# Changelog

All notable changes to this project will be documented in this file.

## [0.1.4-alpha] — 2026-07-06

### Added
- **Evidence-aware score modulation** in the main priority score.
  - Source-quality blend: CVSS 28, EPSS 24, KEV 20, exploit intel 28.
  - Agreement adjustment: +4 when ≥3 independent sources corroborate exploitation; −5 on strong conflict.
  - Internal evidence confidence now drives `evidence_factor = min(1, evidence_score/85)` before exposure weighting and KEV floor logic.
- **Concise deterministic `--explain` mode** with one paragraph per CVE explaining score drivers (KEV/EPSS/exploit artifacts/CVSS), attack-vector exposure impact, CISA floor application, and evidence dampening when applicable.
- **Affected component orientation** in explain output.
  - `--explain` now includes an `affected:` line per CVE to orient testers toward the vulnerable product/service/component.
  - Component extraction prefers NVD CPE product/vendor labels, with fallback to NVD description and OSV summary when needed.
- **Parallel batched ingestion** of independent data sources (NVD CVSS, EPSS, CISA KEV, VulnCheck KEV, GitHub PoC, Metasploit) to reduce end-to-end latency.

### Changed
- **Single-score design preserved**: priority score remains the only headline score.
- Explanation payload simplified: `explain_summary` now contains the full operator-facing explanation paragraph (JSON/CSV).
- Report payload now includes `affected_component` in JSON/CSV for downstream triage and assignment workflows.
- Fetch pipeline now runs independent source pulls concurrently; OSV fallback still runs after CVSS fetch for missing scores.

### Removed
- Redundant multi-line explain dump (`components`/`multipliers`/reason list style output) in favor of concise narrative output.

## [0.1.3-alpha] — 2026-07-03

### Added
- **CVSS attack-vector soft exposure signal** in scoring.
  - Extracts CVSS `AV` (`N/A/L/P`) from v3.x (with vector fallback) and v2 (mapped from `accessVector`).
  - Applies soft exposure weight: `N=1.07`, `A=1.03`, `L=0.96`, `P=0.90`, `UNKNOWN=1.00`.
  - Exposes `attack_vector` and `exposure_weight` in JSON/CSV output.
- **Explicit KEV display status** per record via `kev_status` (`YES`/`EARLY`/`NO`) to keep UI semantics deterministic.

### Changed
- **CLI CVE parsing hardened**: positional input now supports both space-separated and comma-separated CVE lists reliably.
- **Console table expanded**: added `AV` and `ExpW` columns to display the exposure signal directly.
- **KEV label behavior clarified** in console rendering:
  - `YES` only when CISA KEV confirms exploitation
  - `EARLY` for VulnCheck-only KEV
  - `NO` otherwise
- **Console output streamlined**: removed Analysis Summary block and Top priority line.
- **Critical color theme update**: critical/highest-priority rendering now uses bright purple in console output.

### Documentation
- README updated for:
  - comma-separated positional CVE support
  - AV/exposure-weight scoring formula updates
  - new console table columns (`AV`, `ExpW`)
  - deterministic KEV status semantics


## [0.1.2-alpha] — 2026-07-03

### Added
- **Dual KEV ingestion**: Added VulnCheck KEV fetcher alongside CISA KEV.
  - CISA KEV remains the confirmed exploitation signal.
  - VulnCheck-only entries are treated as early signal with reduced confidence.
- **OSV fallback fetcher**: Added OSV integration for CVE metadata fallback when NVD data is missing.
- **EPSS trend enrichment**: Added optional 7-day EPSS delta (`epss_prev_7d`, `epss_delta_7d`) per CVE.
- **API diagnostics expansion**: `api_checker.py` now validates VulnCheck KEV and OSV endpoints and reports VulnCheck token status.
- **Configuration expansion**: Added `VULNCHECK_API_TOKEN` support in `.env`, setup prompt, and config manager.

### Changed
- **Scoring Model Simplified**: Replaced Bayesian log-odds fusion with a transparent weighted risk blend plus hard exploitation override.
  - New core formula: `(0.30 × CVSS_norm) + (0.40 × EPSS_norm) + (0.20 × KEV_strength) + (0.10 × exploit_norm)`
  - CVSS normalization simplified to linear scale: `CVSS / 10`
  - Completeness penalty simplified to: `data_sources_found / 4`
  - KEV now applies a hard critical floor: `score = max(score, 85)`
- **CVSS extraction accuracy**: Now falls back to CVSS v3.0 and v2 metrics when v3.1 is absent — older CVEs (pre-2016) no longer score 0 due to missing v3.1 data.
- **KEV scoring signal refinement**: Replaced binary KEV handling with KEV strength tracking.
  - `1.0` for CISA-confirmed KEV
  - `0.4` for VulnCheck-only early KEV
  - `0.0` otherwise
- **Critical override behavior**: 85-point floor applies only for CISA-confirmed KEV entries.
- **Token behavior clarified**: `VULNCHECK_API_TOKEN` is optional; when absent, analysis continues with CISA KEV and all other sources.

### Removed
- Sigmoid/posterior mapping and log-odds transforms
- Non-linear high/low score reshaping
- Synthetic fallback priors for missing EPSS/KEV evidence
- Deleted unused `nuclei_fetcher.py` module.
- Dead code cleanup (~300 lines): duplicated report-building loop in `main()`, unused rate-limit statistics display, orphaned console helpers (`countdown_timer`, `print_progress`, `print_rate_limits_enhanced`), unused imports and helpers.

### Rationale
- Keeps scoring behavior practical and auditable for operators
- Preserves strongest real-world signal by hard-prioritizing CISA-confirmed active exploitation (KEV)
- Uses explicit missing-data penalty instead of inferred priors


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
