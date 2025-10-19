# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is "Vuln-Bot" - a high-risk CVE intelligence platform that tracks Critical & High severity vulnerabilities with EPSS ≥ 60% exploitation probability. It automatically harvests, scores, and publishes vulnerability briefings every 4 hours. It's a Python-based project using Alpine.js for the frontend dashboard, with static HTML generation via `scripts/generate_alpine_dashboard.py`.

## Common Development Commands

### Python Development
```bash
# Install Python dependencies (using uv)
uv pip install -r requirements.txt

# Run the vulnerability harvester (incremental mode is DEFAULT)
python -m scripts.main harvest --cache-dir .cache/

# INCREMENTAL HARVESTING (Default Behavior):
# - Initial harvest: EPSS-first filtering (~100 CVEs instead of 15,000)
# - Daily incremental: Only CVEs updated in last 48 hours (~10-20 CVEs)
# - Auto-detects first run vs. incremental update

# Force full refresh (weekly EPSS update recommended)
python -m scripts.main harvest --cache-dir .cache/ --no-incremental

# Generate briefing from cached data
python -m scripts.main generate-briefing

# Generate with optimized storage (chunked by severity-year)
python -m scripts.main generate-briefing --storage-strategy severity-year

# Update coverage badge in README
python -m scripts.main update-badge

# Send vulnerability alerts to webhooks
python -m scripts.main send-alerts --risk-threshold 80

# Validate EPSS threshold compliance (CI/CD gating)
python -m scripts.main validate-threshold-compliance \
  --api-dir api \
  --cache-dir .cache \
  --output-dir reports \
  --min-epss 0.6 \
  --fail-on-violations

# Clean stale files before build
python -m scripts.cleanup_stale_files \
  --build-dir _site \
  --api-dir api \
  --min-epss 0.6

# Enrich with CISA KEV data
python -m scripts.enhance_cisa_kev --api-dir api/vulns

# Add exploit availability flags and EPSS percentiles
python -m scripts.enhance_exploit_availability --api-dir api/vulns

# Validate data quality at various stages
python -m scripts.validate_data_quality --stage enriched --api-dir api

# Run Python linting (Ruff)
ruff check scripts/
ruff format scripts/

# Run Python tests with coverage
pytest --cov=scripts --cov-report=html --cov-report=term tests/

# Run Playwright E2E tests for live site
pip install pytest-playwright playwright
playwright install --with-deps chromium
pytest tests/e2e/test_live_site_sanity.py -v

# Run security checks
bandit -r scripts/ -ll

# CRITICAL: Run comprehensive CI/CD gatecheck validation
python -m scripts.ci_gatecheck \
  --api-dir public/api \
  --max-cve-count 1000 \
  --expected-cve-count 60 \
  --min-epss 0.6 \
  --output-report gatecheck.json \
  --fail-on-warnings
```

### Build & Deployment
```bash
# Install Node dependencies (for linting/formatting only)
npm install

# Build the site (Python-based generation)
npm run build  # Runs: python -m scripts.generate_alpine_dashboard

# Force clean build with validation (recommended for production)
npm run build:force  # Runs: python -m scripts.force_rebuild

# Serve the site locally
npm run serve  # Builds then serves on http://localhost:8000

# Validate build output
npm run validate  # Runs CI gatecheck validation

# Run ESLint (Google style guide)
npm run lint

# Run Prettier formatting
npm run format

# Run all pre-commit checks
npm run precommit

# Deploy to GitHub Pages
npm run deploy
```

### ⚠️ IMPORTANT: Build System
- **11ty has been REMOVED** - Site generation is now Python-only
- All builds use `scripts/generate_alpine_dashboard.py`
- Force rebuilds use `scripts/force_rebuild.py`
- No incremental builds - always clean generation

### Git Workflow
```bash
# Commits go through Husky pre-commit hooks automatically
# Commit messages must follow conventional commit format
git commit -m "type(scope): description"

# Make Husky scripts executable (first time setup)
chmod +x .husky/pre-commit .husky/commit-msg
```

## Architecture Overview

### Data Flow
1. **Scheduled Harvesting** (Python scripts in `scripts/`, runs every 4 hours):
   - **Pre-build cleanup**: Removes stale files from previous builds
   - Fetches from multiple sources:
     - CVEProject/cvelistV5 repository (official CVE List, updated every 7 minutes)
     - GitHub Security Advisory Database (via GraphQL API)
   - Filters for Critical/High severity CVEs from 2024-2025 with EPSS scores ≥ 60%
   - **Multi-stage enrichment**:
     - EPSS API data with percentile rankings (flags top 1%, 5%, 10%)
     - CISA KEV catalog integration (Known Exploited Vulnerabilities)
     - Exploit availability detection from multiple sources (Exploit-DB, Metasploit, GitHub PoCs)
     - deps.dev package impact analysis for supply chain visibility (implemented in `scripts/agents/deps_dev_enrichment_agent.py`)
     - Reference categorization (exploit, patch, advisory, vendor, technical)
   - Normalizes data and calculates Risk Score (0-100) based on CVSS, EPSS, popularity, infrastructure tags, and newness
   - **Data validation** at each stage (raw, filtered, enriched, published)
   - Caches responses in SQLite using GitHub Actions cache (10-day TTL, timezone-aware)

2. **Content Generation** (Python-based):
   - `scripts/generate_alpine_dashboard.py` creates single-page Alpine.js dashboard
   - Generates chunked vulnerability data files at `api/vulns/vulns-{{year}}-{{severity}}.json`
   - Builds consolidated search index at `api/vulns/index.json`
   - Creates chunk index at `api/vulns/chunk-index.json` for navigation
   - Output directory: `public/`

3. **Frontend** (Alpine.js + Fuse.js):
   - Client-side filtering UI on the homepage
   - Real-time search/filter on: CVE ID, severity, CVSS/EPSS scores, date ranges, vendors, exploitation status
   - URL hash-based state for shareable filtered views
   - Paginated results (10/20/50/100 rows, default 50)
   - **Data Visualization Dashboard** (Canvas-based for performance):
     - Severity distribution pie chart
     - Risk trend line chart (30-day vulnerability patterns)
     - EPSS score distribution bar chart
     - Top vendor risk horizontal bar chart
     - Keyboard accessible chart navigation (Arrow keys, Home/End)
     - Screen reader descriptions and announcements
     - Chart export functionality for security reports
   - **Mobile-First Responsive Design**:
     - Touch gesture support (swipe for pagination)
     - Collapsible filter sections
     - Auto-hide filters on mobile after use
     - Optimized layouts for all screen sizes
   - Interactive CVE detail modal with:
     - Overview, Technical Details, Timeline, and References tabs
     - WCAG 2.1 AA accessibility compliance
     - Keyboard navigation (Esc to close, Alt+1-4 for tabs)
     - Focus management and screen reader support
   - **Enhanced Accessibility & UX**:
     - Comprehensive keyboard shortcuts (/, r, e, ←/→, 1-4, ?, Esc)
     - Screen reader announcements for filter results
     - High contrast mode support
     - Reduced motion preferences respected
     - CSV export functionality with analytics tracking

### Key Directories
- `scripts/` - Python vulnerability harvesting and processing scripts
  - `harvest/` - Data harvesting clients:
    - `orchestrator.py` - Main harvest orchestration
    - `cvelist_client.py` - CVEProject/cvelistV5 integration
    - `github_advisory_client.py` - GitHub Advisory Database
    - `epss_client.py` - EPSS API client
    - `nvd_client.py` - NVD API client
  - `agents/` - Modular enrichment and validation agents:
    - `deps_dev_enrichment_agent.py` - Package dependency analysis (deps.dev)
    - Data validation, cleanup, CISA KEV, exploit availability agents
  - `processing/` - Data processing and scoring:
    - `risk_scorer.py` - Risk score calculation (0-100)
    - `normalizer.py` - Data normalization
    - `briefing_generator.py` - Briefing generation
    - `cache_manager.py` - SQLite caching
  - `generate_alpine_dashboard.py` - Main dashboard generator (replaces 11ty)
  - `force_rebuild.py` - Force rebuild with validation
  - `ci_gatecheck.py` - CI/CD validation
- `src/` - Source templates and assets (used by Python generator)
  - `assets/ts/` - TypeScript components:
    - `components/` - CveModal, DataVisualization, SecurityAlerts, WidgetManager, etc.
    - `types/` - Type definitions
    - `analytics.ts` - Frontend analytics
    - `dashboard.ts` - Dashboard Alpine.js component
  - `api/` - API data templates (chunked JSON files)
- `public/` - Built static site (output directory, deployed to gh-pages)
- `tests/` - Test suite (391 tests, actual coverage: 6.37%)
  - `e2e/` - Playwright end-to-end tests for live site validation
  - `*.test.ts` - TypeScript unit tests (6 test files)
- `.github/workflows/` - CI/CD pipelines
  - `scheduled-harvest.yml` - Main harvest pipeline (incremental harvesting)
  - `post-deploy-qa.yml` - Post-deployment validation
  - `ci.yml` - CI checks (11ty removed)

### CI/CD Pipeline
- **Scheduled Build**: Runs harvesting every 4 hours (`.github/workflows/scheduled-harvest.yml`):
  - Pre-build cleanup to remove stale files
  - **Incremental harvesting** (default): Only CVEs updated in last 48 hours (~10-20 CVEs per run)
  - **Initial harvest**: EPSS-first filtering (~100 CVEs instead of 15,000)
  - Multi-stage data validation (raw, filtered, enriched, published)
  - CISA KEV and exploit availability enrichment
  - EPSS threshold compliance validation (fails on violations)
  - Python-based dashboard generation (no 11ty)
  - Post-build verification for stale files
  - Commits artifacts to main, deploys to gh-pages
- **Post-Deploy QA**: Automated Playwright tests (`.github/workflows/post-deploy-qa.yml`):
  - Validates live site data integrity
  - Ensures no CVEs below 60% EPSS
  - Checks threat intel enrichments render correctly
  - Fails if stale data detected
- **Quality Gates**:
  - **EPSS Threshold Compliance**: All vulnerabilities must meet ≥60% EPSS threshold
  - **Data Validation**: Multi-stage validation at ingestion, filtering, enrichment, and publication
  - Linting: Ruff (Python), ESLint (JavaScript)
  - Tests: 80% coverage target (actual: 6.37% due to legacy untested code)
  - Security: Bandit, npm audit
  - **Stale File Detection**: Verifies no outdated CVE pages remain
- **Automated Deployment**: GitHub Pages, blocked on threshold/validation failures

### API Keys Required
Environment secrets needed in GitHub Actions:
- `GITHUB_TOKEN` - GitHub API access (for cloning CVEProject/cvelistV5)
- `EPSS_API_KEY` - EPSS API access (optional, for enrichment)

### Testing Strategy
- **Python**: pytest with 80% coverage target (actual: 6.37% due to many untested legacy files)
  - 391 tests collected (2 import errors in legacy files)
  - New code has higher coverage, legacy code lacks tests
- **E2E**: Playwright tests for live site validation:
  - CVE count validation (≤60 expected after incremental harvesting)
  - EPSS threshold compliance (all ≥60%)
  - Threat intel flag rendering (CISA KEV, exploit badges)
  - API endpoint accessibility
  - No stale data detection
- **TypeScript**: 6 test files (`.test.ts`) for frontend components
  - No Vitest configuration (claimed but not implemented)
  - Tests use basic TypeScript setup
- **Data Quality**: Validation at each pipeline stage via agents
- **Security**: Bandit (Python), npm audit (JavaScript)
- **Linting**: Ruff (Python), ESLint with Google style guide (JavaScript)
- **Pre-commit**: Husky hooks enforce linting and formatting

### Deployment
- Static site deployed to GitHub Pages from `gh-pages` branch
- **Build System**: Python-based generation (11ty removed)
  - Always clean builds (no incremental mode)
  - `scripts/generate_alpine_dashboard.py` generates site
  - `scripts/force_rebuild.py` for validated rebuilds
- **GitHub Pages CDN Behavior**:
  - May cache files for 10-15 minutes after deployment
  - Use post-deployment validation to ensure propagation
  - Force refresh browsers after deployment
- No backend servers required - fully client-side Alpine.js functionality
- Coverage badges can be updated via `update-badge` command (if implemented)

### Troubleshooting Stale Data / 15,000+ CVE Issue
If the live site shows thousands of CVEs instead of ~60:
1. **Immediate Fix**: Run `npm run build:force` then `npm run deploy`
2. **Detailed Instructions**: See `docs/TROUBLESHOOTING.md`
3. **Root Cause**: Fixed by removing 11ty and implementing incremental harvesting
4. **Prevention**: Python generator always does clean builds
5. **Incremental Harvesting**: Default mode processes only recent CVEs (48-hour window)

## Performance Optimization Guide

### Frontend Performance Enhancements

#### 1. Debounced Search Implementation
```javascript
// Alpine.js component with debounced search
Alpine.data('vulnDashboard', () => ({
    searchQuery: '',
    // Use Alpine's built-in debounce modifier
    // In template: x-model.debounce.300ms="searchQuery"
}))
```

#### 2. Web Worker for Filtering
The dashboard automatically uses a Web Worker for datasets > 100 items:
```javascript
// Filtering logic runs in separate thread
if (this.vulnerabilities.length > 100 && window.Worker) {
    const results = await this.filterWithWorker(this.vulnerabilities, this.searchQuery, this.filters);
}
```

#### 3. Virtual Scrolling
Automatically enabled for datasets > 500 items:
```javascript
// Only renders visible rows
if (this.vulnerabilities.length > 500) {
    this.virtualScrolling.enabled = true;
}
```

#### 4. Session Storage Caching
5-minute TTL cache to minimize API calls:
```javascript
// Check cache before fetching
const cachedData = sessionStorage.getItem('vuln-data');
const cacheAge = Date.now() - parseInt(sessionStorage.getItem('vuln-data-timestamp'));
if (cachedData && cacheAge < 5 * 60 * 1000) {
    return JSON.parse(cachedData);
}
```

### Backend Performance Tips

#### 1. Chunked Data Strategy
```python
# Generate chunked files by severity and year
python -m scripts.main generate-briefing --storage-strategy severity-year
```

#### 2. SQLite Cache Usage
```python
# Cache manager with 10-day TTL
cache_manager = CacheManager(cache_dir=".cache", ttl_days=10)
```

#### 3. Great Expectations Integration
```python
# Run validation without blocking pipeline
python scripts/integrate_gx_validation.py --enable-validation
```

### Performance Benchmarks

Run performance tests:
```bash
# Frontend performance with Lighthouse
npm run lighthouse

# Backend processing time
time python -m scripts.main harvest --cache-dir .cache/

# E2E performance tests
pytest tests/playwright_live_test.py -v
```

### Common Performance Issues

1. **Slow Search/Filter**: Ensure debouncing is enabled and Web Worker is functioning
2. **High Memory Usage**: Check if virtual scrolling is enabled for large datasets
3. **Slow Page Load**: Verify chunked storage strategy is active
4. **API Rate Limits**: Check cache hit rates and TTL configuration

## 🚨 Critical Production Issues & Solutions

### The 15,000+ CVE Data Issue (Resolved)

**Problem**: Production site was showing 15,000+ CVEs instead of the expected ~30 CVEs after implementing EPSS 60% threshold filtering.

**Root Cause**: 
- Incremental builds were preserving stale data files
- GitHub Pages caching prevented proper cleanup
- Static site generators accumulated files over multiple deployments

**Critical Solution** (Implemented):
```bash
# Use force rebuild command (always clean)
npm run build:force
# Or manually:
python -m scripts.force_rebuild --expected-count 60 --min-epss 0.6
```

**Prevention Measures** (Implemented):
1. **Removed 11ty**: Eliminated incremental build issues
2. **Incremental Harvesting**: Process only recent CVEs (48-hour window)
3. **CI/CD Gatecheck**: All deployments pass validation (`scripts/ci_gatecheck.py`)
4. **Live Site Monitoring**: Post-deployment Playwright tests
5. **EPSS-First Filtering**: Initial harvest ~100 CVEs instead of 15,000

### Critical Validation Commands

```bash
# Pre-deployment validation (REQUIRED)
python -m scripts.ci_gatecheck \
  --api-dir public/api \
  --max-cve-count 1000 \
  --expected-cve-count 60 \
  --min-epss 0.6 \
  --fail-on-warnings

# Post-deployment validation (automated)
pytest tests/e2e/test_live_site_sanity.py -v

# Emergency force rebuild (if 15,000+ issue detected)
python -m scripts.force_rebuild \
  --expected-count 60 \
  --min-epss 0.6
```

### Developer Guidelines

**❌ NEVER DO**:
- ~~Use incremental builds~~ (11ty removed, not applicable)
- Deploy without running gatecheck validation
- Ignore CVE count warnings in CI/CD
- Bypass EPSS threshold validation

**✅ ALWAYS DO**:
- Use `npm run build` or `npm run build:force` for builds
- Run `npm run validate` before deployment
- Check live site counts after deployment
- Monitor post-deployment QA test results

### Emergency Response

If production shows >1000 CVEs:

1. **Immediate**: Run force rebuild script
   ```bash
   npm run build:force
   ```
2. **Validate**: Check gatecheck passes locally
   ```bash
   npm run validate
   ```
3. **Deploy**: Force push to gh-pages branch
   ```bash
   npm run deploy
   ```
4. **Monitor**: Wait 10+ minutes for CDN propagation
5. **Confirm**: Run live site validation tests
   ```bash
   npm run test:e2e
   ```

📋 **For detailed troubleshooting procedures, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)**