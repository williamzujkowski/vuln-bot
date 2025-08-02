# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is "Vuln-Bot" - a high-risk CVE intelligence platform that tracks Critical & High severity vulnerabilities with EPSS ≥ 60% exploitation probability. It automatically harvests, scores, and publishes vulnerability briefings every 4 hours. It's a multi-language project using Python for backend data processing and JavaScript/11ty for the static site generation and frontend.

## Common Development Commands

### Python Development
```bash
# Install Python dependencies (using uv)
uv pip install -r requirements.txt

# Run the vulnerability harvester
python -m scripts.main harvest --cache-dir .cache/

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

### JavaScript/11ty Development
```bash
# Install Node dependencies
npm install

# CRITICAL: Build the 11ty site (ALWAYS use non-incremental builds)
# Incremental builds cause stale data persistence, leading to 15,000+ CVE issues
rm -rf _site public && npm run build

# NEVER use incremental builds in production:
# BAD:  npx eleventy --incremental
# GOOD: npx eleventy (clean build)
npm run build

# Serve the site locally with hot reload
npm run serve

# Run ESLint (Google style guide)
npm run lint

# Run Prettier formatting
npm run format

# Run all pre-commit checks
npm run precommit
```

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
     - deps.dev package impact analysis for supply chain visibility
     - Reference categorization (exploit, patch, advisory, vendor, technical)
   - Normalizes data and calculates Risk Score (0-100) based on CVSS, EPSS, popularity, infrastructure tags, and newness
   - **Data validation** at each stage (raw, filtered, enriched, published)
   - Caches responses in SQLite using GitHub Actions cache (10-day TTL, timezone-aware)

2. **Content Generation** (11ty in `src/`):
   - Creates briefing posts at `_posts/{{date}}-vuln-brief.md` using Nunjucks templates
   - Generates chunked vulnerability data files at `api/vulns/vulns-{{year}}-{{severity}}.json`
   - Builds consolidated search index at `api/vulns/index.json`
   - Creates chunk index at `api/vulns/chunk-index.json` for navigation

3. **Frontend** (Alpine.js + Fuse.js + TypeScript):
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
  - `agents/` - Modular agents for enrichment and validation:
    - `cisa_kev_agent.py` - CISA Known Exploited Vulnerabilities enrichment
    - `exploit_availability_agent.py` - Exploit detection and EPSS percentiles
    - `deps_dev_enrichment_agent.py` - Package dependency analysis
    - `data_validation_agent.py` - Multi-stage data quality validation
    - `cleanup_agent.py` - Stale file removal and verification
    - `threshold_compliance_agent.py` - EPSS threshold enforcement
    - `data_quality_report_agent.py` - Comprehensive data quality reporting
- `src/` - 11ty source files (templates, posts, API generation)
- `src/assets/ts/` - TypeScript components and types
  - `components/` - Reusable UI components (CveModal, DataVisualization)
  - `types/` - TypeScript type definitions
  - `analytics.ts` - Frontend analytics and tracking
  - `dashboard.ts` - Main vulnerability dashboard Alpine.js component
- `src/assets/css/` - Stylesheets with design tokens and component styles
  - `mobile-optimizations.css` - Mobile-first responsive enhancements (40% density improvement)
- `public/` - Built static site (deployed to gh-pages)
- `tests/` - Python test suite (85%+ coverage)
  - `e2e/` - Playwright end-to-end tests for live site validation
- `.github/workflows/` - CI/CD pipelines
  - `scheduled-harvest.yml` - Main harvest pipeline with enrichment and validation
  - `post-deploy-qa.yml` - Automated post-deployment quality assurance

### CI/CD Pipeline
- **Scheduled Build**: Runs harvesting every 4 hours with comprehensive pipeline:
  - Pre-build cleanup to remove stale files
  - Data harvesting with 60% EPSS threshold enforcement
  - Multi-stage data validation (raw, filtered, enriched, published)
  - CISA KEV and exploit availability enrichment
  - EPSS threshold compliance validation (fails on violations)
  - Incremental static site generation
  - Post-build verification for stale files
  - Commits artifacts to main, deploys to gh-pages
- **Post-Deploy QA**: Automated Playwright tests run after deployment:
  - Validates live site data integrity
  - Ensures no CVEs below 60% EPSS
  - Checks threat intel enrichments render correctly
  - Fails if stale data detected
- **Quality Gates**: 
  - **EPSS Threshold Compliance**: Validates all vulnerabilities meet ≥60% EPSS threshold (CI/CD gating)
  - **Data Validation**: Multi-stage validation at ingestion, filtering, enrichment, and publication
  - Linting: Ruff, ESLint (zero errors)
  - Tests: ≥80% coverage requirement
  - Security: Bandit, TruffleHog, CodeQL, npm audit
  - **Stale File Detection**: Verifies no outdated CVE pages remain
- **Automated Deployment**: GitHub Pages with incremental builds, blocked on threshold/validation failures

### API Keys Required
Environment secrets needed in GitHub Actions:
- `GITHUB_TOKEN` - GitHub API access (for cloning CVEProject/cvelistV5)
- `EPSS_API_KEY` - EPSS API access (optional, for enrichment)

### Testing Strategy
- Python: pytest with 80% minimum coverage requirement
- E2E: Playwright tests for live site validation:
  - CVE count validation (≤30 expected)
  - EPSS threshold compliance (all ≥60%)
  - Threat intel flag rendering (CISA KEV, exploit badges)
  - API endpoint accessibility
  - No stale data detection
- Data Quality: Validation at each pipeline stage
- Security: Bandit (high+ severities fail), TruffleHog for secrets
- JavaScript: ESLint with Google style guide, Prettier formatting
- All checks enforced via Husky pre-commit hooks and GitHub Actions

### Deployment
- Static site deployed to GitHub Pages from `gh-pages` branch
- **IMPORTANT**: GitHub Pages may cache stale files. When EPSS threshold changes:
  - Force clean build: `rm -rf _site public` before building
  - Use force push to gh-pages: `git push origin gh-pages --force-with-lease`
  - Clear GitHub Pages cache by toggling source in Settings
- No backend servers required - fully client-side functionality
- Coverage badges auto-updated in README via the `update-badge` command
- Webhook alerts supported for Slack/Teams notifications

### Troubleshooting Stale Data
If the live site shows thousands of CVEs instead of ~30:
1. Check `docs/TROUBLESHOOTING.md` for detailed fix
2. Run force rebuild: `python -m scripts.agents.build_deploy_agent`
3. Verify with: `pytest tests/e2e/test_live_site_sanity.py`

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

**Critical Solution**:
```bash
# ALWAYS use complete rebuilds to prevent stale data
rm -rf _site public
python -m scripts.generate_alpine_dashboard  # Clean generation
# NEVER use --incremental flag on 11ty builds
```

**Prevention Measures**:
1. **Mandatory CI/CD Gatecheck**: All deployments must pass strict validation
2. **Non-Incremental Builds**: Force complete rebuilds every time
3. **Live Site Monitoring**: Automated detection of 15,000+ CVE issues
4. **Force Purge Strategy**: Complete directory cleanup before builds

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
- Use incremental builds in production (`--incremental`)
- Deploy without running gatecheck validation
- Ignore CVE count warnings in CI/CD
- Assume data is correct without validation

**✅ ALWAYS DO**:
- Run complete clean builds (`rm -rf _site public`)
- Validate data before deployment
- Check live site counts after deployment
- Monitor for 15,000+ CVE alerts

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