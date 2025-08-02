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

# Run Python linting (Ruff)
ruff check scripts/
ruff format scripts/

# Run Python tests with coverage
pytest --cov=scripts --cov-report=html --cov-report=term tests/

# Run Python E2E tests with Playwright
pip install pytest-playwright playwright
playwright install --with-deps chromium
python -m pytest tests/e2e/ -m e2e --verbose

# Run security checks
bandit -r scripts/ -ll
```

### JavaScript/11ty Development
```bash
# Install Node dependencies
npm install

# Build the 11ty site
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
   - Fetches from multiple sources:
     - CVEProject/cvelistV5 repository (official CVE List, updated every 7 minutes)
     - GitHub Security Advisory Database (via GraphQL API)
   - Filters for Critical/High severity CVEs from 2024-2025 with EPSS scores ≥ 60%
   - Enriches with EPSS API data and CISA-ADP container information (KEV/SSVC)
   - Normalizes data and calculates Risk Score (0-100) based on CVSS, EPSS, popularity, infrastructure tags, and newness
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
- `src/` - 11ty source files (templates, posts, API generation)
- `src/assets/ts/` - TypeScript components and types
  - `components/` - Reusable UI components (CveModal, DataVisualization)
  - `types/` - TypeScript type definitions
  - `analytics.ts` - Frontend analytics and tracking
  - `dashboard.ts` - Main vulnerability dashboard Alpine.js component
- `src/assets/css/` - Stylesheets with design tokens and component styles
- `public/` - Built static site (deployed to gh-pages)
- `tests/` - Python test suite (90%+ coverage)
- `great_expectations/` - Data validation suites and checkpoints
- `.github/workflows/` - CI/CD pipelines

### CI/CD Pipeline
- **Scheduled Build**: Runs harvesting every 4 hours, generates content, commits artifacts to main, deploys to gh-pages
- **Quality Gates**: 
  - **EPSS Threshold Compliance**: Validates all vulnerabilities meet ≥60% EPSS threshold (CI/CD gating)
  - Linting: Ruff, ESLint, Black, isort (zero errors)
  - Tests: ≥90% coverage, no skipped tests
  - Security: Bandit, TruffleHog, CodeQL, npm audit
  - Performance: Lighthouse CI (≥80% score), bundle size checks (<500KB)
  - Data Validation: Great Expectations checkpoints
- **Automated Deployment**: GitHub Pages with incremental builds, blocked on threshold violations

### API Keys Required
Environment secrets needed in GitHub Actions:
- `GITHUB_TOKEN` - GitHub API access (for cloning CVEProject/cvelistV5)
- `EPSS_API_KEY` - EPSS API access (optional, for enrichment)

### Testing Strategy
- Python: pytest with 90% minimum coverage requirement (enforced)
- E2E: Playwright tests for critical user flows (conditional on installation)
- Security: Bandit (medium+ severities fail), TruffleHog for secrets
- JavaScript: ESLint with Google style guide, Prettier formatting
- Performance: Search latency < 100ms, page load < 2s FCP
- All checks enforced via Husky pre-commit hooks and GitHub Actions

### Deployment
- Static site deployed to GitHub Pages from `gh-pages` branch
- No backend servers required - fully client-side functionality
- Coverage badges auto-updated in README via the `update-badge` command
- Webhook alerts supported for Slack/Teams notifications

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