# Vuln-Bot

![Coverage](https://img.shields.io/badge/coverage-6%25-red)
![CI](https://github.com/williamzujkowski/vuln-bot/actions/workflows/ci.yml/badge.svg)
![Quality Gates](https://github.com/williamzujkowski/vuln-bot/actions/workflows/quality-gates.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

🤖 A high-risk CVE intelligence platform that tracks Critical & High severity vulnerabilities with EPSS ≥ 60% exploitation probability. Automatically harvests, scores, and publishes vulnerability briefings every 4 hours using the official CVEProject/cvelistV5 repository.

## Features

- 🎯 **High-Risk Focus**: Filters for EPSS ≥ 60% exploitation probability using authoritative FIRST.org data
- 🔍 **Multiple Data Sources**: Official CVEProject/cvelistV5 repository, GitHub Security Advisory Database, CISA KEV catalog, and EPSS enrichment
- 🧠 **SSVC Decision Framework**: Stakeholder-Specific Vulnerability Categorization with ACT/ATTEND/TRACK prioritization tiers
- 📊 **Risk Scoring**: Calculates weighted scores based on CVSS, EPSS, popularity, infrastructure tags, and exploit availability
- 💾 **Optimized Storage**: Chunked data storage by severity-year with efficient client-side loading
- 🚀 **Python-Based Generation**: Fast Alpine.js dashboard with single-page application architecture
- 🔎 **Advanced Filtering**: Client-side search with SSVC priority filters, CVSS/EPSS sliders, keyboard shortcuts, and shareable URLs
- 📈 **Data Visualization**: Canvas-based charts for severity distribution, risk trends, EPSS analysis, and vendor risk assessment
- 📱 **Mobile-First Design**: Touch gestures, responsive layouts, and collapsible interfaces for all screen sizes
- 📋 **Interactive CVE Details**: Accessible modal with Overview, Technical Details, Timeline, References, and SSVC Decision tabs
- 🤖 **Incremental Harvesting**: Processes only recent CVEs for faster updates with EPSS-first filtering
- 🔒 **Security First**: Comprehensive CI/CD with Bandit, CodeQL, dependency scanning, and data validation gates

## Quick Start

### Prerequisites

- Python 3.8+ with [uv](https://github.com/astral-sh/uv)
- Node.js 18+ LTS
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/williamzujkowski/vuln-bot.git
cd vuln-bot

# Install Python dependencies
uv pip install -r requirements.txt

# Install Node dependencies
npm install

# Set up pre-commit hooks
npm run prepare
```

### Local Development

```bash
# Run the vulnerability harvester
python -m scripts.main harvest --cache-dir .cache/

# Generate a briefing (uses chunked storage by default)
python -m scripts.main generate-briefing

# Specify storage strategy explicitly
python -m scripts.main generate-briefing --storage-strategy severity-year

# Update coverage badge (for CI/CD)
python -m scripts.main update-badge

# Send vulnerability alerts (requires webhook configuration)
python -m scripts.main send-alerts --risk-threshold 80

# Build and serve the site locally
npm run serve
```

Visit http://localhost:8000 to view the dashboard.

### Keyboard Shortcuts

The dashboard supports keyboard shortcuts for improved productivity:

- `/` - Focus search input
- `r` - Reset all filters
- `e` - Export results as CSV
- `←` `→` - Navigate between pages
- `1`-`4` - Set page size (10, 20, 50, 100)
- `?` - Show keyboard shortcuts help
- `Esc` - Close help modal or CVE details modal

When viewing CVE details:
- `Alt+1` through `Alt+5` - Switch between tabs (Overview, Technical, Timeline, References, SSVC)
- `Tab` - Navigate through interactive elements (focus trapped within modal)

When viewing data visualization charts:
- `←` `→` - Navigate between chart types (Overview, Trend, EPSS, Vendor)
- `Home` - Jump to Overview chart
- `End` - Jump to Vendor Risk chart
- Charts include screen reader announcements and descriptions

## Configuration

### Required API Keys

Set these as GitHub repository secrets:

- `GITHUB_TOKEN` - GitHub API access (for cloning CVEProject/cvelistV5)
- `EPSS_API_KEY` - EPSS API access (optional, for enrichment)

### Optional Webhooks

For alert notifications (feature-flagged):

- `SLACK_WEBHOOK` - Slack incoming webhook URL
- `TEAMS_WEBHOOK` - Microsoft Teams webhook URL
- Set repository variable `SEND_ALERTS=true` to enable

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ CVE Sources     │────▶│ EPSS ≥ 60%       │────▶│ Risk Scoring &  │
│ (CVEProject)    │     │ Filter + SSVC    │     │ SSVC Decision   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ Data Validation  │────▶│ Chunked Storage │
                        │ Gates            │     │ (by severity/yr) │
                        └──────────────────┘     └─────────────────┘
                                │                          │
                                ▼                          ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ SQLite Cache     │     │ Alpine.js       │
                        │ (10-day TTL)     │     │ Dashboard       │
                        └──────────────────┘     └─────────────────┘
                                │                          │
                                ▼                          ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ Incremental      │     │ GitHub Pages    │
                        │ Harvesting       │     │ Deployment      │
                        └──────────────────┘     └─────────────────┘
```

## Development

### Running Tests

```bash
# Python tests with coverage
pytest --cov=scripts --cov-report=term

# Run Playwright E2E tests for live site validation
pytest tests/e2e/test_live_site_sanity.py -v

# JavaScript linting
npm run lint

# Format code
npm run format
```

### Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions/modifications
- `chore:` Maintenance tasks

### Project Structure

```
vuln-bot/
├── scripts/                      # Python harvesting and processing
│   ├── harvest/                 # API client implementations
│   │   ├── orchestrator.py     # Main harvest orchestration
│   │   ├── cvelist_client.py   # CVEProject/cvelistV5 integration
│   │   ├── epss_client.py      # EPSS API client
│   │   └── nvd_client.py       # NVD API client
│   ├── processing/              # Data processing and scoring
│   │   ├── risk_scorer.py      # Risk score calculation (0-100)
│   │   ├── ssvc_calculator.py  # SSVC decision tree
│   │   ├── normalizer.py       # Data normalization
│   │   └── cache_manager.py    # SQLite caching
│   ├── agents/                  # Modular enrichment agents
│   │   └── deps_dev_enrichment_agent.py # Package analysis
│   └── generate_alpine_dashboard.py # Main dashboard generator
├── public/                      # Built static site (deployed to gh-pages)
│   ├── api/vulns/              # Chunked JSON API files
│   └── index.html              # Alpine.js dashboard
├── src/                        # Source templates and assets
│   ├── api/                    # API data templates
│   └── assets/                 # Frontend assets
│       ├── css/               # Stylesheets
│       └── ts/                # TypeScript components
├── tests/                      # Test suite
│   ├── e2e/                   # Playwright end-to-end tests
│   └── *.test.ts              # TypeScript unit tests
└── .github/workflows/         # CI/CD pipelines
    ├── ci.yml                 # Main CI checks
    ├── quality-gates.yml      # Quality gate enforcement
    └── scheduled-harvest.yml  # Automated harvesting
```

## API Documentation

### Vulnerability Index

`GET /api/vulns/index.json`

Returns a consolidated search index of all vulnerabilities with EPSS ≥ 60%.

### Chunked Vulnerability Data

`GET /api/vulns/chunk-index.json`

Returns an index of available data chunks organized by severity and year.

`GET /api/vulns/vulns-{year}-{severity}.json`

Returns vulnerability data for a specific year and severity level. Examples:
- `/api/vulns/vulns-2024-CRITICAL.json`
- `/api/vulns/vulns-2024-HIGH.json`
- `/api/vulns/vulns-2025-CRITICAL.json`

Each chunk includes:
- CVSS vectors and scores
- EPSS probability (≥ 60%)
- CPE configurations
- References and patches
- ATT&CK mappings

### Syndication Feeds

- **RSS Feed**: `/feed.xml` - Latest vulnerability briefings in RSS 2.0 format
- **Atom Feed**: `/atom.xml` - Latest vulnerability briefings in Atom 1.0 format

Both feeds include the 10 most recent briefings with summary statistics and top affected vendors.

## Performance

### Dashboard Performance Optimizations

The dashboard implements several performance optimizations for responsive user experience:

- **Debounced Search**: Uses Alpine.js debounce modifier to prevent excessive search operations
- **Web Worker Filtering**: Offloads filtering logic to a Web Worker for larger datasets, keeping the main thread responsive
- **Virtual Scrolling**: Automatically enabled for large datasets, rendering only visible rows
- **Session Storage Caching**: Temporary cache for vulnerability data to reduce network requests
- **Memoized Computations**: Frequently calculated values (risk scores, date formatting) are cached
- **Request Animation Frame**: Chart updates and DOM manipulations are batched for smooth rendering

### Backend Performance

- **Incremental Harvesting**: Processes only recently updated CVEs (48-hour window) for faster updates
- **EPSS-First Filtering**: Initial harvest focuses on high-probability threats, filtering early in the pipeline
- **Chunked Storage**: Data organized by severity and year for efficient loading
- **SQLite Caching**: 10-day TTL cache reduces redundant API calls
- **CI Optimization**: Dependency and browser caching for faster build times

## Data Validation

The platform implements comprehensive data validation at multiple stages:

### Validation Stages

1. **Ingestion Stage**: Validates raw CVE data structure, required fields, and data types
2. **EPSS Threshold Gate**: Enforces EPSS ≥ 60% filtering with CI/CD validation
3. **Enrichment Stage**: Validates CISA KEV data, exploit availability, and SSVC decision outputs
4. **Publication Stage**: Multi-stage validation ensures API data quality before deployment

### Schema Compliance

- Adherence to CVE Schema v5.1 specification
- CVSS vector and score validation
- EPSS probability range validation (0-1.0)
- Date format compliance (ISO 8601)
- SSVC decision tree validation for all prioritization outputs

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Testing Requirements

- All tests must pass before merging
- Security scans must pass (Bandit for Python, npm audit for JavaScript)
- CodeQL analysis required for security-sensitive changes
- E2E tests validate live site functionality after deployment
- CI enforces quality gates including linting, formatting, and test execution

## Releases

This project uses automated releases via GitHub Actions. To create a new release:

```bash
# Bump version (patch/minor/major)
python scripts/bump_version.py patch

# Push changes and tag
git push origin main
git push origin v1.0.1
```

See [Release Process](docs/RELEASE.md) for details.

## Security

- All dependencies are regularly scanned for vulnerabilities
- Security issues are tracked via GitHub Security Advisories
- Report security vulnerabilities to [security@example.com]

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- CVE.org for vulnerability data
- FIRST for EPSS scores
- GitHub Security Advisory Database
- All vulnerability data providers