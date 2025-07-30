# Vuln-Bot

![Coverage](https://img.shields.io/badge/coverage-80%25-green)
![CI](https://github.com/williamzujkowski/vuln-bot/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

🤖 A high-risk CVE intelligence platform that tracks Critical & High severity vulnerabilities with EPSS ≥ 70% exploitation probability. Automatically harvests, scores, and publishes vulnerability briefings every 4 hours using the official CVEProject/cvelistV5 repository.

## Features

- 🎯 **High-Risk Focus**: Filters for EPSS ≥ 70% - only the most likely exploited vulnerabilities
- 🔍 **Multiple Data Sources**: CVEProject/cvelistV5 repository and GitHub Security Advisory Database with EPSS enrichment and CISA-ADP container data
- 📊 **Risk Scoring**: Calculates weighted scores (0-100) based on CVSS, EPSS, popularity, and infrastructure tags
- 💾 **Optimized Storage**: Chunked data storage by severity-year reducing 33,000+ individual files to ~7 chunks
- 🚀 **Static Site Generation**: Uses 11ty to generate fast, SEO-friendly briefings
- 🔎 **Advanced Filtering**: Client-side dashboard with instant search, CVSS/EPSS sliders, keyboard shortcuts, and shareable views
- 📈 **Data Visualization Dashboard**: Interactive Canvas-based charts showing severity distribution, risk trends, EPSS ranges, and vendor analysis with accessibility support
- 📱 **Mobile-First Design**: Touch gestures, responsive layouts, and collapsible interfaces optimized for all devices
- 📋 **Interactive CVE Details**: Click any CVE ID to view detailed information in an accessible modal with technical details, timeline, and references
- 📡 **RSS/Atom Feeds**: Subscribe to vulnerability briefings via RSS or Atom feeds
- 🤖 **Fully Automated**: Harvesting every 4 hours with zero manual intervention required
- 🔒 **Security First**: Comprehensive CI/CD with Bandit, CodeQL, and dependency scanning

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

Visit http://localhost:8080 to view the dashboard.

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
- `Alt+1` through `Alt+4` - Switch between tabs (Overview, Technical, Timeline, References)
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
│ CVE Sources     │────▶│ EPSS ≥ 70%       │────▶│ Risk Scoring &  │
│ (CVEProject)    │     │ Filter           │     │ Normalization   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ Chunked Storage  │────▶│ Static Site     │
                        │ (by severity/yr) │     │ Generation      │
                        └──────────────────┘     └─────────────────┘
                                │                          │
                                ▼                          ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ SQLite Cache     │     │ GitHub Pages    │
                        │ (10-day TTL)     │     │ (vuln-bot/)     │
                        └──────────────────┘     └─────────────────┘
```

## Development

### Running Tests

```bash
# Python tests with coverage (currently 88%)
pytest --cov=scripts --cov-report=term

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
├── scripts/              # Python harvesting and processing
│   ├── harvest/         # API client implementations
│   └── processing/      # Data normalization and scoring
├── src/                 # 11ty source files
│   ├── _posts/         # Generated vulnerability briefings
│   ├── api/            # JSON API endpoints
│   └── assets/         # Frontend assets and components
│       ├── ts/         # TypeScript components and types
│       │   ├── components/ # UI components (CveModal, DataVisualization)
│       │   ├── types/     # TypeScript type definitions
│       │   ├── analytics.ts # Frontend analytics
│       │   └── dashboard.ts # Main dashboard component
│       ├── css/        # Stylesheets with design tokens
│       └── js/         # Compiled JavaScript output
├── tests/              # Python test suite
└── .github/workflows/  # CI/CD pipelines
```

## API Documentation

### Vulnerability Index

`GET /api/vulns/index.json`

Returns a consolidated search index of all vulnerabilities with EPSS ≥ 70%.

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
- EPSS probability (≥ 70%)
- CPE configurations
- References and patches
- ATT&CK mappings

### Syndication Feeds

- **RSS Feed**: `/feed.xml` - Latest vulnerability briefings in RSS 2.0 format
- **Atom Feed**: `/atom.xml` - Latest vulnerability briefings in Atom 1.0 format

Both feeds include the 10 most recent briefings with summary statistics and top affected vendors.

## Performance

- **Harvesting**: ~120x faster using GitHub releases vs individual API calls
- **Dataset**: Processes 30,000+ vulnerabilities, filters to ~250-500 with EPSS ≥ 70%
- **Storage**: Optimized from 33,000+ individual files to ~8 chunked files
- **Display**: Shows filtered high-risk vulnerabilities with 50 per page by default

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Testing Requirements

- Minimum test coverage: 80% (CI enforced)
- Current test coverage: 88%
- All tests must pass before merging
- Security scans must pass (Bandit, CodeQL)

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