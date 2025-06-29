# Morning Vuln Briefing

![Coverage](https://img.shields.io/badge/coverage-63%25-yellow)
![CI](https://github.com/williamzujkowski/vuln-bot/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

An automated vulnerability intelligence platform that harvests, scores, and publishes vulnerability briefings every 4 hours using the official CVEProject/cvelistV5 repository. Focuses on Critical and High severity CVEs from 2024-2025 with EPSS scores above 60%.

## Features

- 🔍 **Official CVE Data**: Uses CVEProject/cvelistV5 repository (updated every 7 minutes) with EPSS enrichment and CISA-ADP container data
- 📊 **Risk Scoring**: Calculates weighted scores (0-100) based on CVSS, EPSS, popularity, and infrastructure tags
- 🚀 **Static Site Generation**: Uses 11ty to generate fast, SEO-friendly briefings
- 🔎 **Advanced Filtering**: Client-side dashboard with instant search, CVSS/EPSS sliders, keyboard shortcuts, and shareable views
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

# Generate a briefing
python -m scripts.main generate-briefing

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
- `Esc` - Close help modal

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
│ Vulnerability   │────▶│ Risk Scoring &   │────▶│ Static Site     │
│ Sources (APIs)  │     │ Normalization    │     │ Generation      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │                          │
                                ▼                          ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ SQLite Cache     │     │ GitHub Pages    │
                        │ (10-day TTL)     │     │ (public/)       │
                        └──────────────────┘     └─────────────────┘
```

## Development

### Running Tests

```bash
# Python tests with coverage
pytest

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
│   └── assets/         # CSS, JS, and static files
├── tests/              # Python test suite
└── .github/workflows/  # CI/CD pipelines
```

## API Documentation

### Vulnerability Index

`GET /api/vulns/index.json`

Returns a consolidated search index of all vulnerabilities.

### Vulnerability Details

`GET /api/vulns/{cveId}.json`

Returns detailed information for a specific CVE including:
- CVSS vectors and scores
- EPSS probability
- CPE configurations
- References and patches
- ATT&CK mappings

### Syndication Feeds

- **RSS Feed**: `/feed.xml` - Latest vulnerability briefings in RSS 2.0 format
- **Atom Feed**: `/atom.xml` - Latest vulnerability briefings in Atom 1.0 format

Both feeds include the 10 most recent briefings with summary statistics and top affected vendors.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

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