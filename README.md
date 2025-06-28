# Morning Vuln Briefing

![Coverage](https://img.shields.io/badge/coverage-43%25-yellow)
![CI](https://github.com/yourusername/vuln-bot/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

An automated vulnerability intelligence platform that harvests, scores, and publishes daily vulnerability briefings using the official CVEProject/cvelistV5 repository. Focuses on Critical and High severity CVEs from 2025 onwards with EPSS scores above 60%.

## Features

- 🔍 **Official CVE Data**: Uses CVEProject/cvelistV5 repository (updated every 7 minutes) with EPSS enrichment and CISA-ADP container data
- 📊 **Risk Scoring**: Calculates weighted scores (0-100) based on CVSS, EPSS, popularity, and infrastructure tags
- 🚀 **Static Site Generation**: Uses 11ty to generate fast, SEO-friendly briefings
- 🔎 **Advanced Filtering**: Client-side dashboard with instant search, CVSS/EPSS sliders, and shareable views
- 🤖 **Fully Automated**: Nightly harvesting with zero manual intervention required
- 🔒 **Security First**: Comprehensive CI/CD with Bandit, CodeQL, and dependency scanning

## Quick Start

### Prerequisites

- Python 3.8+ with [uv](https://github.com/astral-sh/uv)
- Node.js 18+ LTS
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vuln-bot.git
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

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

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