# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is "Vuln-Bot" - a high-risk CVE intelligence platform that tracks Critical & High severity vulnerabilities with EPSS ≥ 70% exploitation probability. It automatically harvests, scores, and publishes vulnerability briefings every 4 hours. It's a multi-language project using Python for backend data processing and JavaScript/11ty for the static site generation and frontend.

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

# Run Python linting (Ruff)
ruff check scripts/
ruff format scripts/

# Run Python tests with coverage
pytest --cov=scripts --cov-report=html --cov-report=term tests/

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
   - Fetches from CVEProject/cvelistV5 repository (official CVE List, updated every 7 minutes)
   - Filters for Critical/High severity CVEs from 2024-2025 with EPSS scores ≥ 70%
   - Enriches with EPSS API data and CISA-ADP container information (KEV/SSVC)
   - Normalizes data and calculates Risk Score (0-100) based on CVSS, EPSS, popularity, infrastructure tags, and newness
   - Caches responses in SQLite using GitHub Actions cache (10-day TTL)

2. **Content Generation** (11ty in `src/`):
   - Creates briefing posts at `_posts/{{date}}-vuln-brief.md` using Nunjucks templates
   - Generates chunked vulnerability data files at `api/vulns/vulns-{{year}}-{{severity}}.json`
   - Builds consolidated search index at `api/vulns/index.json`
   - Creates chunk index at `api/vulns/chunk-index.json` for navigation

3. **Frontend** (Alpine.js + Fuse.js):
   - Client-side filtering UI on the homepage
   - Real-time search/filter on: CVE ID, severity, CVSS/EPSS scores, date ranges, vendors, exploitation status
   - URL hash-based state for shareable filtered views
   - Paginated results (10/20/50/100 rows, default 50)

### Key Directories
- `scripts/` - Python vulnerability harvesting and processing scripts
- `src/` - 11ty source files (templates, posts, API generation)
- `public/` - Built static site (deployed to gh-pages)
- `tests/` - Python test suite
- `.github/workflows/` - CI/CD pipelines

### CI/CD Pipeline
- **Scheduled Build**: Runs harvesting every 4 hours, generates content, commits artifacts to main, deploys to gh-pages
- **PR Checks**: Linting (Ruff, ESLint), tests (≥80% coverage), security scans (Bandit, TruffleHog, CodeQL)
- **Security**: npm-audit for dependencies, automated vulnerability scanning

### API Keys Required
Environment secrets needed in GitHub Actions:
- `GITHUB_TOKEN` - GitHub API access (for cloning CVEProject/cvelistV5)
- `EPSS_API_KEY` - EPSS API access (optional, for enrichment)

### Testing Strategy
- Python: pytest with 80% minimum coverage requirement
- Security: Bandit (high+ severities fail), TruffleHog for secrets
- JavaScript: ESLint with Google style guide, Prettier formatting
- All checks enforced via Husky pre-commit hooks and GitHub Actions

### Deployment
- Static site deployed to GitHub Pages from `gh-pages` branch
- No backend servers required - fully client-side functionality
- Coverage badges auto-updated in README via Shields.io