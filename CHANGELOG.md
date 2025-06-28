# Changelog

All notable changes to the Morning Vuln Briefing project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-06-28

### Added
- Initial release of Morning Vuln Briefing platform
- Automated vulnerability harvesting from CVEProject/cvelistV5
- EPSS score enrichment for exploit prediction
- Custom risk scoring algorithm (0-100 scale)
- Static site generation with 11ty
- Real-time client-side filtering with Alpine.js
- TypeScript migration for type-safe frontend
- WCAG 2.1 AA accessibility compliance
- Privacy-respecting analytics system
- GitHub Actions CI/CD pipeline
- Nightly automated harvesting workflow
- SQLite-based caching with 10-day TTL
- CSV export functionality
- Shareable URL filters via hash parameters
- Comprehensive test suite (80%+ coverage)
- Security scanning (Bandit, TruffleHog, CodeQL)
- Metrics collection and monitoring
- GitHub Pages deployment
- Project metadata (MANIFEST.yaml)
- Contributing guidelines

### Security
- No secrets in code - all sensitive data in environment variables
- Input validation on all user inputs
- Content Security Policy headers
- Dependency scanning via npm audit

### Performance
- Client-side filtering for instant results
- Optimized search with Fuse.js
- Lazy loading of vulnerability data
- Webpack bundle optimization
- CDN delivery via GitHub Pages

## [Unreleased]

### Planned
- Additional vulnerability sources (GitHub Advisory, OSV)
- Email notification system
- RSS feed generation
- API rate limit handling improvements
- Advanced analytics dashboard
- Multi-language support
- Dark mode theme
- Vulnerability timeline visualization
- Integration with security tools
- Webhook notifications

---

For a detailed list of changes, see the [commit history](https://github.com/wclaytor/vuln-bot/commits/main).