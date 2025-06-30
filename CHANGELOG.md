# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Security Advisory Database as an additional vulnerability data source
  - Implemented GraphQL API client for fetching advisories
  - Added `github_advisory_id` field to vulnerability model
  - Integrated into harvest orchestrator with proper pagination
- Interactive CVE details modal with accessibility features
  - Four tabs: Overview, Technical Details, Timeline, and References
  - WCAG 2.1 AA compliance with keyboard navigation
  - Focus management and screen reader support
  - Responsive design with mobile breakpoints
- Badge update functionality for automated coverage reporting
  - New `update-badge` CLI command
  - Automatic color coding based on coverage percentage
  - Dry-run mode for testing
  - CI/CD integration for automatic updates
- Webhook alerts for high-risk vulnerabilities
  - Support for Slack and Teams webhooks
  - Configurable risk threshold
  - Dry-run mode for testing

### Fixed
- SQLite timezone handling issues in cache manager
  - Convert timezone-aware datetimes to naive UTC for storage
  - Added helper methods for datetime conversion
  - All cache-related tests now pass consistently
- Implemented previously skipped tests in cvelist_client_extended.py
  - Fixed field name references (vendors → affected_vendors)
  - All 4 previously skipped tests now pass

### Changed
- Updated CI workflow to use new badge update command instead of generate_badge.py
- Enhanced documentation with new features and commands
- Improved TypeScript type safety in frontend components

## [1.0.0] - 2024-12-25

### Added
- Initial release of Vuln-Bot
- High-risk CVE intelligence platform
- Automated vulnerability harvesting from CVEProject/cvelistV5
- EPSS enrichment and risk scoring
- Static site generation with 11ty
- Advanced filtering dashboard with Alpine.js
- RSS/Atom feed generation
- GitHub Actions automation