# Enhanced CVE Data Enrichment

## Overview

The DataEnrichmentAgent provides comprehensive vulnerability enrichment by integrating with multiple data sources, with a primary focus on the deps.dev and OSV (Open Source Vulnerabilities) APIs. This enrichment adds critical context about affected packages, patch availability, and exploitation risk assessment.

## Features

### 1. Comprehensive Ecosystem Coverage

The agent supports all major package ecosystems:

- **npm** - Node.js/JavaScript packages
- **PyPI** - Python packages
- **Maven** - Java packages
- **NuGet** - .NET packages
- **Cargo** - Rust crates
- **Go** - Go modules
- **RubyGems** - Ruby gems
- **Packagist** - PHP Composer packages
- **Pub** - Dart/Flutter packages
- **Hex** - Erlang/Elixir packages
- **Hackage** - Haskell packages
- **CRAN** - R packages
- **CocoaPods** - iOS/macOS packages
- **Swift** - Swift Package Manager
- **GitHub** - GitHub Actions
- **Docker** - Docker Hub images

### 2. Robust API Integration

- **Rate Limiting**: Automatic rate limiting (5 requests/second) to respect API limits
- **Retry Logic**: Exponential backoff retry for failed requests (max 3 attempts)
- **Multiple Data Sources**: Falls back to OSV API if deps.dev data is unavailable
- **Caching**: 24-hour cache to minimize API calls
- **Error Handling**: Graceful degradation when APIs are unavailable

### 3. Rich Data Extraction

For each affected package, the agent extracts:

- **Package Information**
  - Ecosystem and package name
  - Description and homepage
  - Repository URL
  - Dependency count

- **Version Analysis**
  - Affected version ranges
  - Fixed versions
  - Latest safe version
  - Patch availability status

- **Severity Assessment**
  - Per-package severity ratings
  - Aggregated severity breakdown
  - Risk scoring based on multiple factors

### 4. Exploitation Intelligence

The agent analyzes multiple risk factors to provide actionable intelligence:

- **Risk Levels**: CRITICAL, HIGH, MEDIUM, LOW
- **Risk Factors**:
  - EPSS score analysis
  - KEV catalog listing
  - Available exploits
  - Package impact scope
  - Affected ecosystem popularity

- **Recommendations**: Risk-appropriate remediation guidance

### 5. Enhanced Reference Categorization

References are automatically categorized for better organization:

- Vendor Advisories
- Patches
- Exploits (highlighted with 🚨)
- Technical Details
- Media Coverage
- Other References

## Data Structure

### Enriched CVE Format

```json
{
  "cve_id": "CVE-2024-1234",
  "enrichment": {
    "timestamp": "2025-08-01T12:00:00Z",
    "sources": ["deps.dev", "cve_schema"],
    "deps_dev": {
      "packages": [...],
      "total_affected": 42,
      "ecosystems": ["npm", "pypi"],
      "severity_breakdown": {
        "CRITICAL": 5,
        "HIGH": 20,
        "MEDIUM": 17
      }
    },
    "impact_summary": {
      "total_affected_packages": 42,
      "affected_ecosystems": ["npm", "pypi"],
      "has_impact_data": true,
      "severity_breakdown": {...},
      "patch_availability": {
        "total": 42,
        "patched": 38,
        "percentage": 90.5
      }
    },
    "package_impact": [
      {
        "ecosystem": "npm",
        "name": "vulnerable-package",
        "version_range": ">= 1.0.0 < 1.2.5",
        "severity": "HIGH",
        "patch_available": true,
        "fixed_versions": ["1.2.5"],
        "latest_safe_version": "1.2.5",
        "repository": "https://github.com/...",
        "affected_version_count": 15
      }
    ],
    "exploitation_intel": {
      "risk_level": "HIGH",
      "risk_factors": [
        "High EPSS score (85%)",
        "Significant impact (42 packages affected)",
        "Affects popular ecosystems: npm, pypi"
      ],
      "recommendation": "HIGH PRIORITY: Patches are available..."
    },
    "categorized_references": {
      "vendor_advisories": [...],
      "patches": [...],
      "exploits": [...],
      "technical_details": [...]
    }
  },
  "has_deps_data": true,
  "total_affected_packages": 42,
  "affected_ecosystems": ["npm", "pypi"]
}
```

## Static Page Generation

The enriched data is automatically formatted for display in the static site:

### Package Impact Table

```markdown
### NPM

| Package | Version Range | Severity | Patch Available |
|---------|---------------|----------|-----------------|
| package-a | >= 1.0.0 < 1.2.5 | HIGH | ✅ (1.2.5) |
| package-b | >= 2.0.0 | CRITICAL | ❌ |
```

### Exploitation Intelligence

```markdown
## Exploitation Intelligence

**Risk Level:** 🟠 HIGH

**Risk Factors:**
- High EPSS score (85%)
- Known exploits available (2 references)
- Widespread impact (42 packages affected)

**Recommendation:** HIGH PRIORITY: Patches are available for most affected packages. Update affected systems within 24-48 hours.
```

## API Rate Limits

- **deps.dev API**: No official rate limit, but we implement 5 req/sec
- **OSV API**: No rate limit, used as fallback
- **Retry Strategy**: Exponential backoff with jitter
- **Cache TTL**: 24 hours to minimize API calls

## Testing

### Unit Tests
```bash
pytest tests/test_enrichment_agent.py -v
```

### Integration Test
```bash
python scripts/test_deps_dev_integration.py
```

### Manual Testing
```bash
python scripts/test_enrichment.py
```

## Configuration

The agent can be configured via environment variables:

- `DEPS_DEV_API_URL`: Override deps.dev API URL (default: https://api.deps.dev/v3alpha)
- `ENRICHMENT_CACHE_TTL`: Cache TTL in hours (default: 24)
- `ENRICHMENT_RATE_LIMIT`: Requests per second (default: 5)
- `ENRICHMENT_MAX_RETRIES`: Max retry attempts (default: 3)

## Error Handling

The agent implements graceful degradation:

1. If deps.dev API fails, falls back to OSV API
2. If both APIs fail, returns basic enrichment from CVE data
3. Partial data is better than no data - continues even with errors
4. All errors are logged with context for debugging

## Future Enhancements

1. **Dependency Graph Analysis**: Analyze transitive dependencies
2. **SBOM Integration**: Support for Software Bill of Materials
3. **License Analysis**: Check for license conflicts in affected packages
4. **Update Path Analysis**: Suggest safe update paths
5. **Container Image Scanning**: Check affected packages in container images