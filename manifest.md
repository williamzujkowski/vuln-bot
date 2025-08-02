# Vuln-Bot System Manifest

## Overview

This manifest documents the agent-based architecture, validation checkpoints, and performance criteria for the Vuln-Bot high-risk CVE intelligence platform.

## Agent Responsibilities

### 1. DataEnrichmentAgent
**Location**: `scripts/agents/enrichment_agent.py`
**Purpose**: Enriches CVE data with external sources

**Responsibilities**:
- Query deps.dev API for package vulnerability impact
- Extract ecosystem-specific package information
- Rate limit API calls (200ms delay between requests)
- Cache enrichment results (24-hour TTL)
- Handle API failures gracefully

**Performance Criteria**:
- API response time < 500ms per CVE
- Cache hit rate > 80%
- Zero data loss on API failures

### 2. StaticPageAgent
**Location**: `scripts/agents/static_page_agent.py`
**Purpose**: Generates static site content

**Responsibilities**:
- Create individual CVE detail pages
- Generate vulnerability index pages
- Produce chunked JSON API files
- Apply Jinja2 templates with proper escaping
- Ensure valid markdown frontmatter

**Performance Criteria**:
- Page generation < 100ms per CVE
- Chunk size optimization (25 CVEs default)
- Valid HTML/Markdown output

### 3. BaseAgent
**Location**: `scripts/agents/base_agent.py`
**Purpose**: Foundation for all agent implementations

**Provides**:
- Standardized logging interface
- Error handling and recovery
- Task execution framework
- Metrics collection
- Agent lifecycle management

### 4. Risk Scoring System
**Location**: `scripts/processing/risk_scorer.py`
**Purpose**: Calculate weighted risk scores

**Algorithm Weights**:
- CVSS Score: 25%
- EPSS Score: 20%
- Exploitation Status: 20%
- Age (Recency): 10%
- Reference Count: 5%
- Vendor Impact: 10%
- Attack Vector: 5%
- Complexity: 5%

**Score Range**: 0-100 (higher = more critical)

## Validation Checkpoints

### 1. Ingestion Validation
**Stage**: Raw CVE data ingestion
**Tool**: Great Expectations - `cve_ingestion_validation` suite

**Validates**:
- CVE ID format (regex: `^CVE-\d{4}-\d{4,}$`)
- Required fields presence (cveId, severity, description)
- Severity values (CRITICAL, HIGH, MEDIUM, LOW, NONE)
- CVSS score ranges (0.0-10.0)
- EPSS percentile ranges (0-100)
- Date format compliance (ISO 8601)
- Field uniqueness (CVE IDs)

### 2. Enrichment Validation
**Stage**: Post-enrichment processing
**Tool**: Great Expectations - `cve_enrichment_validation` suite

**Validates**:
- Exploitation status values (ACTIVE, POC, UNPROVEN, UNKNOWN)
- Tag data types (must be lists)
- Reference URL validity
- Vendor/product list formats
- Enrichment field presence

### 3. Static Page Validation
**Stage**: Generated content
**Tool**: Great Expectations - `cve_static_page_validation` suite

**Validates**:
- Markdown frontmatter structure
- Layout field (must be "cve-detail")
- Required metadata fields
- Description length constraints
- Content escaping and safety

## Performance Audit Criteria

### Frontend Performance

**Search/Filter Responsiveness**:
- Debounce delay: 300ms
- Filter execution: < 100ms
- Web Worker activation: > 100 vulnerabilities
- Virtual scroll activation: > 500 vulnerabilities

**Page Load Metrics**:
- First Contentful Paint: < 2s
- Time to Interactive: < 5s
- Cumulative Layout Shift: < 0.1
- Total Blocking Time: < 300ms

**Resource Constraints**:
- JavaScript bundle size: < 500KB per file
- Memory usage: < 50MB for 1000 items
- Session storage cache: 5-minute TTL

### Backend Performance

**Processing Speed**:
- CVE harvesting: < 5 minutes for full dataset
- Risk scoring: < 10ms per vulnerability
- Static generation: < 30s for all pages
- API response: < 200ms

**Data Efficiency**:
- Storage reduction: > 99% (from 33K to ~8 files)
- Cache hit rate: > 95%
- EPSS filter efficiency: ~97% reduction (EPSS ≥ 50%)

## CI/CD Quality Gates

### Style & Lint Enforcement
- **Python**: Ruff with zero errors/warnings
- **JavaScript**: ESLint (Google style guide)
- **Formatting**: Black (Python), Prettier (JS)
- **Imports**: isort compliance
- **Type checking**: mypy (best effort)

### Test Coverage Requirements
- **Minimum coverage**: 90%
- **No skipped tests**: Enforced
- **Test types**: Unit, integration, E2E
- **Async tests**: pytest-asyncio compliant

### Security Scanning
- **Bandit**: Medium+ confidence issues fail CI
- **npm audit**: High severity vulnerabilities fail
- **CodeQL**: Automated security analysis
- **TruffleHog**: Secret detection

### Performance Benchmarks
- **Lighthouse CI**: Performance score ≥ 80%
- **Accessibility**: Score ≥ 90%
- **Best Practices**: Score ≥ 90%
- **SEO**: Score ≥ 90%

## Data Flow Checkpoints

```
1. CVE Ingestion → Validation → Pass/Fail
                                   ↓
2. EPSS Filtering → Validation → Pass/Fail
                                    ↓
3. Risk Scoring → Range Check → Pass/Fail
                                   ↓
4. Enrichment → Schema Valid → Pass/Fail
                                  ↓
5. Storage → Chunk Valid → Pass/Fail
                            ↓
6. Static Gen → Content Valid → Pass/Fail
                                   ↓
7. Deployment → Health Check → Live
```

## Monitoring & Alerts

### Key Metrics
- CVE processing rate (per hour)
- EPSS API success rate
- Cache hit/miss ratio
- Page generation time
- Search performance (P95)

### Alert Thresholds
- API failures > 10% → Alert
- Processing time > 10 min → Alert
- Cache hit rate < 80% → Warning
- Search latency > 200ms → Warning

## Compliance & Traceability

### Data Lineage
Every CVE record maintains:
- Source timestamp
- Processing timestamps
- Validation results
- Enrichment sources
- Score calculations

### Audit Trail
- All transformations logged
- Validation failures recorded
- Performance metrics tracked
- Error conditions captured

## Future Enhancements

1. **Real-time Updates**: WebSocket support for live CVE streaming
2. **ML Risk Scoring**: Machine learning model for predictive scoring
3. **Multi-language Support**: Internationalization for global users
4. **API Rate Limiting**: Public API with rate limiting
5. **Advanced Analytics**: Time-series analysis and forecasting

---

*Last Updated: [Auto-generated timestamp]*
*Version: 2.0.0*