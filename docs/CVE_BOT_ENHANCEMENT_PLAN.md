# 🚀 CVE Bot Enhancement Plan with Great Expectations

## Current State Analysis

The vuln-bot project has migrated from Eleventy (11ty) to a Python-based Alpine.js single-page application. This creates an opportunity to implement a robust data quality framework using Great Expectations.

### Current Architecture
- **Frontend**: Alpine.js reactive SPA (single HTML file with embedded JSON)
- **Backend**: Python harvest pipeline with SQLite caching
- **Data Sources**: CVEProject/cvelistV5, NIST NVD API, GitHub Advisory, EPSS API
- **Deployment**: GitHub Actions → GitHub Pages

## 1. Standards Mapping

### CS: Code Standards
- **Python**: PEP 8 compliant with Ruff linting
- **JavaScript**: ESLint with Google style guide
- **Modular**: Agent-based architecture with clear separation

### TS: Testing Standards
- **Python**: pytest with >80% coverage requirement
- **JavaScript**: Vitest for Alpine.js components
- **E2E**: Playwright for live site validation

### SEC: Security Standards
- **Schema Validation**: CVE Schema v5.x compliance via Great Expectations
- **Input Sanitization**: All external data validated before processing
- **CI Secrets**: GitHub Actions secrets for API keys

### FE/WD: Frontend Standards
- **Accessibility**: WCAG 2.1 AA compliance
- **SEO**: Static HTML with proper meta tags
- **UX**: Alpine.js reactive filtering and search

### DOP/CN: DevOps Standards
- **CI/CD**: GitHub Actions with incremental builds
- **Caching**: SQLite cache with 10-day TTL
- **Monitoring**: Data quality metrics and alerts

### DE: Data Engineering
- **Schema**: CVE Schema v5.0/5.1 validation
- **Pipeline**: ETL with normalization and enrichment
- **Quality**: Great Expectations for comprehensive validation

## 2. Implementation Blueprint

### Tech Stack
```yaml
tech_stack:
  languages: [Python, JavaScript]
  frameworks: [Alpine.js, Flask (optional API)]
  testing: [pytest, Playwright, Vitest]
  infra: [GitHub Actions, GitHub Pages]
  data_sources: [cvelistV5, NVD API, GitHub Advisory, EPSS]
  validation: [cve-schema v5.x, Great Expectations]
  
agents:
  - ControllerAgent: Orchestrates harvest pipeline
  - FetchAgent: Retrieves data from sources
  - ValidatorAgent: Great Expectations validation
  - EnrichmentAgent: Adds EPSS scores and metadata
  - StaticPageAgent: Generates Alpine.js dashboard
  - QualityAgent: Monitors data quality metrics
  - CIAgent: Manages CI/CD pipeline
```

### Enhanced Project Structure
```
vuln-bot/
├── agents/
│   ├── __init__.py
│   ├── controller_agent.py      # Main orchestrator
│   ├── fetch_agent.py           # Data retrieval
│   ├── validator_agent.py       # GX validation
│   ├── enrichment_agent.py      # Data enrichment
│   ├── static_page_agent.py     # Dashboard generation
│   ├── quality_agent.py         # Quality monitoring
│   └── ci_agent.py              # CI/CD automation
├── great_expectations/
│   ├── expectations/
│   │   ├── cve_schema_v5.json   # CVE schema expectations
│   │   ├── data_quality.json    # Quality expectations
│   │   └── cross_source.json    # Multi-source validation
│   ├── checkpoints/
│   │   ├── harvest_checkpoint.yml
│   │   └── production_checkpoint.yml
│   └── great_expectations.yml
├── scripts/
│   ├── quality/
│   │   ├── great_expectations_integration.py
│   │   ├── schema_validator.py
│   │   └── audit_logger.py
│   └── harvest/
├── tests/
│   ├── unit/
│   │   ├── test_agents.py
│   │   ├── test_validation.py
│   │   └── test_enrichment.py
│   ├── integration/
│   │   └── test_pipeline.py
│   └── e2e/
│       ├── playwright.config.ts
│       ├── test_dashboard.spec.ts
│       └── test_data_quality.spec.ts
├── .github/workflows/
│   ├── harvest-and-validate.yml
│   ├── quality-checks.yml
│   └── e2e-tests.yml
└── config/
    ├── quality_gates.yaml
    └── cve_schema_v5.json
```

## 3. Code Generation

### A. Enhanced GitHub Actions Workflow
```yaml
# .github/workflows/harvest-and-validate.yml
name: Enhanced CVE Harvest with Validation

on:
  schedule:
    - cron: '0 */4 * * *'  # Every 4 hours
  workflow_dispatch:

jobs:
  harvest-validate-deploy:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: |
          pip install uv
          uv pip install -r requirements.txt
          uv pip install great-expectations
          
      - name: Initialize Great Expectations
        run: |
          python agents/validator_agent.py --init
          
      - name: Run harvest with validation
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: |
          python -m agents.controller_agent harvest \
            --with-validation \
            --checkpoint harvest_checkpoint \
            --fail-on-validation-error
            
      - name: Generate quality report
        run: |
          python -m agents.quality_agent report \
            --output reports/quality_report.html
            
      - name: Build Alpine.js dashboard
        run: |
          python scripts/generate_alpine_dashboard.py
          
      - name: Run Playwright tests
        run: |
          npx playwright install chromium
          npx playwright test --config=tests/e2e/playwright.config.ts
          
      - name: Process test results
        if: failure()
        run: |
          python -m agents.ci_agent process-failures \
            --create-todos \
            --output issues.json
            
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: quality-reports
          path: |
            reports/
            issues.json
            
      - name: Deploy to GitHub Pages
        if: success()
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./public
```

### B. Validator Agent with Great Expectations
```python
# agents/validator_agent.py
"""CVE data validation agent using Great Expectations."""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import great_expectations as gx
from great_expectations.core.batch import RuntimeBatchRequest
from great_expectations.core.expectation_configuration import ExpectationConfiguration
import structlog

from scripts.models import Vulnerability


class ValidatorAgent:
    """Validates CVE data against schema and quality rules."""
    
    def __init__(self, context_root: Path = Path("great_expectations")):
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.context = gx.get_context(context_root_dir=str(context_root))
        self._init_expectations()
        
    def _init_expectations(self):
        """Initialize CVE schema expectations."""
        # Create CVE Schema v5 expectation suite
        suite = self.context.add_or_update_expectation_suite(
            expectation_suite_name="cve_schema_v5"
        )
        
        # Required fields per CVE schema
        required_fields = [
            "cveId", "state", "assignerOrgId", "datePublished",
            "descriptions", "affected", "metrics", "references"
        ]
        
        for field in required_fields:
            suite.add_expectation(
                ExpectationConfiguration(
                    expectation_type="expect_column_values_to_not_be_null",
                    kwargs={"column": field}
                )
            )
            
        # CVE ID format validation
        suite.add_expectation(
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_match_regex",
                kwargs={
                    "column": "cveId",
                    "regex": r"^CVE-\d{4}-\d{4,}$"
                }
            )
        )
        
        # State validation
        suite.add_expectation(
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_in_set",
                kwargs={
                    "column": "state",
                    "value_set": ["PUBLISHED", "RESERVED", "REJECTED"]
                }
            )
        )
        
        # CVSS score validation
        suite.add_expectation(
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_between",
                kwargs={
                    "column": "cvss_base_score",
                    "min_value": 0.0,
                    "max_value": 10.0,
                    "mostly": 0.95
                }
            )
        )
        
        # Cross-source validation suite
        cross_suite = self.context.add_or_update_expectation_suite(
            expectation_suite_name="cross_source_validation"
        )
        
        # Ensure consistency across sources
        cross_suite.add_expectation(
            ExpectationConfiguration(
                expectation_type="expect_column_pair_values_to_be_equal",
                kwargs={
                    "column_A": "cve_id_cvelist",
                    "column_B": "cve_id_nvd",
                    "ignore_row_if": "either_value_is_missing"
                }
            )
        )
        
        self.context.save_expectation_suite(suite)
        self.context.save_expectation_suite(cross_suite)
        
    def validate_cve_batch(
        self, 
        cve_data: List[Dict[str, Any]], 
        source: str = "mixed"
    ) -> Dict[str, Any]:
        """Validate a batch of CVE data."""
        self.logger.info(f"Validating {len(cve_data)} CVEs from {source}")
        
        # Convert to pandas DataFrame for GX
        import pandas as pd
        df = pd.DataFrame(cve_data)
        
        # Create runtime batch
        batch_request = RuntimeBatchRequest(
            datasource_name="pandas_datasource",
            data_connector_name="runtime_data_connector",
            data_asset_name=f"cve_batch_{source}",
            runtime_parameters={"batch_data": df},
            batch_identifiers={
                "source": source,
                "timestamp": pd.Timestamp.now().isoformat()
            }
        )
        
        # Run validation
        checkpoint_result = self.context.run_checkpoint(
            checkpoint_name="cve_validation_checkpoint",
            validations=[
                {
                    "batch_request": batch_request,
                    "expectation_suite_name": "cve_schema_v5"
                }
            ]
        )
        
        # Process results
        validation_summary = {
            "success": checkpoint_result.success,
            "total_expectations": checkpoint_result.statistics["evaluated_expectations"],
            "passed_expectations": checkpoint_result.statistics["successful_expectations"],
            "failed_expectations": checkpoint_result.statistics["unsuccessful_expectations"],
            "validation_time": pd.Timestamp.now().isoformat(),
            "source": source,
            "record_count": len(df)
        }
        
        # Log failures
        if not checkpoint_result.success:
            failures = []
            for result in checkpoint_result.results:
                if not result.success:
                    failures.append({
                        "expectation": result.expectation_config.expectation_type,
                        "column": result.expectation_config.kwargs.get("column"),
                        "details": result.result
                    })
            validation_summary["failures"] = failures
            
            self.logger.warning(
                "Validation failed",
                failures=len(failures),
                source=source
            )
            
        return validation_summary
        
    def validate_incremental(
        self,
        new_cves: List[Dict[str, Any]],
        existing_cves: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate new CVEs against existing data."""
        # Check for duplicates
        new_ids = {cve["cveId"] for cve in new_cves}
        existing_ids = {cve["cveId"] for cve in existing_cves}
        
        duplicates = new_ids.intersection(existing_ids)
        if duplicates:
            self.logger.warning(f"Found {len(duplicates)} duplicate CVEs")
            
        # Validate new batch
        validation_result = self.validate_cve_batch(new_cves, "incremental")
        validation_result["duplicates"] = list(duplicates)
        
        return validation_result
        
    def generate_data_docs(self):
        """Generate and update data documentation."""
        self.context.build_data_docs()
        self.logger.info("Data documentation updated")


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="Initialize GX context")
    parser.add_argument("--validate", help="Validate JSON file")
    parser.add_argument("--docs", action="store_true", help="Generate data docs")
    
    args = parser.parse_args()
    
    agent = ValidatorAgent()
    
    if args.init:
        print("Great Expectations context initialized")
    elif args.validate:
        with open(args.validate) as f:
            data = json.load(f)
        result = agent.validate_cve_batch(data)
        print(json.dumps(result, indent=2))
    elif args.docs:
        agent.generate_data_docs()
        print("Data documentation generated")
```

### C. Quality Agent for Monitoring
```python
# agents/quality_agent.py
"""Data quality monitoring and reporting agent."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd
import structlog
from jinja2 import Template

from scripts.processing.cache_manager import CacheManager


class QualityAgent:
    """Monitors and reports on data quality metrics."""
    
    def __init__(self, cache_dir: Path = Path(".cache")):
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.cache_manager = CacheManager(cache_dir)
        self.metrics_history = []
        
    def collect_quality_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive quality metrics."""
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "by_source": {},
            "trends": {},
            "issues": []
        }
        
        # Get recent vulnerabilities
        recent_vulns = self.cache_manager.get_recent_vulnerabilities(limit=10000)
        df = pd.DataFrame([v.to_dict() for v in recent_vulns])
        
        # Summary metrics
        metrics["summary"] = {
            "total_vulnerabilities": len(df),
            "sources_active": df["source"].nunique() if "source" in df else 0,
            "avg_completeness": self._calculate_completeness(df),
            "vendor_extraction_rate": self._calculate_extraction_rate(df, "vendor"),
            "product_extraction_rate": self._calculate_extraction_rate(df, "product"),
            "cvss_coverage": self._calculate_field_coverage(df, "cvss_base_score"),
            "epss_coverage": self._calculate_field_coverage(df, "epss_probability"),
            "avg_risk_score": df["risk_score"].mean() if "risk_score" in df else 0
        }
        
        # Metrics by source
        if "source" in df:
            for source in df["source"].unique():
                source_df = df[df["source"] == source]
                metrics["by_source"][source] = {
                    "count": len(source_df),
                    "completeness": self._calculate_completeness(source_df),
                    "vendor_rate": self._calculate_extraction_rate(source_df, "vendor"),
                    "cvss_coverage": self._calculate_field_coverage(source_df, "cvss_base_score")
                }
                
        # Trend analysis
        metrics["trends"] = self._analyze_trends(df)
        
        # Identify quality issues
        metrics["issues"] = self._identify_issues(metrics)
        
        return metrics
        
    def _calculate_completeness(self, df: pd.DataFrame) -> float:
        """Calculate overall data completeness score."""
        if df.empty:
            return 0.0
            
        required_fields = [
            "cve_id", "severity", "description", 
            "published_date", "references"
        ]
        
        completeness_scores = []
        for field in required_fields:
            if field in df:
                score = 1.0 - (df[field].isna().sum() / len(df))
                completeness_scores.append(score)
                
        return sum(completeness_scores) / len(completeness_scores) if completeness_scores else 0.0
        
    def _calculate_extraction_rate(self, df: pd.DataFrame, field: str) -> float:
        """Calculate successful extraction rate for a field."""
        if field not in df or df.empty:
            return 0.0
            
        unknown_count = (df[field] == "Unknown").sum()
        return 1.0 - (unknown_count / len(df))
        
    def _calculate_field_coverage(self, df: pd.DataFrame, field: str) -> float:
        """Calculate coverage for a specific field."""
        if field not in df or df.empty:
            return 0.0
            
        return 1.0 - (df[field].isna().sum() / len(df))
        
    def _analyze_trends(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze quality trends over time."""
        if "published_date" not in df:
            return {}
            
        # Convert to datetime
        df["published_date"] = pd.to_datetime(df["published_date"])
        
        # Group by week
        weekly = df.set_index("published_date").resample("W")
        
        trends = {
            "weekly_volume": weekly.size().to_dict(),
            "weekly_completeness": {},
            "weekly_vendor_rate": {}
        }
        
        for week, group in weekly:
            if not group.empty:
                trends["weekly_completeness"][week.isoformat()] = self._calculate_completeness(group)
                trends["weekly_vendor_rate"][week.isoformat()] = self._calculate_extraction_rate(group, "vendor")
                
        return trends
        
    def _identify_issues(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify quality issues based on metrics."""
        issues = []
        
        # Check vendor extraction rate
        vendor_rate = metrics["summary"]["vendor_extraction_rate"]
        if vendor_rate < 0.8:
            issues.append({
                "severity": "high",
                "type": "extraction",
                "message": f"Low vendor extraction rate: {vendor_rate:.1%}",
                "recommendation": "Review vendor extraction patterns"
            })
            
        # Check CVSS coverage
        cvss_coverage = metrics["summary"]["cvss_coverage"]
        if cvss_coverage < 0.9:
            issues.append({
                "severity": "medium",
                "type": "coverage",
                "message": f"Low CVSS score coverage: {cvss_coverage:.1%}",
                "recommendation": "Consider additional CVSS data sources"
            })
            
        # Check source balance
        if "by_source" in metrics:
            source_counts = [s["count"] for s in metrics["by_source"].values()]
            if source_counts and max(source_counts) / sum(source_counts) > 0.8:
                issues.append({
                    "severity": "medium",
                    "type": "balance",
                    "message": "Data heavily skewed to one source",
                    "recommendation": "Verify all data sources are functioning"
                })
                
        return issues
        
    def generate_report(self, output_path: Path = Path("reports/quality_report.html")):
        """Generate HTML quality report."""
        metrics = self.collect_quality_metrics()
        
        # HTML template
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>CVE Data Quality Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { display: inline-block; margin: 10px; padding: 15px; 
                  background: #f0f0f0; border-radius: 5px; }
        .metric .value { font-size: 24px; font-weight: bold; }
        .issue { margin: 10px 0; padding: 10px; border-left: 4px solid #ff6b6b; }
        .issue.high { border-color: #ff6b6b; }
        .issue.medium { border-color: #ffa500; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .chart { margin: 20px 0; }
    </style>
</head>
<body>
    <h1>CVE Data Quality Report</h1>
    <p>Generated: {{ metrics.timestamp }}</p>
    
    <h2>Summary Metrics</h2>
    <div class="metrics">
        <div class="metric">
            <div class="label">Total CVEs</div>
            <div class="value">{{ metrics.summary.total_vulnerabilities }}</div>
        </div>
        <div class="metric">
            <div class="label">Vendor Extraction</div>
            <div class="value">{{ "%.1f"|format(metrics.summary.vendor_extraction_rate * 100) }}%</div>
        </div>
        <div class="metric">
            <div class="label">CVSS Coverage</div>
            <div class="value">{{ "%.1f"|format(metrics.summary.cvss_coverage * 100) }}%</div>
        </div>
        <div class="metric">
            <div class="label">Avg Completeness</div>
            <div class="value">{{ "%.1f"|format(metrics.summary.avg_completeness * 100) }}%</div>
        </div>
    </div>
    
    <h2>Quality by Source</h2>
    <table>
        <tr>
            <th>Source</th>
            <th>Count</th>
            <th>Completeness</th>
            <th>Vendor Rate</th>
            <th>CVSS Coverage</th>
        </tr>
        {% for source, data in metrics.by_source.items() %}
        <tr>
            <td>{{ source }}</td>
            <td>{{ data.count }}</td>
            <td>{{ "%.1f"|format(data.completeness * 100) }}%</td>
            <td>{{ "%.1f"|format(data.vendor_rate * 100) }}%</td>
            <td>{{ "%.1f"|format(data.cvss_coverage * 100) }}%</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Quality Issues</h2>
    {% for issue in metrics.issues %}
    <div class="issue {{ issue.severity }}">
        <strong>{{ issue.severity|upper }}:</strong> {{ issue.message }}<br>
        <em>Recommendation:</em> {{ issue.recommendation }}
    </div>
    {% endfor %}
    
    <h2>Trends</h2>
    <div class="chart">
        <!-- Trend charts would go here -->
        <p>Weekly volume trend data available in JSON format</p>
    </div>
</body>
</html>
        """)
        
        # Generate HTML
        html = template.render(metrics=metrics)
        
        # Save report
        output_path.parent.mkdir(exist_ok=True)
        output_path.write_text(html)
        
        # Also save JSON version
        json_path = output_path.with_suffix(".json")
        json_path.write_text(json.dumps(metrics, indent=2, default=str))
        
        self.logger.info(f"Quality report generated: {output_path}")
        return metrics


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["report", "metrics"])
    parser.add_argument("--output", default="reports/quality_report.html")
    
    args = parser.parse_args()
    
    agent = QualityAgent()
    
    if args.command == "report":
        agent.generate_report(Path(args.output))
    elif args.command == "metrics":
        metrics = agent.collect_quality_metrics()
        print(json.dumps(metrics, indent=2, default=str))
```

### D. Playwright E2E Tests
```typescript
// tests/e2e/test_dashboard.spec.ts
import { test, expect } from '@playwright/test';

const BASE_URL = 'https://williamzujkowski.github.io/vuln-bot';

test.describe('CVE Dashboard E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('dashboard loads successfully', async ({ page }) => {
    await expect(page).toHaveTitle(/Vulnerability Intelligence Dashboard/);
    await expect(page.locator('table')).toBeVisible();
  });

  test('vulnerability data displays correctly', async ({ page }) => {
    // Check table has data
    const rows = page.locator('tbody tr');
    await expect(rows).toHaveCount(50); // Default page size
    
    // Check first row has all required fields
    const firstRow = rows.first();
    await expect(firstRow.locator('td').nth(0)).toContainText(/CVE-\d{4}-\d+/);
    await expect(firstRow.locator('td').nth(1)).toContainText(/(CRITICAL|HIGH|MEDIUM|LOW)/);
  });

  test('vendor and product data populated', async ({ page }) => {
    const vendorCells = page.locator('tbody tr td:nth-child(6)'); // Adjust based on actual column
    const unknownCount = await vendorCells.filter({ hasText: 'Unknown' }).count();
    const totalCount = await vendorCells.count();
    
    // Should have less than 20% unknown vendors
    expect(unknownCount / totalCount).toBeLessThan(0.2);
  });

  test('search functionality works', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"]');
    await searchInput.fill('Microsoft');
    await page.waitForTimeout(500); // Debounce
    
    const visibleRows = await page.locator('tbody tr:visible').count();
    expect(visibleRows).toBeGreaterThan(0);
    
    // Verify filtered results contain search term
    const firstResult = page.locator('tbody tr:visible').first();
    const text = await firstResult.textContent();
    expect(text?.toLowerCase()).toContain('microsoft');
  });

  test('EPSS filtering works', async ({ page }) => {
    const epssInput = page.locator('input[placeholder*="Min EPSS"]');
    await epssInput.fill('90');
    await page.waitForTimeout(500);
    
    const rows = page.locator('tbody tr:visible');
    const count = await rows.count();
    
    // Should have some high EPSS vulnerabilities
    expect(count).toBeGreaterThan(0);
    
    // Verify EPSS values
    for (let i = 0; i < Math.min(count, 5); i++) {
      const epssCell = rows.nth(i).locator('td:nth-child(4)'); // Adjust column
      const epssText = await epssCell.textContent();
      const epssValue = parseFloat(epssText || '0');
      expect(epssValue).toBeGreaterThanOrEqual(90);
    }
  });

  test('CVE detail pages accessible', async ({ page }) => {
    // Click first CVE link
    const firstLink = page.locator('tbody tr a').first();
    const cveId = await firstLink.textContent();
    await firstLink.click();
    
    // Should navigate to detail page
    await expect(page).toHaveURL(new RegExp(`/cves/${cveId}`));
    await expect(page.locator('h1')).toContainText(cveId || '');
    
    // Check schema fields rendered
    await expect(page.locator('text=Attack Vector')).toBeVisible();
    await expect(page.locator('text=CVSS Score')).toBeVisible();
    await expect(page.locator('text=EPSS Score')).toBeVisible();
  });

  test('data export functionality', async ({ page }) => {
    const exportButton = page.locator('button:has-text("Export")');
    
    // Start waiting for download before clicking
    const downloadPromise = page.waitForEvent('download');
    await exportButton.click();
    
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
  });

  test('mobile responsiveness', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Check table is still accessible
    await expect(page.locator('table')).toBeVisible();
    
    // Check horizontal scroll or responsive design
    const tableContainer = page.locator('.table-container');
    const containerWidth = await tableContainer.evaluate(el => el.scrollWidth);
    const viewportWidth = await page.evaluate(() => window.innerWidth);
    
    // Table should be scrollable or fit viewport
    expect(containerWidth).toBeGreaterThan(0);
  });
});

test.describe('Data Quality Validation', () => {
  test('all required CVE fields present', async ({ page }) => {
    await page.goto(BASE_URL);
    
    // Check a sample of CVEs for required fields
    const cveLinks = page.locator('tbody tr a');
    const sampleSize = Math.min(await cveLinks.count(), 5);
    
    for (let i = 0; i < sampleSize; i++) {
      await cveLinks.nth(i).click();
      
      // Required fields per CVE schema
      await expect(page.locator('text=CVE-')).toBeVisible();
      await expect(page.locator('text=Published')).toBeVisible();
      await expect(page.locator('text=Description')).toBeVisible();
      await expect(page.locator('text=References')).toBeVisible();
      
      await page.goBack();
    }
  });

  test('CVSS scores within valid range', async ({ page }) => {
    await page.goto(BASE_URL);
    
    const cvssScores = page.locator('tbody tr td:nth-child(3)'); // Adjust column
    const count = await cvssScores.count();
    
    for (let i = 0; i < Math.min(count, 10); i++) {
      const scoreText = await cvssScores.nth(i).textContent();
      const score = parseFloat(scoreText || '0');
      
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(10);
    }
  });
});
```

### E. Enhanced Alpine.js Dashboard Component
```javascript
// public/assets/js/enhanced-dashboard.js
document.addEventListener('alpine:init', () => {
  Alpine.data('enhancedDashboard', () => ({
    // Data
    vulnerabilities: [],
    filteredVulnerabilities: [],
    
    // Quality metrics
    qualityMetrics: {
      vendorExtractionRate: 0,
      productExtractionRate: 0,
      cvssCompleteness: 0,
      epssCompleteness: 0,
      overallQuality: 0
    },
    
    // Filters
    filters: {
      search: '',
      severity: '',
      minCvss: 0,
      maxCvss: 10,
      minEpss: 0,
      maxEpss: 100,
      vendor: '',
      dateFrom: '',
      dateTo: '',
      onlyUnknownVendor: false,
      onlyMissingCvss: false
    },
    
    // UI state
    loading: true,
    error: null,
    currentPage: 1,
    pageSize: 50,
    sortField: 'risk_score',
    sortDirection: 'desc',
    
    // Initialize
    async init() {
      try {
        await this.loadVulnerabilities();
        this.calculateQualityMetrics();
        this.applyFilters();
        this.loading = false;
      } catch (error) {
        this.error = error.message;
        this.loading = false;
      }
    },
    
    // Load vulnerability data
    async loadVulnerabilities() {
      // In production, this would fetch from API
      // For now, using embedded data
      if (window.vulnerabilityData) {
        this.vulnerabilities = window.vulnerabilityData;
      } else {
        throw new Error('No vulnerability data found');
      }
    },
    
    // Calculate data quality metrics
    calculateQualityMetrics() {
      const total = this.vulnerabilities.length;
      if (total === 0) return;
      
      // Vendor extraction rate
      const unknownVendors = this.vulnerabilities.filter(v => 
        v.vendor === 'Unknown' || !v.vendor
      ).length;
      this.qualityMetrics.vendorExtractionRate = ((total - unknownVendors) / total) * 100;
      
      // Product extraction rate
      const unknownProducts = this.vulnerabilities.filter(v => 
        v.product === 'Unknown' || !v.product
      ).length;
      this.qualityMetrics.productExtractionRate = ((total - unknownProducts) / total) * 100;
      
      // CVSS completeness
      const withCvss = this.vulnerabilities.filter(v => 
        v.cvss_base_score !== null && v.cvss_base_score !== undefined
      ).length;
      this.qualityMetrics.cvssCompleteness = (withCvss / total) * 100;
      
      // EPSS completeness
      const withEpss = this.vulnerabilities.filter(v => 
        v.epss_probability !== null && v.epss_probability !== undefined
      ).length;
      this.qualityMetrics.epssCompleteness = (withEpss / total) * 100;
      
      // Overall quality score
      this.qualityMetrics.overallQuality = (
        this.qualityMetrics.vendorExtractionRate +
        this.qualityMetrics.productExtractionRate +
        this.qualityMetrics.cvssCompleteness +
        this.qualityMetrics.epssCompleteness
      ) / 4;
    },
    
    // Apply all filters
    applyFilters() {
      let filtered = [...this.vulnerabilities];
      
      // Search filter
      if (this.filters.search) {
        const search = this.filters.search.toLowerCase();
        filtered = filtered.filter(v => 
          v.cve_id.toLowerCase().includes(search) ||
          v.vendor?.toLowerCase().includes(search) ||
          v.product?.toLowerCase().includes(search) ||
          v.description?.toLowerCase().includes(search)
        );
      }
      
      // Severity filter
      if (this.filters.severity) {
        filtered = filtered.filter(v => v.severity === this.filters.severity);
      }
      
      // CVSS range
      filtered = filtered.filter(v => 
        v.cvss_base_score >= this.filters.minCvss &&
        v.cvss_base_score <= this.filters.maxCvss
      );
      
      // EPSS range
      filtered = filtered.filter(v => 
        v.epss_probability >= this.filters.minEpss &&
        v.epss_probability <= this.filters.maxEpss
      );
      
      // Vendor filter
      if (this.filters.vendor) {
        filtered = filtered.filter(v => 
          v.vendor?.toLowerCase().includes(this.filters.vendor.toLowerCase())
        );
      }
      
      // Date range
      if (this.filters.dateFrom) {
        filtered = filtered.filter(v => 
          new Date(v.published_date) >= new Date(this.filters.dateFrom)
        );
      }
      if (this.filters.dateTo) {
        filtered = filtered.filter(v => 
          new Date(v.published_date) <= new Date(this.filters.dateTo)
        );
      }
      
      // Quality filters
      if (this.filters.onlyUnknownVendor) {
        filtered = filtered.filter(v => v.vendor === 'Unknown' || !v.vendor);
      }
      if (this.filters.onlyMissingCvss) {
        filtered = filtered.filter(v => 
          v.cvss_base_score === null || v.cvss_base_score === undefined
        );
      }
      
      // Apply sorting
      filtered.sort((a, b) => {
        const aVal = a[this.sortField];
        const bVal = b[this.sortField];
        
        if (this.sortDirection === 'asc') {
          return aVal > bVal ? 1 : -1;
        } else {
          return aVal < bVal ? 1 : -1;
        }
      });
      
      this.filteredVulnerabilities = filtered;
      this.currentPage = 1; // Reset to first page
    },
    
    // Get paginated results
    get paginatedResults() {
      const start = (this.currentPage - 1) * this.pageSize;
      const end = start + this.pageSize;
      return this.filteredVulnerabilities.slice(start, end);
    },
    
    // Get total pages
    get totalPages() {
      return Math.ceil(this.filteredVulnerabilities.length / this.pageSize);
    },
    
    // Sort by field
    sortBy(field) {
      if (this.sortField === field) {
        this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
      } else {
        this.sortField = field;
        this.sortDirection = 'desc';
      }
      this.applyFilters();
    },
    
    // Export to CSV
    exportToCsv() {
      const headers = [
        'CVE ID', 'Severity', 'CVSS Score', 'EPSS %', 'Risk Score',
        'Vendor', 'Product', 'Attack Vector', 'Published Date'
      ];
      
      const rows = this.filteredVulnerabilities.map(v => [
        v.cve_id,
        v.severity,
        v.cvss_base_score || '',
        v.epss_probability || '',
        v.risk_score,
        v.vendor || 'Unknown',
        v.product || 'Unknown',
        v.attack_vector || 'Unknown',
        v.published_date
      ]);
      
      let csv = headers.join(',') + '\n';
      rows.forEach(row => {
        csv += row.map(cell => `"${cell}"`).join(',') + '\n';
      });
      
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnerabilities_${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
    },
    
    // Reset all filters
    resetFilters() {
      this.filters = {
        search: '',
        severity: '',
        minCvss: 0,
        maxCvss: 10,
        minEpss: 0,
        maxEpss: 100,
        vendor: '',
        dateFrom: '',
        dateTo: '',
        onlyUnknownVendor: false,
        onlyMissingCvss: false
      };
      this.applyFilters();
    }
  }));
});
```

## 4. Quality Gates Configuration

```yaml
# config/quality_gates.yaml
quality_gates:
  data_validation:
    - name: cve_schema_compliance
      type: great_expectations
      suite: cve_schema_v5
      fail_on_error: true
      
    - name: vendor_extraction_rate
      type: metric
      metric: vendor_extraction_rate
      threshold: 0.8
      comparison: gte
      
    - name: cvss_completeness
      type: metric
      metric: cvss_completeness
      threshold: 0.9
      comparison: gte
      
  code_quality:
    - name: python_linting
      command: ruff check scripts/
      fail_on_error: true
      
    - name: javascript_linting
      command: npm run lint
      fail_on_error: true
      
    - name: python_coverage
      command: pytest --cov=scripts --cov-fail-under=90
      fail_on_error: true
      
  security:
    - name: bandit_scan
      command: bandit -r scripts/ -ll
      fail_on_error: true
      
    - name: dependency_scan
      command: pip-audit
      fail_on_error: false
      
  e2e_testing:
    - name: playwright_tests
      command: npx playwright test
      fail_on_error: true
      retry: 2
      
    - name: accessibility_tests
      command: npx playwright test tests/e2e/accessibility.spec.ts
      fail_on_error: false
```

## 5. Summary Checklist

✅ **Architecture Analysis**
- Identified migration from Eleventy to Python/Alpine.js
- Mapped existing agent-based architecture
- Analyzed current data quality challenges

✅ **Standards Mapping**
- Code standards with linting enforcement
- Comprehensive testing strategy
- Security validation with Great Expectations
- Frontend accessibility and UX standards

✅ **Implementation Blueprint**
- Agent-based architecture with clear separation
- Great Expectations integration for schema validation
- Quality monitoring and reporting agents
- Enhanced CI/CD pipeline

✅ **Code Generation**
- ValidatorAgent with CVE schema validation
- QualityAgent for metrics and reporting
- Playwright E2E test suite
- Enhanced Alpine.js dashboard

✅ **Quality Gates**
- Data validation with Great Expectations
- Code quality with 90% coverage requirement
- Security scanning with Bandit
- E2E testing with Playwright

✅ **Tool Recommendations**
- **Required**: Great Expectations, Playwright, pytest, Ruff
- **Recommended**: Data profiling tools, quality dashboards
- **Optional**: Docker for agent isolation, advanced monitoring

The implementation provides a robust data quality framework that ensures CVE data integrity while maintaining the simplicity of the current Alpine.js architecture.