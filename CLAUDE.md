# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ⏰ **CRITICAL: Authoritative Time Enforcement**

**ALL time calculations MUST use authoritative external time sources, NEVER system time.**

- **Primary Source**: NIST Time API (`https://time.nist.gov/actualtime.cgi`)
- **Fallback Source**: WorldTimeAPI (`https://worldtimeapi.org/api/timezone/Etc/UTC`)
- **Implementation**: Use `scripts/utils/time_client.py` - `AuthoritativeTimeClient`
- **Convenience Functions**:
  - `get_authoritative_now()` - Current datetime (UTC)
  - `get_current_year()` - Current year
  - `get_current_date()` - Current date (YYYY-MM-DD)

**Why**: Ensures consistent, accurate time across all systems regardless of local clock drift or misconfiguration.

**Usage Example**:
```python
from scripts.utils.time_client import get_authoritative_now, get_current_year

# ❌ NEVER DO THIS:
current_time = datetime.now(timezone.utc)  # System time - unreliable!
current_year = 2025  # Hardcoded - becomes stale!

# ✅ ALWAYS DO THIS:
current_time = get_authoritative_now()  # Authoritative NIST/WorldTimeAPI
current_year = get_current_year()  # Dynamically fetched
```

## 📊 **CRITICAL: Data Quality & Accuracy Standards**

**ALL data claims, statistics, and metrics MUST be verified and sourced from authoritative data.**

### Mandatory Data Verification Rules

#### 1. **NEVER Hallucinate Numbers**
```python
# ❌ NEVER DO THIS:
print("We have 30 CVEs")  # Unverified claim
print("Coverage is 96.67%")  # Unverified claim
print("217 tests passing")  # Unverified claim

# ✅ ALWAYS DO THIS:
cve_count = len(load_json(api_index_file))  # Verify from actual data
print(f"We have {cve_count} CVEs")  # Data-backed claim

coverage = run_coverage_command()  # Run actual test
print(f"Coverage is {coverage}%")  # Verified metric
```

#### 2. **Use Only Authoritative Sources**
**Approved Data Sources**:
- **CVE Data**: NVD, CISA KEV, CVEProject/cvelistV5, GitHub Advisory Database
- **EPSS Scores**: FIRST.org EPSS API
- **Package Data**: npm registry, PyPI, Maven Central, NuGet
- **Dependencies**: deps.dev API, OSV.dev API
- **Exploits**: Exploit-DB, Metasploit, GitHub Security Lab

**Document Sources in Code**:
```python
def get_cve_count() -> int:
    """
    Get total CVE count from API index.

    Source: /public/api/vulns/index.json (generated from CVEProject/cvelistV5)
    Last verified: 2025-10-19
    """
    return len(json.load(open("public/api/vulns/index.json")))
```

#### 3. **Include Data Freshness Checks**
```python
def verify_data_freshness(data_file: Path, max_age_hours: int = 4) -> bool:
    """Verify data is not stale."""
    file_age = datetime.now() - datetime.fromtimestamp(data_file.stat().st_mtime)
    if file_age > timedelta(hours=max_age_hours):
        logger.warning(f"Data is {file_age.hours}h old (max: {max_age_hours}h)")
        return False
    return True
```

#### 4. **Validate All Counts and Metrics**
```python
# Before reporting metrics, validate them
def validate_cve_metrics(api_dir: Path) -> dict:
    """
    Validate CVE counts against actual API data.

    Returns: Dict with actual counts, not assumptions
    """
    index_file = api_dir / "vulns" / "index.json"
    if not index_file.exists():
        raise FileNotFoundError(f"API index not found: {index_file}")

    cves = json.load(index_file.open())

    return {
        "total_cves": len(cves),  # Actual count from data
        "high_severity": sum(1 for c in cves if c["severity"] == "HIGH"),
        "critical_severity": sum(1 for c in cves if c["severity"] == "CRITICAL"),
        "with_epss_60plus": sum(1 for c in cves if c.get("epss", 0) >= 0.6),
        "data_source": str(index_file),  # Document source
        "last_verified": get_authoritative_now().isoformat()
    }
```

#### 5. **No Exaggerations Without Data Backing**
```markdown
❌ BAD (Unverified superlatives):
- "World-class vulnerability detection"
- "Industry-leading accuracy"
- "Best-in-class performance"
- "Comprehensive coverage of all CVEs"

✅ GOOD (Data-backed claims):
- "6% test coverage across 8,978 statements" (verified from pytest --cov)
- "399 tests collected with 1 import error" (verified from pytest output)
- "3 CVEs currently in production API" (verified from index.json)
- "EPSS threshold: ≥60% (configured in scripts/main.py)"
```

#### 6. **Verify Test Coverage Claims**
```bash
# Always run actual coverage before claiming numbers
pytest --cov=scripts --cov-report=term | tee coverage_actual.txt

# Document exact coverage numbers, not aspirational targets
# Example from actual run:
# TOTAL: 8978 statements, 8312 missing, 6% coverage
```

#### 7. **Cross-Reference Documentation with Reality**
```python
def audit_documentation_claims(doc_file: Path) -> List[str]:
    """
    Audit documentation for unverified claims.

    Returns: List of claims that need verification
    """
    unverified_patterns = [
        r"\d+% coverage",  # Coverage claims
        r"\d+ tests passing",  # Test count claims
        r"\d+ CVEs",  # CVE count claims
        r"best|world-class|industry-leading",  # Superlatives
    ]

    content = doc_file.read_text()
    findings = []

    for pattern in unverified_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append(f"Unverified claim in {doc_file}: {matches}")

    return findings
```

### Enforcement in CI/CD

```yaml
# .github/workflows/data-quality-gate.yml
- name: Verify Documentation Accuracy
  run: |
    python -m scripts.audit_documentation_claims \
      --docs CLAUDE.md README.md \
      --fail-on-unverified

- name: Validate Metrics Match Reality
  run: |
    # Get actual CVE count
    ACTUAL_CVES=$(python -c "import json; print(len(json.load(open('public/api/vulns/index.json'))))")

    # Check documentation matches
    DOC_CLAIMS=$(grep -oP '\d+(?= CVEs)' CLAUDE.md | head -1)

    if [ "$ACTUAL_CVES" != "$DOC_CLAIMS" ]; then
      echo "ERROR: Documentation claims $DOC_CLAIMS CVEs but actual count is $ACTUAL_CVES"
      exit 1
    fi
```

### Documentation Update Requirements

**Before updating CLAUDE.md or README.md**:
1. ✅ Run `pytest --collect-only` to get actual test count
2. ✅ Run `pytest --cov=scripts --cov-report=term` to get actual coverage
3. ✅ Check `public/api/vulns/index.json` for actual CVE count
4. ✅ Verify all statistics from source data files
5. ✅ Document data sources and verification dates
6. ✅ Include data freshness warnings if data is stale

**Example Accurate Documentation**:
```markdown
## Current System Status (Verified: 2025-10-23 11:50 UTC)

**Data Metrics** (Source: public/api/vulns/index.json):
- Total CVEs: 298 (verified from API index)
- Critical: 187 (62.8%)
- High: 111 (37.2%)
- SSVC Coverage: 100% (298/298 CVEs)
- SSVC Distribution: 46 ACT, 90 ATTEND, 162 TRACK
- KEV Listed: 76 (25.5%)
- EPSS Threshold: ≥60% (configured threshold)
- Data Age: <1 day (✅ FRESH - last updated 2025-10-22 20:45 UTC)

**Test Metrics** (Source: pytest --collect-only):
- Tests Collected: 507 (with 1 collection error)
- Import Errors: 1 (collection error in test suite)

**Coverage Metrics** (Source: pytest --cov=scripts):
- Overall Coverage: 7% (9,348 total statements, 8,606 missing)
- Note: Low coverage due to many untested legacy files
- New modules have higher coverage (verified individually)
- Target Coverage: 90% (aspirational goal, not enforced)

**Build Status**:
- Last Successful Build: 2025-10-22 20:45 UTC
- Build System: Python-based (11ty removed)
- Deployment: GitHub Pages (gh-pages branch)
- Live Site: https://williamzujkowski.github.io/vuln-bot/ (298 CVEs verified)
```

### Red Flags to Avoid

🚨 **These patterns indicate unverified claims**:
- Round numbers without source (e.g., "30 CVEs" when actual is 298)
- Percentage claims without pytest output (e.g., "96.67% coverage")
- Test counts without verification (e.g., "217 tests passing")
- Superlatives without benchmarks ("best", "world-class", "leading")
- Aspirational targets presented as facts ("90% coverage" when actually 6%)

### Correction Process

**When Hallucinations are Detected**:
1. **Immediate**: Flag the claim as unverified
2. **Verify**: Run actual commands to get real data
3. **Correct**: Update documentation with verified metrics
4. **Document**: Add source citations and verification dates
5. **Prevent**: Add CI/CD checks to catch future discrepancies

## Project Overview (Updated: 2025-10-22)

This is "Vuln-Bot" - a high-risk CVE intelligence platform that tracks Critical & High severity vulnerabilities with EPSS ≥ 60% exploitation probability. It automatically harvests, scores, and publishes vulnerability briefings every 4 hours with **SSVC (Stakeholder-Specific Vulnerability Categorization)** decision framework integration. It's a Python-based project using Tailwind CSS and Alpine.js for the frontend dashboard, with static HTML generation via `scripts/generate_alpine_dashboard.py`.

**Current Production Status** (Verified: 2025-10-23 11:50 UTC):
- **CVE Count**: 298 CVEs (Source: public/api/vulns/index.json)
- **Critical**: 187 (62.8%)
- **High**: 111 (37.2%)
- **KEV Listed**: 76 (25.5%)
- **SSVC Coverage**: 100% (298/298 CVEs)
- **SSVC Distribution**: 46 ACT, 90 ATTEND, 162 TRACK
- **Test Count**: 507 tests (pytest --collect-only, 1 collection error)
- **Test Coverage**: 7% (9,348 total statements, 8,606 missing)
- **EPSS Threshold**: ≥60% (configured in scripts/main.py)
- **Live Site**: https://williamzujkowski.github.io/vuln-bot/
- **Deployment**: GitHub Pages (gh-pages branch)
- **Build System**: Python-based (11ty removed)
- **Harvest Frequency**: Every 4 hours (incremental updates)

**Schema Migration Status**:
- ✅ CVE 5.0 data models added to `scripts/models.py` (raw_cve_v5 field)
- ✅ CVE 5.0 enrichment methods implemented (_to_cve_v5_with_enrichments)
- ✅ Raw CVE 5.0 storage implemented in harvest pipeline (scripts/harvest/cvelist_client.py)
- ✅ **Phase 1 Complete** (2025-10-23): Backend CVE 5.0 support with enrichments in `containers.adp[]`
- ⏳ Data pipeline still uses legacy transformation for frontend (to_summary_dict, to_detail_dict)
- 📅 Phase 2 (Frontend native CVE 5.0): Planned for future release

**Note**: Production API (public/api/) is built from source API (src/api/). Run build process to sync.

## 🔧 CVE 5.0 Migration & Critical Bug Fixes (2025-10-23)

### ✅ Phase 1: CVE 5.0 Backend Support (COMPLETE)

**Objective**: Enable native CVE 5.0 schema storage while maintaining backward compatibility with existing frontend.

**Implementation** (Commit: `2ed430382`):

1. **Raw CVE 5.0 Storage** (`scripts/harvest/cvelist_client.py`):
   - Store complete CVE 5.0 JSON during ingestion using `deep copy`
   - Preserve original schema structure for future native frontend support
   - Location: `parse_cve_v5_record()` method (lines 352-355)

2. **CVE 5.0 Serialization** (`scripts/models.py`):
   - Added `raw_cve_v5: Optional[Dict[str, Any]]` field to Vulnerability model
   - Implemented `_to_cve_v5_with_enrichments()` method (lines 371-432)
   - Enrichments placed in `containers.adp[]` array with VulnBot-Enrichment provider
   - Includes EPSS, SSVC, and Risk Score data in official CVE 5.0 format

3. **Backward Compatibility**:
   - Frontend continues using legacy flattened schema (no breaking changes)
   - `to_summary_dict()` and `to_detail_dict()` remain unchanged
   - API output unchanged for existing consumers

**CVE 5.0 Enrichment Structure**:
```json
{
  "containers": {
    "adp": [
      {
        "providerMetadata": {
          "orgId": "vulnbot-enrichment",
          "shortName": "VulnBot-Enrichment",
          "dateUpdated": "2025-10-23T03:01:59Z"
        },
        "title": "VulnBot Threat Intelligence Enrichment",
        "enrichments": {
          "epss": { "score": 0.997, "percentile": 99.9 },
          "ssvc": { "priorityTier": "ACT", "compactNotation": "SSVC:E:A/A:N/T:T/M:M" },
          "riskScore": 95.2
        }
      }
    ]
  }
}
```

### ✅ Critical Bug Fix: Search Functionality (COMPLETE)

**Problem**: Dashboard search throwing `TypeError: v.products.toLowerCase is not a function`

**Root Cause**: Products and vendors changed from strings to arrays in data structure, but search filter code still called `.toLowerCase()` directly on arrays.

**Solution** (`scripts/generate_tailwind_dashboard.py` line 946):
```javascript
// BEFORE (broken):
v.products.toLowerCase().includes(query)

// AFTER (fixed):
v.products.some(product => product.toLowerCase().includes(query))
```

**Validation Results**:
- ✅ Local testing (Playwright): Fortinet (4 results), Microsoft (24 results)
- ✅ Live site testing: Search filtering correctly on https://williamzujkowski.github.io/vuln-bot/
- ✅ Zero JavaScript errors (only harmless favicon 404)
- ✅ Deployment: GitHub Actions completed in 16 seconds

**Files Modified**:
- `scripts/models.py` (CVE 5.0 serialization methods)
- `scripts/harvest/cvelist_client.py` (raw CVE 5.0 storage)
- `scripts/generate_tailwind_dashboard.py` (search bug fix)
- `public/index.html` (rebuilt dashboard with fix)

**Live Site Status** (Verified: 2025-10-23 03:02 UTC):
- **URL**: https://williamzujkowski.github.io/vuln-bot/
- **Total CVEs**: 298
- **Search**: ✅ Working (Fortinet: 4 results, Microsoft: 24 results)
- **Deployment**: ✅ SUCCESS (Run ID: 18736172476)

## 🎯 Recent Dashboard Improvements (2025-10-20)

### KEV Widget Fix & UI Enhancements

**Problem Solved**: KEV widget was displaying "0" despite 73 CVEs being enriched with CISA KEV data.

**Root Cause**: The `enrichments` field was never embedded in frontend JavaScript (line 548 in `generate_alpine_dashboard.py` was missing `"enrichments": vuln.get("enrichments", {})`).

**Solutions Implemented**:

1. **✅ KEV Widget Fix** (Commit: `21b28a97d`):
   - Added missing enrichments field to vuln_data dictionary
   - KEV widget now correctly displays 73 on live site
   - Verified with Playwright validation

2. **✅ Dashboard UI Improvements** (Commit: `a03fe7db8`):
   - **Moved Build Timestamp and Data Last Updated to same row**: Now displayed as two adjacent stat cards with color-coded indicators (green for Build Timestamp, blue for Data Last Updated)
   - **Removed redundant "KEV Listed" column**: Column was duplicate of Exploit Status column which already shows "🔴 KEV Listed"
   - **Simplified data freshness indicator**: Shows "✓ Fresh" (green) or "⚠ Stale (>24h)" (red) based on data age

3. **✅ GitHub Actions Deployment Automation**:
   - **`.github/workflows/pages.yml`**: Triggers automatically on push to main when `public/**` or `scripts/generate_alpine_dashboard.py` changes
   - **`.github/workflows/scheduled-harvest.yml`**: Already has deployment logic (lines 288-298) using `upload-pages-artifact@v3` and `deploy-pages@v4`
   - **Both manual pushes AND scheduled harvests now trigger website deployments**

**Live Site Validation** (Verified: 2025-10-20):
- ✅ KEV widget shows 73 (correct count)
- ✅ Build Timestamp and Data Last Updated on same row
- ✅ Redundant KEV Listed column removed
- ✅ GitHub Actions workflow triggered automatically on push

**Files Modified**:
- `scripts/generate_alpine_dashboard.py` (lines 548, 1415-1431, 1672-1674, 1714-1717)
- `.github/workflows/pages.yml` (added automatic triggers)
- `public/index.html` (regenerated with improvements)

### Table Cleanup & Data Enhancement (2025-10-20)

**Objective**: Streamline vulnerability table by removing redundant columns and adding actionable data freshness information.

**Changes Implemented** (Commit: `c1e283c1f`):

1. **✅ Removed Priority Column**:
   - **Rationale**: Priority and Severity columns were redundant (both showing similar criticality information)
   - **Impact**: Cleaner table layout, reduced information overload
   - **Location**: `generate_alpine_dashboard.py` lines 1669-1671 (header), 1702-1710 (cells)

2. **✅ Fixed Severity Column Styling**:
   - **Before**: `⚠️ CRITICAL` (with emojis and warning icons)
   - **After**: `CRITICAL` (clean text badge with color coding)
   - **Impact**: More professional appearance, better accessibility for screen readers
   - **Location**: `generate_alpine_dashboard.py` lines 1711-1716

3. **✅ Removed Risk Score Column**:
   - **Rationale**: Redundant metric - CVSS and EPSS scores provide sufficient severity indicators
   - **Impact**: Focused on industry-standard metrics (CVSS, EPSS)
   - **Location**: `generate_alpine_dashboard.py` lines 1681-1683 (header), 1719 (cells), 1775-1785 (mobile view)

4. **✅ Added Last Updated Column**:
   - **Data Source**: MITRE CVE JSON `last_modified_date` field
   - **Format**: Short date format (YYYY-MM-DD) matching Published column
   - **Value**: Shows data freshness for each CVE, helps users identify recently updated vulnerabilities
   - **Location**: `generate_alpine_dashboard.py` lines 94-98, 192-196 (data processing), 540 (data embedding), 1686-1688 (header), 1725 (cells)

5. **✅ Fixed Filter Card Spacing**:
   - **Problem**: Filter controls overlapping on smaller screens
   - **Solution**: Increased grid gap from 1rem to 1.25rem, increased bottom margin from 1rem to 1.5rem
   - **Location**: `generate_alpine_dashboard.py` lines 722-723

**Final Table Columns (9 total, down from 11)**:
1. CVE ID - Link to MITRE CVE page
2. Severity - Clean badge (CRITICAL/HIGH) without emojis
3. CVSS - CVSS score (0-10)
4. EPSS % - Exploit Prediction Scoring System percentage
5. Product - Affected product name
6. Vendors - Affected vendors (comma-separated)
7. Exploit Status - KEV Listed / PoC Available / Not Listed
8. Published - Initial publication date
9. **Last Updated** - Most recent modification date (**NEW**)

**Removed Columns**:
- Priority (redundant with Severity)
- Risk Score (redundant metric)

**Playwright Validation Results** (All checks PASSED):
- ✅ Priority column removed
- ✅ Risk Score column removed
- ✅ Last Updated column added with dates
- ✅ Severity badges clean (no emojis)
- ✅ Filter section spacing fixed (no overlaps)
- ✅ Mobile card view updated (Risk Score removed)

**Live Site Status** (Verified: 2025-10-20 05:49 ET):
- **Deployment**: ✅ SUCCESS via GitHub Actions (23 seconds)
- **Build Timestamp**: 2025-10-20 05:49:19 EDT
- **Table Columns**: 9 columns displaying correctly
- **URL**: https://williamzujkowski.github.io/vuln-bot/

**Files Modified**:
- `scripts/generate_alpine_dashboard.py` (~30 additions, ~15 deletions)
- `public/index.html` (auto-regenerated from script)

### Filter Layout Overlap Fix (2025-10-20)

**Problem Identified**: Published Date filter boxes (two date inputs side-by-side) were overlapping the Vendor filter box due to insufficient grid column width.

**Root Cause Analysis**:
- Published Date filter contains two date input boxes with 0.5rem gap between them
- Each date input requires ~150px minimum width
- Combined space needed: ~320-350px total (inputs + gap + label + padding)
- Original grid setting: `grid-template-columns: repeat(auto-fit, minmax(250px, 1fr))`
- **250px minimum was insufficient** for the Published Date filter

**Solution Implemented** (Commit: `7d9a8360b`):
- **Approach**: Increased minimum column width and grid gap
- **Changes**:
  - Minimum column width: `250px` → `280px` (+30px, 12% increase)
  - Grid gap: `1.25rem` → `1.5rem` (+0.25rem, 20% increase)
- **Location**: `generate_alpine_dashboard.py` lines 719-723
- **CSS**:
  ```css
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  ```

**Responsive Validation** (All viewports tested with Playwright):

| Viewport | Resolution | Status | Layout | Grid Gap |
|----------|------------|--------|--------|----------|
| Desktop | 1920x1080 | ✅ PASS | 5 filters/row 1, 1/row 2 | 24px (1.5rem) |
| Laptop | 1366x768 | ✅ PASS | 4 filters/row 1, 2/row 2 | 24px (1.5rem) |
| Tablet | 768x1024 | ✅ PASS | Single column | 12px (0.75rem) |
| Mobile | 375x667 | ✅ PASS | Single column | 12px (0.75rem) |

**Validation Checklist** (All items PASSED):
- ✅ Published Date filter boxes visible and not overlapping
- ✅ Vendor filter box visible and not overlapping
- ✅ All filters have adequate spacing (1.5rem gap)
- ✅ No horizontal scrollbar in filter card
- ✅ Desktop layout correct (1920x1080)
- ✅ Laptop layout correct (1366x768)
- ✅ Tablet layout correct (768x1024)
- ✅ Mobile layout correct (375x667)
- ✅ Filter functionality working (Alpine.js components)
- ✅ Filters collapse properly on mobile

**Live Site Status** (Verified: 2025-10-20 10:26 UTC):
- **Deployment**: ✅ SUCCESS via GitHub Actions (20 seconds)
- **URL**: https://williamzujkowski.github.io/vuln-bot/
- **CDN Propagation**: Complete (validated 3 minutes post-deployment)
- **Zero overlaps detected** on all tested viewports

**Benefits**:
- Simple CSS-only fix (no structural changes)
- Future-proof for other filters needing more space
- Improved visual breathing room with increased gap
- Fully responsive across all device sizes

**Files Modified**:
- `scripts/generate_alpine_dashboard.py` (lines 719-723)
- `public/index.html` (auto-regenerated from script)

## 🎯 Latest Dashboard Features (2025-10-22)

### CVE Detail Modal with 4-Tab Interface

**Feature**: Interactive modal dialog for viewing complete CVE details without leaving the dashboard.

**Implementation** (Commit: `bd4ae2143`):

**Trigger**: Click any table row to open modal
**Close Methods**: Close button (X), ESC key, click backdrop

**Tab Structure**:
1. **Overview Tab**:
   - Full CVE description (not truncated)
   - Published and last modified dates
   - Affected products (full list with badges)
   - Affected vendors (full list with badges)
   - SSVC priority tier and compact notation

2. **Technical Details Tab**:
   - Attack vector, complexity, privileges required, user interaction
   - Exploitation status
   - Vulnerability tags
   - Scoring details grid (CVSS, EPSS score, EPSS percentile, Risk score)

3. **References Tab**:
   - External links with hover effects
   - Source attribution for each reference
   - External link icons
   - Empty state when no references available

4. **Enrichments Tab**:
   - CISA KEV data (vendor, product, vulnerability name, dates, required action)
   - Additional enrichment data when available
   - Empty state when no enrichments exist

**UX Features**:
- Full-screen overlay with backdrop blur
- Smooth fade-in/fade-out transitions
- Sticky header with CVE ID and badges
- Body scroll prevention when modal open
- Responsive design (max-width 5xl, max-height 90vh)
- Dark mode support throughout
- ARIA labels and semantic HTML

**Data Displayed**:
- All CVSS metrics
- EPSS score and percentile
- Products and vendors (complete, not truncated)
- Publication and modification dates
- SSVC priority tier with color-coded badges
- KEV enrichment details
- Reference links

**Files Modified**:
- `scripts/generate_tailwind_dashboard.py`:
  - Lines 36-85: Enhanced vuln_data embedding with all CVE fields
  - Lines 776-779: Modal state (selectedVuln, modalOpen, activeTab)
  - Lines 951-968: Modal methods (openModal, closeModal, switchTab)
  - Lines 477-761: Modal HTML structure
- `public/index.html` (auto-regenerated)

### Sortable Table Columns

**Feature**: Click column headers to sort vulnerability data ascending/descending.

**Implementation** (Commit: `09e225638`):

**Sortable Columns** (5 total):
1. **CVE ID** - Alphabetical sorting
2. **Severity** - Custom priority order (CRITICAL > HIGH)
3. **CVSS Score** - Numeric sorting (0-10)
4. **EPSS %** - Numeric sorting by percentile
5. **Published Date** - Chronological sorting

**Non-Sortable Columns**:
- Product (too varied for meaningful sorting)
- Vendors (too varied for meaningful sorting)
- Exploit Status (binary KEV flag)

**UX Indicators**:
- ↕️ icon = unsorted (neutral state)
- ↑ icon = ascending order
- ↓ icon = descending order
- Hover effect with gray background highlight
- Cursor pointer on sortable headers
- Text selection prevented (select-none)

**Sort Logic**:
- First click: Sort ascending
- Second click: Toggle to descending
- Clicking different column: Reset to ascending
- Smart type detection (numeric vs string comparison)
- Custom severity ordering logic

**Implementation Details**:
- Alpine.js state: `sortColumn`, `sortDirection`
- `sortBy(column)` method with toggle logic
- `getSortIcon(column)` for visual indicators
- Sorting applied after filters in `filteredVulns` getter
- Maintains current page on sort

**Files Modified**:
- `scripts/generate_tailwind_dashboard.py`:
  - Lines 781-783: Sort state variables
  - Lines 809-831: Sorting logic in filteredVulns getter
  - Lines 972-988: sortBy() and getSortIcon() methods
  - Lines 401-433: Clickable column headers with icons
- `public/index.html` (auto-regenerated)

### Vendors Column Addition

**Feature**: New table column displaying affected vendors for supply chain risk analysis.

**Implementation** (Commit: `a482016ba`):

**Column Details**:
- **Position**: Between Product and Exploit Status columns
- **Data Format**: Comma-separated vendor names, truncated at 100 characters
- **Display Field**: `vendors_display` (matching `products_display` pattern)
- **Full Data**: Complete vendor array available in modal view

**CSV Export**:
- Column already included in CSV export (line 935)
- Format: Semicolon-separated (v.vendors.join('; '))
- Proper CSV escaping applied

**Current Table Columns** (8 total):
1. CVE ID (sortable)
2. Severity (sortable)
3. CVSS (sortable)
4. EPSS % (sortable)
5. Product
6. **Vendors** (NEW)
7. Exploit Status
8. Published (sortable)

**Benefits**:
- Vendor visibility for supply chain risk analysis
- Quick identification of affected vendors
- Better filtering capability (vendors already in search filter)
- Complete data available in modal view

**Files Modified**:
- `scripts/generate_tailwind_dashboard.py`:
  - Line 59: Added `vendors_display` field to vuln_data
  - Line 427: Table header "Vendors"
  - Line 455: Table cell displaying `vendors_display`
- `public/index.html` (auto-regenerated)

### Mobile Card Layout

**Feature**: Responsive card-based layout for mobile devices, replacing horizontal scroll.

**Implementation** (Commit: `8a9c9c6ef`):

**Responsive Strategy**:
- **Desktop/Tablet (≥768px)**: Table view with `hidden md:block`
- **Mobile (<768px)**: Card view with `md:hidden`
- **Breakpoint**: Tailwind's md breakpoint (768px)

**Card Layout Structure**:
1. **Header Section**:
   - CVE ID (clickable link to MITRE, with @click.stop)
   - Severity badge (color-coded: red for CRITICAL, orange for HIGH)
   - Flex layout with proper spacing

2. **Scores Grid**:
   - 2-column grid for CVSS and EPSS scores
   - Background highlight boxes (gray-50/gray-900)
   - Large, bold score display
   - Descriptive labels

3. **Product & Vendors Section**:
   - Stacked vertical layout
   - Section labels (Product, Vendors)
   - Truncated display with ellipsis
   - Full data available on card click

4. **Footer Section**:
   - KEV status indicator (purple badge or dash)
   - Published date (monospace font)
   - Border-top separator

**UX Improvements**:
- No horizontal scrolling on mobile
- Entire card clickable to open modal
- Hover shadow effect for visual feedback
- Consistent spacing and padding
- Dark mode support throughout
- Better touch targets for mobile users

**Implementation Details**:
- Uses same `paginatedVulns` data as table
- Alpine.js template x-for iteration
- @click.stop on CVE link prevents modal opening
- Tailwind responsive utilities (md: prefix)
- Semantic HTML with proper structure

**Files Modified**:
- `scripts/generate_tailwind_dashboard.py`:
  - Line 399: Hidden table on mobile (`hidden md:block`)
  - Lines 471-527: Mobile card view HTML
- `public/index.html` (auto-regenerated)

**Current Status** (Verified: 2025-10-22):
- **Total CVEs**: 297 (Source: api/vulns/index.json)
- **Critical Severity**: 186 (62.6%)
- **High Severity**: 111 (37.4%)
- **KEV Listed**: 75 (25.3%)
- **Live Site**: https://williamzujkowski.github.io/vuln-bot/

## 📋 Implementation Status: SSVC Integration

### ✅ **Phase 1: Backend SSVC Calculation** (COMPLETE)
**Status**: Fully implemented and validated
**Completion Date**: 2025-10-19
**Coverage**: 100% (298/298 CVEs)

**Implementation Details**:
- **SSVC Engine** (`scripts/processing/ssvc_calculator.py`):
  - 4-factor decision tree: Exploitation, Automatable, Technical Impact, Mission Impact
  - Priority tier assignment: ACT (immediate), ATTEND (scheduled), TRACK (monitor)
  - Compact notation generation (e.g., "SSVC:E:A/A:N/T:T/M:M = ACT")
  - Fallback logic for missing data with inference flags

- **Data Pipeline Integration**:
  - SQLite cache storage with SSVC fields
  - JSON API generation with SSVC objects
  - CSV export with SSVC columns (Priority, Notation)

- **Validation Results**:
  - 298 CVEs processed with 100% success rate
  - Distribution verified on live site with all CVEs categorized
  - Zero errors or missing data issues

### ✅ **Phase 2: Frontend SSVC Visualization** (COMPLETE)
**Status**: Fully implemented and deployed
**Completion Date**: 2025-10-19
**Commit**: `4fe0ce9d2` - "feat(ssvc): Phase 2 - Complete frontend integration"

**Implementation Details**:

#### 1. Dashboard Table Integration
**File**: `public/index.html` (Alpine.js dashboard)
- ✅ **Sortable SSVC Priority Column**:
  - Column header: "SSVC Priority" with sort indicator
  - Color-coded badges: 🔴 ACT (red), 🟠 ATTEND (orange), 🔵 TRACK (blue)
  - Tier-based sorting logic (ACT > ATTEND > TRACK)
  - Mobile-responsive card view with SSVC badges

- ✅ **SSVC Filter Dropdowns**:
  - **SSVC Priority Filter**: All, ACT, ATTEND, TRACK (4 options)
  - **Exploitability Profile Filter**: All, Active Exploitation, PoC Available, None (4 options)
  - Real-time filtering with Alpine.js reactivity
  - URL hash state for shareable filtered views

#### 2. CVE Detail Modal Enhancement
**Files**: `public/index.html`, `src/assets/css/components/modal.css`
- ✅ **SSVC Tab Implementation**:
  - New tab: "SSVC Decision" (5th tab in modal)
  - Keyboard shortcut: Alt+5 for quick access
  - Comprehensive decision tree visualization

- ✅ **SSVC Data Display**:
  - Priority tier with action guidance (immediate/scheduled/monitor)
  - Exploitation status with descriptions (Active/PoC/None)
  - Automatable attack classification (Yes/No)
  - Technical impact assessment (Total/Partial/None)
  - Compact notation display (SSVC:E:A/A:N/T:T/M:M)
  - Inference flags when data is missing

- ✅ **Helper Methods** (5 total):
  - `getPriorityAction()`: Action guidance per tier
  - `formatExploitation()`: Exploitation status formatting
  - `getExploitationDesc()`: Exploitation descriptions
  - `getAutomatableDesc()`: Automatable attack descriptions
  - `getImpactDesc()`: Technical impact descriptions

#### 3. CSV Export Enhancement
**File**: `public/index.html` (exportCSV function)
- ✅ **SSVC Columns Added**:
  - Column: "SSVC Priority" (ACT/ATTEND/TRACK)
  - Column: "SSVC Profile" (compact notation)
  - Proper escaping for CSV format
  - Backwards compatible with existing columns

#### 4. Styling & Accessibility
**Files**: `src/assets/css/components/modal.css`, `public/index.html`
- ✅ **SSVC Badge Styling**:
  - Semantic color scheme (red/orange/blue)
  - Dark mode support with adjusted colors
  - High contrast for accessibility
  - Consistent sizing and spacing

- ✅ **Accessibility Features**:
  - WCAG 2.1 AA compliance maintained
  - ARIA labels for screen readers
  - Keyboard navigation support
  - Focus management in modal tabs

#### 5. Data Verification
**Verified Metrics** (Source: public/api/vulns/index.json, verified 2025-10-23):
- ✅ Total CVEs: 298
- ✅ SSVC Coverage: 100% (298/298)
- ✅ All CVEs categorized with ACT/ATTEND/TRACK priorities
- ✅ Distribution verified on live site (https://williamzujkowski.github.io/vuln-bot/)
- ✅ CSV Export: Tested with SSVC columns
- ✅ All UI elements: Validated in browser

### 🎯 **Phase 3: Testing & Documentation** (NEXT)
**Status**: Not started
**Planned Features**:
- [ ] Playwright E2E tests for SSVC functionality
- [ ] Visual regression tests for SSVC badges/modal
- [ ] Unit tests for SSVC calculator edge cases
- [ ] Performance testing for SSVC filtering
- [ ] User guide for SSVC methodology
- [ ] API documentation for SSVC fields

---

## 📊 SSVC Data Verification Commands

**Use these commands to verify SSVC implementation and data quality:**

### Verify SSVC Coverage
```bash
# Check SSVC coverage in source API
python3 -c "
import json
data = json.load(open('src/api/vulns/index.json'))
vulns = data['vulnerabilities']
total = len(vulns)
with_ssvc = sum(1 for v in vulns if v.get('ssvc'))
print(f'Total CVEs: {total}')
print(f'CVEs with SSVC: {with_ssvc}')
print(f'SSVC Coverage: {with_ssvc/total*100:.1f}%')
"
```

### Verify SSVC Distribution
```bash
# Check SSVC tier distribution
python3 -c "
import json
data = json.load(open('src/api/vulns/index.json'))
vulns = data['vulnerabilities']
tiers = {}
for v in vulns:
    if v.get('ssvc', {}).get('priorityTier'):
        tier = v['ssvc']['priorityTier']
        tiers[tier] = tiers.get(tier, 0) + 1
print('SSVC Tier Distribution:')
for tier in ['ACT', 'ATTEND', 'TRACK']:
    count = tiers.get(tier, 0)
    pct = count/len(vulns)*100
    print(f'  {tier}: {count} CVEs ({pct:.1f}%)')
"
```

### Verify SSVC in CSV Export
```bash
# Check CSV has SSVC columns
head -1 public/data/vulnerabilities.csv | grep -q "SSVC Priority" && \
  echo "✅ CSV has SSVC Priority column" || \
  echo "❌ CSV missing SSVC Priority column"

head -1 public/data/vulnerabilities.csv | grep -q "SSVC Profile" && \
  echo "✅ CSV has SSVC Profile column" || \
  echo "❌ CSV missing SSVC Profile column"
```

### Verify SSVC in Dashboard HTML
```bash
# Check dashboard has SSVC filters
grep -q "x-model=\"filters.ssvc_priority\"" public/index.html && \
  echo "✅ Dashboard has SSVC Priority filter" || \
  echo "❌ Dashboard missing SSVC Priority filter"

grep -q "x-model=\"filters.ssvc_exploitation\"" public/index.html && \
  echo "✅ Dashboard has Exploitability filter" || \
  echo "❌ Dashboard missing Exploitability filter"

# Check modal has SSVC tab
grep -q "x-show=\"activeTab === 'ssvc'\"" public/index.html && \
  echo "✅ Modal has SSVC tab" || \
  echo "❌ Modal missing SSVC tab"
```

### Generate SSVC Report
```bash
# Generate comprehensive SSVC verification report
cat > ssvc_verification_report.md <<EOF
# SSVC Implementation Verification Report
Generated: $(date -u +"%Y-%m-%d %H:%M UTC")

## Data Coverage
$(python3 -c "
import json
data = json.load(open('src/api/vulns/index.json'))
vulns = data['vulnerabilities']
total = len(vulns)
with_ssvc = sum(1 for v in vulns if v.get('ssvc'))
print(f'- Total CVEs: {total}')
print(f'- CVEs with SSVC: {with_ssvc}')
print(f'- Coverage: {with_ssvc/total*100:.1f}%')
")

## Tier Distribution
$(python3 -c "
import json
data = json.load(open('src/api/vulns/index.json'))
vulns = data['vulnerabilities']
tiers = {}
for v in vulns:
    if v.get('ssvc', {}).get('priorityTier'):
        tier = v['ssvc']['priorityTier']
        tiers[tier] = tiers.get(tier, 0) + 1
for tier in ['ACT', 'ATTEND', 'TRACK']:
    count = tiers.get(tier, 0)
    pct = count/len(vulns)*100
    print(f'- {tier}: {count} CVEs ({pct:.1f}%)')
")

## Frontend Integration
$(grep -q "x-model=\"filters.ssvc_priority\"" public/index.html && echo "- ✅ SSVC Priority filter" || echo "- ❌ SSVC Priority filter missing")
$(grep -q "x-show=\"activeTab === 'ssvc'\"" public/index.html && echo "- ✅ SSVC modal tab" || echo "- ❌ SSVC modal tab missing")
$(head -1 public/data/vulnerabilities.csv | grep -q "SSVC Priority" && echo "- ✅ CSV export" || echo "- ❌ CSV export missing SSVC")

## Latest Commit
$(git log --oneline --grep="ssvc" -i -1)
EOF

cat ssvc_verification_report.md
```

---

## 🔄 Harvest Strategy & Update Detection (Updated: 2025-10-23)

### Comprehensive Harvest Approach

The vulnerability harvest system is designed to capture **ALL CVEs that meet criteria**, including:
1. **New CVEs** - Freshly published vulnerabilities
2. **Updated CVEs** - Existing CVEs with changes to EPSS, CVSS, or metadata
3. **Newly Qualifying CVEs** - CVEs that previously didn't meet thresholds but now do after updates

### How Update Detection Works

#### 1. **Release-Based Delta Files** (`cvelist_client.py:716-726`)
```python
# Incremental harvests use GitHub release delta files
# Delta files contain ONLY CVEs that changed since last release
if incremental and self.cache_manager:
    cves.extend(self._process_delta_files(release_data, year, min_severity))

# ALSO processes midnight file for comprehensive coverage
cves.extend(self._process_midnight_file(release_data, year, min_severity, incremental))
```

**How It Works**:
- CVEProject/cvelistV5 publishes daily release files
- **Delta files**: Only CVEs added/modified in last 24 hours (~10-50 CVEs/day)
- **Midnight files**: Complete snapshot of all CVEs at midnight UTC
- Incremental mode processes BOTH for maximum coverage

#### 2. **Individual CVE Update Detection** (`cvelist_client.py:610-683`)
```python
def _should_skip_cve(self, cve_id: str, file_path: str) -> bool:
    """Check if CVE should be skipped in incremental mode."""
    # Get cached CVE metadata
    cached_vuln = self.cache_manager.get_vulnerability(cve_id)
    if not cached_vuln:
        return False  # No cache = fetch it

    # Fetch current CVE metadata from GitHub
    cve_content = fetch_from_github(file_path)
    date_updated = cve_content['cveMetadata']['dateUpdated']

    # Compare dates: Skip only if no updates since cache
    if date_updated <= cached_vuln.last_modified_date:
        return True  # Skip - no updates

    return False  # Fetch - CVE has been updated
```

**How It Works**:
- Compares `cveMetadata.dateUpdated` from CVEProject against cached `last_modified_date`
- **Fetches CVE if**:
  - No cached version exists (new CVE)
  - `dateUpdated` is newer than cache (CVE updated)
  - Any comparison fails (safety - fetch on error)
- **Skips CVE only if**: `dateUpdated <= cached_date` (definitely no changes)

#### 3. **EPSS-First Filtering** (Initial Harvest Only)
```python
# Initial harvest: Pre-filter using EPSS scores before fetching CVE details
high_epss_cve_ids = self._get_high_epss_cve_ids(min_epss_score=0.6)
# Result: ~1,000 CVE IDs with EPSS ≥60% (instead of 15,000+ all CVEs)

# Then fetch only those CVE IDs that meet EPSS threshold
vulnerabilities = self.cvelist_client.harvest(
    years=[2024, 2025],
    epss_filter_cve_ids=high_epss_cve_ids  # Pre-filtered list
)
```

**Why This Matters**:
- Without EPSS-first: Would fetch 15,000+ CVEs, then filter to ~300
- With EPSS-first: Fetch ~1,000 CVEs, filter to ~300
- **Performance**: 93% reduction in API calls and processing time

### Baseline Count Regression Prevention (New: 2025-10-23)

#### Problem Statement
Previously, CVE counts could decrease if:
- EPSS scores dropped below threshold
- Harvest bugs missed existing CVEs
- Filtering logic changed

#### Solution: Baseline Enforcement

**CI/CD Gatecheck** (`scripts/ci_gatecheck.py:41-103`):
```python
def validate_cve_count_threshold(
    self,
    api_dir: Path,
    max_count: int = 1000,
    expected_count: int = 298,
    min_baseline: int = 298,  # NEW: Minimum count threshold
):
    # CRITICAL: Enforce minimum baseline (count should NEVER decrease)
    if total_cves < min_baseline:
        self.add_error(
            f"CRITICAL: CVE count regression detected: {total_cves} < {min_baseline}",
            f"Count dropped from baseline. Harvest is missing CVEs."
        )
        return False  # FAIL the build
```

**Baseline Policy**:
- **Current Baseline**: 298 CVEs (set 2025-10-23)
- **Rule**: CVE count must be ≥ 298 (can only increase, never decrease)
- **Enforcement**: CI/CD pipeline FAILS if count < baseline
- **Rationale**: Ensures harvest improvements or threshold changes never lose qualifying CVEs

**Usage**:
```bash
# CI/CD gatecheck with baseline enforcement
python -m scripts.ci_gatecheck \
  --api-dir public/api \
  --max-cve-count 1000 \
  --expected-cve-count 298 \
  --min-baseline 298 \        # NEW: Baseline parameter
  --min-epss 0.6 \
  --fail-on-violations

# If count < 298: ❌ CRITICAL ERROR - build fails
# If count >= 298: ✅ PASS - deployment proceeds
```

### Update Scenarios Handled

| Scenario | Detection Method | Result |
|----------|------------------|--------|
| New CVE published | Delta file + cache miss | ✅ Fetched |
| CVE metadata updated | `dateUpdated` comparison | ✅ Fetched |
| CVSS score changed | `dateUpdated` triggers re-fetch | ✅ Fetched |
| EPSS score increased | Weekly EPSS refresh + re-validation | ✅ Captured |
| EPSS score decreased | EPSS filter + baseline enforcement | ⚠️ Kept if in baseline |
| CVE threshold newly met | EPSS refresh detects new qualifying CVE | ✅ Fetched |
| Count regression | Baseline enforcement in CI/CD | ❌ Build fails |

### Harvest Modes

#### 1. **Incremental Mode** (DEFAULT)
```bash
python -m scripts.main harvest --cache-dir .cache/
# OR explicitly:
python -m scripts.main harvest --cache-dir .cache/ --incremental
```

**Behavior**:
- Processes delta files (last 24 hours of changes)
- Checks `dateUpdated` for individual CVEs
- Skips CVEs with no updates since last harvest
- **Performance**: ~10-20 CVEs processed per run
- **Use Case**: Daily automated harvests (every 4 hours)

#### 2. **Full Refresh Mode**
```bash
python -m scripts.main harvest --cache-dir .cache/ --no-incremental
```

**Behavior**:
- Processes all CVEs regardless of cache
- Re-validates ALL EPSS scores
- Recalculates all risk scores
- **Performance**: ~300-1000 CVEs processed
- **Use Case**: Weekly full refresh, EPSS threshold changes, baseline verification

### Best Practices

1. **Daily Incremental Harvests**: Capture new and updated CVEs automatically
2. **Weekly Full Refresh**: Re-validate all CVEs against current EPSS scores
3. **Baseline Enforcement**: Never allow count regressions
4. **Delta + Midnight Processing**: Ensures comprehensive coverage of all changes

### Verification Commands

```bash
# Verify harvest captured updates
python3 -c "
import json
from datetime import datetime
data = json.load(open('public/api/vulns/index.json'))
recent = [v for v in data['vulnerabilities']
          if datetime.fromisoformat(v['lastUpdated'].replace('Z', '+00:00')) >
             datetime(2025, 10, 20, tzinfo=timezone.utc)]
print(f'CVEs updated since Oct 20: {len(recent)}')
"

# Verify baseline enforcement
python -m scripts.ci_gatecheck \
  --api-dir public/api \
  --min-baseline 298 \
  --expected-cve-count 298 \
  --fail-on-violations
# Expected: ✅ PASS if count >= 298
```

---

## Common Development Commands

### Python Development
```bash
# Install Python dependencies (using uv)
uv pip install -r requirements.txt

# Run the vulnerability harvester (incremental mode is DEFAULT)
python -m scripts.main harvest --cache-dir .cache/

# INCREMENTAL HARVESTING (Default Behavior):
# - Initial harvest: EPSS-first filtering (~100 CVEs instead of 15,000)
# - Daily incremental: Only CVEs updated in last 48 hours (~10-20 CVEs)
# - Auto-detects first run vs. incremental update

# Force full refresh (weekly EPSS update recommended)
python -m scripts.main harvest --cache-dir .cache/ --no-incremental

# Generate briefing from cached data
python -m scripts.main generate-briefing

# Generate with optimized storage (chunked by severity-year)
python -m scripts.main generate-briefing --storage-strategy severity-year

# Update coverage badge in README
python -m scripts.main update-badge

# Send vulnerability alerts to webhooks
python -m scripts.main send-alerts --risk-threshold 80

# Validate EPSS threshold compliance (CI/CD gating)
python -m scripts.main validate-threshold-compliance \
  --api-dir api \
  --cache-dir .cache \
  --output-dir reports \
  --min-epss 0.6 \
  --fail-on-violations

# Clean stale files before build
python -m scripts.cleanup_stale_files \
  --build-dir _site \
  --api-dir api \
  --min-epss 0.6

# Enrich with CISA KEV data
python -m scripts.enhance_cisa_kev --api-dir api/vulns

# Add exploit availability flags and EPSS percentiles
python -m scripts.enhance_exploit_availability --api-dir api/vulns

# Validate data quality at various stages
python -m scripts.validate_data_quality --stage enriched --api-dir api

# ========================================
# SSVC (Stakeholder-Specific Vulnerability Categorization)
# ========================================

# Calculate SSVC decision scores for all CVEs
python -m scripts.processing.ssvc_calculator \
  --input .cache/enriched/ \
  --output api/vulns/ \
  --decision-model deployer

# Validate SSVC coverage and distribution
python -m scripts.validate_ssvc_coverage \
  --api-dir api/vulns \
  --min-coverage 95 \
  --fail-on-violations

# Export SSVC report (CSV format)
python -m scripts.export_ssvc_report \
  --api-dir api/vulns \
  --output reports/ssvc_report.csv

# Run Python linting (Ruff)
ruff check scripts/
ruff format scripts/

# Run Python tests with coverage
pytest --cov=scripts --cov-report=html --cov-report=term tests/

# Run Playwright E2E tests for live site
pip install pytest-playwright playwright
playwright install --with-deps chromium
pytest tests/e2e/test_live_site_sanity.py -v

# Run security checks
bandit -r scripts/ -ll

# CRITICAL: Run comprehensive CI/CD gatecheck validation
python -m scripts.ci_gatecheck \
  --api-dir public/api \
  --max-cve-count 1000 \
  --expected-cve-count 60 \
  --min-epss 0.6 \
  --output-report gatecheck.json \
  --fail-on-warnings
```

### Build & Deployment
```bash
# Install Node dependencies (for linting/formatting only)
npm install

# Build the site (Python-based generation)
npm run build  # Runs: python -m scripts.generate_alpine_dashboard

# Force clean build with validation (recommended for production)
npm run build:force  # Runs: python -m scripts.force_rebuild

# Serve the site locally
npm run serve  # Builds then serves on http://localhost:8000

# Validate build output
npm run validate  # Runs CI gatecheck validation

# Run ESLint (Google style guide)
npm run lint

# Run Prettier formatting
npm run format

# Run all pre-commit checks
npm run precommit

# Deploy to GitHub Pages
npm run deploy
```

### ⚠️ IMPORTANT: Build System
- **11ty has been REMOVED** - Site generation is now Python-only
- All builds use `scripts/generate_alpine_dashboard.py`
- Force rebuilds use `scripts/force_rebuild.py`
- No incremental builds - always clean generation

### Git Workflow
```bash
# Commits go through Husky pre-commit hooks automatically
# Commit messages must follow conventional commit format
git commit -m "type(scope): description"

# Make Husky scripts executable (first time setup)
chmod +x .husky/pre-commit .husky/commit-msg
```

## Architecture Overview

### CVE 5.0 Native Schema (Migration Status)

**Current State**: The system is in transition from legacy transformed schema to CVE 5.0 native storage.

#### What is CVE 5.0?

CVE Record Format 5.0 is the official schema from the CVE Program for vulnerability data. It provides:
- **Structured Metadata**: `cveMetadata` contains CVE ID, dates, state information
- **Container Model**: `containers` holds data from different providers
  - `containers.cna`: CVE Numbering Authority (official vulnerability data)
  - `containers.adp[]`: Array of Additional Data Providers (enrichments)

#### Migration Progress

**✅ Completed**:
- CVE 5.0 data models added to `scripts/models.py`
  - `Vulnerability.raw_cve_v5` field to store original CVE 5.0 JSON
  - `_to_cve_v5_with_enrichments()` method to add enrichments to `containers.adp[]`
  - `_to_legacy_detail_dict()` for backward compatibility
- CVE 5.0 enrichment structure designed:
  - EPSS scores → `containers.adp[]` with `providerMetadata.shortName: "EPSS"`
  - SSVC decisions → `containers.adp[]` with `providerMetadata.shortName: "SSVC"`
  - CISA KEV data → `containers.adp[]` with `providerMetadata.shortName: "CISA-ADP"`
  - VulnBot enrichments → `containers.adp[]` with `providerMetadata.orgId: "vulnbot-enrichment"`

**⏳ In Progress / Planned**:
- Harvest pipeline: Store raw CVE 5.0 JSON in `Vulnerability.raw_cve_v5`
- Enrichment agents: Append to `containers.adp[]` instead of transforming
- API generation: Output native CVE 5.0 format with enrichments
- Frontend: Parse CVE 5.0 structure for display

#### Current Workaround

While migration is in progress, the system uses **legacy transformation**:
1. Raw CVE data fetched from CVEProject/cvelistV5
2. Parsed into Pydantic `Vulnerability` model (loses original structure)
3. Enrichments added as Pydantic fields (not in `containers.adp[]`)
4. Transformed to custom JSON via `to_summary_dict()` and `to_detail_dict()`
5. Output schema: Custom format with fields like `cveId`, `severity`, `epssScore`, `ssvc`, `enrichments`

#### Future CVE 5.0 Native Flow

Once migration is complete:
1. Raw CVE 5.0 JSON stored in `Vulnerability.raw_cve_v5`
2. Enrichments appended to `containers.adp[]` with proper providerMetadata
3. API outputs native CVE 5.0 format (no transformation)
4. Frontend extracts data from CVE 5.0 structure
5. Full compatibility with CVE Program ecosystem

#### Why CVE 5.0 Native?

**Benefits**:
- **Standardization**: Follows official CVE Program schema
- **Interoperability**: Compatible with other CVE 5.0 tools
- **Provenance**: Clear attribution of enrichments to providers
- **Extensibility**: Easy to add new enrichment providers
- **No Data Loss**: Preserves original CVE structure

**Drawbacks of Current Transformation**:
- Loses original CVE 5.0 structure
- Custom schema requires maintenance
- Not compatible with CVE 5.0 ecosystem
- Enrichment attribution unclear

---

### Data Flow

**Current Schema**: Legacy transformed format (CVE 5.0 migration in progress)

1. **Scheduled Harvesting** (Python scripts in `scripts/`, runs every 4 hours):
   - **Pre-build cleanup**: Removes stale files from previous builds
   - Fetches from multiple sources:
     - CVEProject/cvelistV5 repository (official CVE List, updated every 7 minutes)
     - GitHub Security Advisory Database (via GraphQL API)
   - **Data Transformation**: Raw CVE data is parsed and transformed into Pydantic models
     - Currently uses legacy transformation (to_summary_dict, to_detail_dict)
     - CVE 5.0 native storage planned for future phase
   - Filters for Critical/High severity CVEs from 2024-2025 with EPSS scores ≥ 60%
   - **Multi-stage enrichment**:
     - EPSS API data with percentile rankings (flags top 1%, 5%, 10%)
     - CISA KEV catalog integration (Known Exploited Vulnerabilities)
     - Exploit availability detection from multiple sources (Exploit-DB, Metasploit, GitHub PoCs)
     - deps.dev package impact analysis for supply chain visibility (implemented in `scripts/agents/deps_dev_enrichment_agent.py`)
     - **SSVC (Stakeholder-Specific Vulnerability Categorization)**: 4-factor decision tree (Exploitation, Automatable, Technical Impact, Mission Impact) with priority tier assignment (ACT/ATTEND/TRACK)
     - Reference categorization (exploit, patch, advisory, vendor, technical)
   - Calculates derived metrics:
     - **Risk Score (0-100)**: Based on CVSS, EPSS, popularity, infrastructure tags, and newness
     - **SSVC Priority**: Decision-tree based prioritization (ACT, ATTEND, TRACK)
   - **Deduplication**: Uses `VulnerabilityNormalizer.deduplicate_vulnerabilities()` to merge duplicate CVE records from multiple sources
   - **Data validation** at each stage (raw, filtered, enriched, published)
   - Caches responses in SQLite using GitHub Actions cache (10-day TTL, timezone-aware)

2. **Content Generation** (Python-based):
   - `scripts/generate_tailwind_dashboard.py` (formerly generate_alpine_dashboard.py) creates single-page dashboard
   - Uses Pydantic models to transform data via `to_summary_dict()` and `to_detail_dict()` methods
   - Generates chunked vulnerability data files at `api/vulns/vulns-{{year}}-{{severity}}.json`
   - Builds consolidated search index at `api/vulns/index.json`
   - Creates chunk index at `api/vulns/chunk-index.json` for navigation
   - Output directory: `public/`
   - **Note**: Currently outputs legacy transformed schema, not CVE 5.0 native format

3. **Frontend** (Alpine.js + Fuse.js):
   - Client-side filtering UI on the homepage
   - Real-time search/filter on: CVE ID, severity, CVSS/EPSS scores, date ranges, vendors, exploitation status, **SSVC priority tiers**, **exploitability profiles**
   - URL hash-based state for shareable filtered views
   - Paginated results (10/20/50/100 rows, default 50)
   - **SSVC Integration**:
     - Sortable SSVC Priority column with color-coded badges (🔴 ACT, 🟠 ATTEND, 🔵 TRACK)
     - SSVC Priority filter (All, ACT, ATTEND, TRACK)
     - Exploitability Profile filter (All, Active, PoC, None)
     - CSV export with SSVC Priority and Compact Notation columns
   - **Data Visualization Dashboard** (Canvas-based for performance):
     - Severity distribution pie chart
     - Risk trend line chart (30-day vulnerability patterns)
     - EPSS score distribution bar chart
     - Top vendor risk horizontal bar chart
     - Keyboard accessible chart navigation (Arrow keys, Home/End)
     - Screen reader descriptions and announcements
     - Chart export functionality for security reports
   - **Mobile-First Responsive Design**:
     - Touch gesture support (swipe for pagination)
     - Collapsible filter sections
     - Auto-hide filters on mobile after use
     - Optimized layouts for all screen sizes
   - Interactive CVE detail modal with:
     - Overview, Technical Details, Timeline, References, and **SSVC Decision** tabs
     - **SSVC Tab Features**:
       - Complete decision tree visualization (Exploitation, Automatable, Technical Impact, Mission Impact)
       - Priority tier with action guidance (ACT: immediate, ATTEND: scheduled, TRACK: monitor)
       - Compact notation display (e.g., "SSVC:E:A/A:N/T:T/M:M = ACT")
       - Inference flags when data is missing
       - Keyboard shortcut: Alt+5 for SSVC tab
     - WCAG 2.1 AA accessibility compliance
     - Keyboard navigation (Esc to close, Alt+1-5 for tabs)
     - Focus management and screen reader support
   - **Enhanced Accessibility & UX**:
     - Comprehensive keyboard shortcuts (/, r, e, ←/→, 1-5, ?, Esc)
       - Alt+1-5: Switch between modal tabs (Overview, Technical, Timeline, References, SSVC)
       - ←/→: Navigate between vulnerabilities
       - /: Focus search box
       - r: Reset filters
       - e: Export CSV
       - ?: Show keyboard shortcuts help
       - Esc: Close modal
     - Screen reader announcements for filter results
     - High contrast mode support
     - Reduced motion preferences respected
     - CSV export functionality with SSVC columns and analytics tracking

### Key Directories
- `scripts/` - Python vulnerability harvesting and processing scripts
  - `harvest/` - Data harvesting clients:
    - `orchestrator.py` - Main harvest orchestration
    - `cvelist_client.py` - CVEProject/cvelistV5 integration
    - `github_advisory_client.py` - GitHub Advisory Database
    - `epss_client.py` - EPSS API client
    - `nvd_client.py` - NVD API client
  - `agents/` - Modular enrichment and validation agents:
    - `deps_dev_enrichment_agent.py` - Package dependency analysis (deps.dev)
    - Data validation, cleanup, CISA KEV, exploit availability agents
  - `processing/` - Data processing and scoring:
    - `risk_scorer.py` - Risk score calculation (0-100)
    - `ssvc_calculator.py` - SSVC decision tree (ACT/ATTEND/TRACK)
    - `normalizer.py` - Data normalization
    - `briefing_generator.py` - Briefing generation
    - `cache_manager.py` - SQLite caching
  - `generate_alpine_dashboard.py` - Main dashboard generator (replaces 11ty)
  - `force_rebuild.py` - Force rebuild with validation
  - `ci_gatecheck.py` - CI/CD validation
- `src/` - Source templates and assets (used by Python generator)
  - `assets/ts/` - TypeScript components:
    - `components/` - CveModal, DataVisualization, SecurityAlerts, WidgetManager, etc.
    - `types/` - Type definitions
    - `analytics.ts` - Frontend analytics
    - `dashboard.ts` - Dashboard Alpine.js component
  - `api/` - API data templates (chunked JSON files)
- `public/` - Built static site (output directory, deployed to gh-pages)
- `tests/` - Test suite (391 tests, actual coverage: 6.37%)
  - `e2e/` - Playwright end-to-end tests for live site validation
  - `*.test.ts` - TypeScript unit tests (6 test files)
- `.github/workflows/` - CI/CD pipelines
  - `scheduled-harvest.yml` - Main harvest pipeline (incremental harvesting)
  - `post-deploy-qa.yml` - Post-deployment validation
  - `ci.yml` - CI checks (11ty removed)

### CI/CD Pipeline
- **Scheduled Build**: Runs harvesting every 4 hours (`.github/workflows/scheduled-harvest.yml`):
  - Pre-build cleanup to remove stale files
  - **Incremental harvesting** (default): Only CVEs updated in last 48 hours (~10-20 CVEs per run)
  - **Initial harvest**: EPSS-first filtering (~100 CVEs instead of 15,000)
  - Multi-stage data validation (raw, filtered, enriched, published)
  - CISA KEV and exploit availability enrichment
  - EPSS threshold compliance validation (fails on violations)
  - Python-based dashboard generation (no 11ty)
  - Post-build verification for stale files
  - Commits artifacts to main, deploys to gh-pages
- **Post-Deploy QA**: Automated Playwright tests (`.github/workflows/post-deploy-qa.yml`):
  - Validates live site data integrity
  - Ensures no CVEs below 60% EPSS
  - Checks threat intel enrichments render correctly
  - Fails if stale data detected
- **Quality Gates**:
  - **EPSS Threshold Compliance**: All vulnerabilities must meet ≥60% EPSS threshold
  - **Data Validation**: Multi-stage validation at ingestion, filtering, enrichment, and publication
  - Linting: Ruff (Python), ESLint (JavaScript)
  - Tests: 80% coverage target (actual: 6.37% due to legacy untested code)
  - Security: Bandit, npm audit
  - **Stale File Detection**: Verifies no outdated CVE pages remain
- **Automated Deployment**: GitHub Pages, blocked on threshold/validation failures

### API Keys Required
Environment secrets needed in GitHub Actions:
- `GITHUB_TOKEN` - GitHub API access (for cloning CVEProject/cvelistV5)
- `EPSS_API_KEY` - EPSS API access (optional, for enrichment)

### Testing Strategy (Verified: 2025-10-19)

**Python Testing** (Source: `pytest --collect-only` and `pytest --cov=scripts`):
- **Tests Collected**: 399 tests (with 1 collection error)
- **Collection Errors**:
  - `tests/test_nvd_client.py` - import error
  - `tests/test_reference_analysis.py` - import error
- **Coverage Target**: 80% (aspirational, not yet achieved)
- **Actual Coverage**: 6% (8,978 statements total, 8,312 missing)
- **Coverage Note**: Low overall coverage due to many untested legacy files. New modules have higher individual coverage but are not reflected in aggregate metric.

**E2E Testing** (Playwright - tests/e2e/):
- Live site validation after deployment
- CVE count validation (expected: varies based on harvest, currently 3 in production)
- EPSS threshold compliance check (all CVEs ≥60%)
- Threat intel enrichment verification (CISA KEV flags, exploit badges)
- API endpoint accessibility tests
- Stale data detection

**Frontend Testing**:
- **TypeScript Tests**: 6 test files (`.test.ts`)
- **Note**: No Vitest configuration exists despite documentation claims
- Tests use basic TypeScript/Jest setup
- **Actual Test Framework**: Standard npm test runner

**Data Quality Testing**:
- Multi-stage validation via modular agents
- Raw data validation (schema compliance)
- Filtered data validation (EPSS threshold enforcement)
- Enriched data validation (CISA KEV, exploit flags)
- Published data validation (API schema compliance)

**Security Testing**:
- **Python**: Bandit static analysis (high/critical severities fail build)
- **JavaScript**: npm audit (production dependencies only)
- **Secrets**: TruffleHog scanning (not yet implemented)
- **SAST**: CodeQL scanning (GitHub Security - not yet enabled)

**Code Quality**:
- **Python Linting**: Ruff (zero errors enforced)
- **JavaScript Linting**: ESLint with Google style guide
- **Formatting**: Prettier for JavaScript, Ruff for Python
- **Pre-commit Hooks**: Husky enforces linting and formatting checks

**Performance Testing**:
- **Lighthouse CI**: Not yet implemented (claimed in docs but no config exists)
- **Load Testing**: Not implemented
- **Benchmark Suite**: Not implemented

### Deployment
- Static site deployed to GitHub Pages from `gh-pages` branch
- **Build System**: Python-based generation (11ty removed)
  - Always clean builds (no incremental mode)
  - `scripts/generate_alpine_dashboard.py` generates site
  - `scripts/force_rebuild.py` for validated rebuilds
- **GitHub Pages CDN Behavior**:
  - May cache files for 10-15 minutes after deployment
  - Use post-deployment validation to ensure propagation
  - Force refresh browsers after deployment
- No backend servers required - fully client-side Alpine.js functionality
- Coverage badges can be updated via `update-badge` command (if implemented)

### Troubleshooting Stale Data / 15,000+ CVE Issue
If the live site shows thousands of CVEs instead of ~60:
1. **Immediate Fix**: Run `npm run build:force` then `npm run deploy`
2. **Detailed Instructions**: See `docs/TROUBLESHOOTING.md`
3. **Root Cause**: Fixed by removing 11ty and implementing incremental harvesting
4. **Prevention**: Python generator always does clean builds
5. **Incremental Harvesting**: Default mode processes only recent CVEs (48-hour window)

## Performance Optimization Guide

### Frontend Performance Enhancements

#### 1. Debounced Search Implementation
```javascript
// Alpine.js component with debounced search
Alpine.data('vulnDashboard', () => ({
    searchQuery: '',
    // Use Alpine's built-in debounce modifier
    // In template: x-model.debounce.300ms="searchQuery"
}))
```

#### 2. Web Worker for Filtering
The dashboard automatically uses a Web Worker for datasets > 100 items:
```javascript
// Filtering logic runs in separate thread
if (this.vulnerabilities.length > 100 && window.Worker) {
    const results = await this.filterWithWorker(this.vulnerabilities, this.searchQuery, this.filters);
}
```

#### 3. Virtual Scrolling
Automatically enabled for datasets > 500 items:
```javascript
// Only renders visible rows
if (this.vulnerabilities.length > 500) {
    this.virtualScrolling.enabled = true;
}
```

#### 4. Session Storage Caching
5-minute TTL cache to minimize API calls:
```javascript
// Check cache before fetching
const cachedData = sessionStorage.getItem('vuln-data');
const cacheAge = Date.now() - parseInt(sessionStorage.getItem('vuln-data-timestamp'));
if (cachedData && cacheAge < 5 * 60 * 1000) {
    return JSON.parse(cachedData);
}
```

### Backend Performance Tips

#### 1. Chunked Data Strategy
```python
# Generate chunked files by severity and year
python -m scripts.main generate-briefing --storage-strategy severity-year
```

#### 2. SQLite Cache Usage
```python
# Cache manager with 10-day TTL
cache_manager = CacheManager(cache_dir=".cache", ttl_days=10)
```

#### 3. Great Expectations Integration
```python
# Run validation without blocking pipeline
python scripts/integrate_gx_validation.py --enable-validation
```

### Performance Benchmarks

Run performance tests:
```bash
# Frontend performance with Lighthouse
npm run lighthouse

# Backend processing time
time python -m scripts.main harvest --cache-dir .cache/

# E2E performance tests
pytest tests/playwright_live_test.py -v
```

### Common Performance Issues

1. **Slow Search/Filter**: Ensure debouncing is enabled and Web Worker is functioning
2. **High Memory Usage**: Check if virtual scrolling is enabled for large datasets
3. **Slow Page Load**: Verify chunked storage strategy is active
4. **API Rate Limits**: Check cache hit rates and TTL configuration

## 🚨 Critical Production Issues & Solutions

### The 15,000+ CVE Data Issue (Resolved)

**Problem**: Production site was showing 15,000+ CVEs instead of the expected ~30 CVEs after implementing EPSS 60% threshold filtering.

**Root Cause**: 
- Incremental builds were preserving stale data files
- GitHub Pages caching prevented proper cleanup
- Static site generators accumulated files over multiple deployments

**Critical Solution** (Implemented):
```bash
# Use force rebuild command (always clean)
npm run build:force
# Or manually:
python -m scripts.force_rebuild --expected-count 60 --min-epss 0.6
```

**Prevention Measures** (Implemented):
1. **Removed 11ty**: Eliminated incremental build issues
2. **Incremental Harvesting**: Process only recent CVEs (48-hour window)
3. **CI/CD Gatecheck**: All deployments pass validation (`scripts/ci_gatecheck.py`)
4. **Live Site Monitoring**: Post-deployment Playwright tests
5. **EPSS-First Filtering**: Initial harvest ~100 CVEs instead of 15,000

### Critical Validation Commands

```bash
# Pre-deployment validation (REQUIRED)
python -m scripts.ci_gatecheck \
  --api-dir public/api \
  --max-cve-count 1000 \
  --expected-cve-count 60 \
  --min-epss 0.6 \
  --fail-on-warnings

# Post-deployment validation (automated)
pytest tests/e2e/test_live_site_sanity.py -v

# Emergency force rebuild (if 15,000+ issue detected)
python -m scripts.force_rebuild \
  --expected-count 60 \
  --min-epss 0.6
```

### Developer Guidelines

**❌ NEVER DO**:
- ~~Use incremental builds~~ (11ty removed, not applicable)
- Deploy without running gatecheck validation
- Ignore CVE count warnings in CI/CD
- Bypass EPSS threshold validation

**✅ ALWAYS DO**:
- Use `npm run build` or `npm run build:force` for builds
- Run `npm run validate` before deployment
- Check live site counts after deployment
- Monitor post-deployment QA test results

### Emergency Response

If production shows >1000 CVEs:

1. **Immediate**: Run force rebuild script
   ```bash
   npm run build:force
   ```
2. **Validate**: Check gatecheck passes locally
   ```bash
   npm run validate
   ```
3. **Deploy**: Force push to gh-pages branch
   ```bash
   npm run deploy
   ```
4. **Monitor**: Wait 10+ minutes for CDN propagation
5. **Confirm**: Run live site validation tests
   ```bash
   npm run test:e2e
   ```

📋 **For detailed troubleshooting procedures, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)**

---

## 📋 Documentation Verification Commands

**Use these commands to verify all claims in this documentation are accurate:**

### Verify CVE Counts
```bash
# Get actual CVE count from production API
python3 -c "import json; data=json.load(open('public/api/vulns/index.json')); print(f'CVE Count: {len(data)}')"

# Count API files generated
ls -la public/api/vulns/*.json | wc -l
```

### Verify Test Metrics
```bash
# Get actual test count
pytest --collect-only 2>&1 | grep "collected"

# Get actual coverage
pytest --cov=scripts --cov-report=term 2>&1 | grep "TOTAL"

# Count test files
find tests/ -name "*.test.ts" -o -name "test_*.py" | wc -l
```

### Verify Data Freshness
```bash
# Check when API data was last generated
stat -c '%y' public/api/vulns/index.json

# Calculate data age in days
python3 -c "
from datetime import datetime
import os
mtime = os.path.getmtime('public/api/vulns/index.json')
age_days = (datetime.now().timestamp() - mtime) / 86400
print(f'Data age: {age_days:.0f} days')
"
```

### Verify Build Configuration
```bash
# Check if 11ty is actually removed
grep -r "@11ty/eleventy" package.json 2>/dev/null && echo "❌ 11ty still present" || echo "✅ 11ty removed"

# Check actual npm scripts
npm run 2>&1 | grep -E "build|test|serve"
```

### Verify Coverage Claims
```bash
# Run full coverage report and save to file
pytest --cov=scripts --cov-report=term --cov-report=html 2>&1 | tee coverage_verification.txt

# Extract exact coverage percentage
grep "TOTAL" coverage_verification.txt | awk '{print "Coverage: " $4}'
```

### Audit Documentation for Unverified Claims
```bash
# Find percentage claims in documentation
grep -oP '\d+(\.\d+)?%' CLAUDE.md | sort -u

# Find CVE count claims
grep -oP '\d+\s+(CVEs?|vulnerabilities)' CLAUDE.md

# Find test count claims
grep -oP '\d+\s+tests?' CLAUDE.md

# Find superlatives (potential exaggerations)
grep -iE 'best|world-class|industry-leading|comprehensive|complete' CLAUDE.md
```

### Generate Verification Report
```bash
# Create a verification report with all metrics
cat > docs/verification_report.md <<EOF
# Documentation Verification Report
Generated: $(date -u +"%Y-%m-%d %H:%M UTC")

## Data Metrics
$(python3 -c "import json; data=json.load(open('public/api/vulns/index.json')); print(f'- CVE Count: {len(data)}')")
- EPSS Threshold: ≥60% (from scripts/main.py)
- Data Age: $(python3 -c "from datetime import datetime; import os; age=(datetime.now().timestamp()-os.path.getmtime('public/api/vulns/index.json'))/86400; print(f'{age:.0f} days')")

## Test Metrics
$(pytest --collect-only 2>&1 | grep "collected")
$(pytest --cov=scripts --cov-report=term 2>&1 | grep "TOTAL")

## Build Status
- Build System: Python-based
- 11ty Status: $(grep -q "@11ty/eleventy" package.json 2>/dev/null && echo "Present (ERROR)" || echo "Removed (OK)")
- Last Build: $(stat -c '%y' public/api/vulns/index.json)

## Documentation Audit
- Percentage Claims: $(grep -oP '\d+(\.\d+)?%' CLAUDE.md | wc -l)
- CVE Count Claims: $(grep -oP '\d+\s+(CVEs?|vulnerabilities)' CLAUDE.md | wc -l)
- Superlatives Found: $(grep -iEc 'best|world-class|industry-leading' CLAUDE.md)
EOF

cat docs/verification_report.md
```

**Run this verification before any documentation updates to ensure accuracy.**