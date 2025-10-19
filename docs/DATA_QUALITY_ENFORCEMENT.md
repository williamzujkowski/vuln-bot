# Data Quality & Accuracy Enforcement

**Created**: 2025-10-19
**Purpose**: Enforce strict data accuracy standards in all project documentation and code

## Summary of Changes

### 1. New Data Quality Standards Section in CLAUDE.md

Added comprehensive "📊 **CRITICAL: Data Quality & Accuracy Standards**" section after the time enforcement section with:

- **7 Mandatory Verification Rules**:
  1. Never hallucinate numbers
  2. Use only authoritative sources
  3. Include data freshness checks
  4. Validate all counts and metrics
  5. No exaggerations without data backing
  6. Verify test coverage claims
  7. Cross-reference documentation with reality

- **Enforcement Mechanisms**:
  - CI/CD validation gates
  - Documentation update requirements
  - Red flag patterns to avoid
  - Correction process for detected hallucinations

### 2. Updated Testing Strategy Section

**Replaced aspirational claims with verified metrics**:

#### Before (Unverified):
- "391 tests collected (2 import errors)"
- "6.37% coverage"
- "Vitest configuration" (claimed but not implemented)

#### After (Verified - 2025-10-19):
- **Tests Collected**: 399 tests (verified via `pytest --collect-only`)
- **Collection Errors**: 1 error in tests/test_nvd_client.py
- **Actual Coverage**: 6% (8,978 statements, 8,312 missing - verified via `pytest --cov`)
- **Coverage Target**: 80% (aspirational, clearly labeled as target not achievement)
- **Vitest**: Documented as "not implemented despite documentation claims"

### 3. Updated Project Overview

**Added Current Production Status** (Verified: 2025-10-19):
- CVE Count: 3 (verified from public/api/vulns/index.json)
- Data Freshness: ⚠️ STALE (77 days old)
- EPSS Threshold: ≥60% (from scripts/main.py)
- Live Site: https://williamzujkowski.github.io/vuln-bot/
- Build System: Python-based (11ty removed)

**Note**: Added clarification that low count indicates stale data, expected 60-100 CVEs after fresh harvest.

### 4. Added Documentation Verification Commands

New section at end of CLAUDE.md with commands to verify all claims:

- **Verify CVE Counts**: Check actual data from API files
- **Verify Test Metrics**: Run pytest to get real numbers
- **Verify Data Freshness**: Calculate actual data age
- **Verify Build Configuration**: Check for 11ty removal
- **Verify Coverage Claims**: Run coverage and extract percentages
- **Audit Documentation**: Find unverified claims
- **Generate Verification Report**: Automated verification script

## Verification Results (2025-10-19 18:10 UTC)

### Actual Metrics (Verified)

```bash
✅ CVE Count: 3 (Source: public/api/vulns/index.json)
✅ Test Count: 399 tests collected, 1 error (Source: pytest --collect-only)
✅ Coverage: 6% (8978 statements, 8312 missing - Source: pytest --cov=scripts)
✅ API Files: 8 JSON files (Source: ls -la public/api/vulns/*.json)
✅ Build System: Python-based, 11ty removed (Source: package.json)
```

### Data Age

```bash
Last Modified: 2025-08-03 (77 days old)
Status: ⚠️ STALE - requires harvest
Expected CVEs After Harvest: ~60-100 (depending on current EPSS scores)
```

### Previous Claims vs Reality

| Claim in Old Docs | Reality (Verified) | Status |
|-------------------|-------------------|--------|
| "30 CVEs" | 3 CVEs | ❌ Hallucination |
| "217 tests passing" | 399 tests (1 error) | ❌ Hallucination |
| "96.67% coverage" | 6% coverage | ❌ Hallucination |
| "Vitest infrastructure" | Not implemented | ❌ Hallucination |
| "Lighthouse CI" | Not implemented | ❌ Hallucination |
| "90% coverage target" | 80% target (6% actual) | ⚠️ Misrepresentation |

## Enforcement Guidelines

### Before Updating Documentation

**REQUIRED STEPS**:
1. ✅ Run `pytest --collect-only` to get actual test count
2. ✅ Run `pytest --cov=scripts --cov-report=term` to get actual coverage
3. ✅ Check `public/api/vulns/index.json` for actual CVE count
4. ✅ Verify all statistics from source data files
5. ✅ Document data sources and verification dates
6. ✅ Include data freshness warnings if data is stale

### Approved Data Sources

**CVE Intelligence**:
- NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities)
- CVEProject/cvelistV5 (official CVE list)
- GitHub Advisory Database

**Exploit Intelligence**:
- FIRST.org EPSS API (Exploit Prediction Scoring)
- Exploit-DB
- Metasploit Framework
- GitHub Security Lab

**Package Ecosystems**:
- npm registry (JavaScript)
- PyPI (Python)
- Maven Central (Java)
- NuGet (C#/.NET)

**Supply Chain Analysis**:
- deps.dev API (Google Open Source)
- OSV.dev (Open Source Vulnerabilities)

### CI/CD Validation Gates

**Proposed GitHub Actions Workflow** (not yet implemented):

```yaml
name: Documentation Quality Gate

on:
  pull_request:
    paths:
      - 'CLAUDE.md'
      - 'README.md'
      - 'docs/**'

jobs:
  verify-claims:
    runs-on: ubuntu-latest
    steps:
      - name: Verify CVE Counts Match
        run: |
          ACTUAL=$(python3 -c "import json; print(len(json.load(open('public/api/vulns/index.json'))))")
          CLAIMED=$(grep -oP '\d+(?= CVEs)' CLAUDE.md | head -1)
          if [ "$ACTUAL" != "$CLAIMED" ]; then
            echo "❌ CVE count mismatch: claimed $CLAIMED, actual $ACTUAL"
            exit 1
          fi

      - name: Verify Test Counts Match
        run: |
          ACTUAL=$(pytest --collect-only 2>&1 | grep -oP '\d+(?= items)')
          CLAIMED=$(grep -oP '\d+(?= tests collected)' CLAUDE.md | head -1)
          if [ "$ACTUAL" != "$CLAIMED" ]; then
            echo "❌ Test count mismatch: claimed $CLAIMED, actual $ACTUAL"
            exit 1
          fi

      - name: Verify Coverage Matches
        run: |
          ACTUAL=$(pytest --cov=scripts 2>&1 | grep "TOTAL" | awk '{print $NF}')
          CLAIMED=$(grep -oP '\d+% coverage' CLAUDE.md | head -1 | grep -oP '\d+')
          if [ "$ACTUAL" != "${CLAIMED}%" ]; then
            echo "❌ Coverage mismatch: claimed ${CLAIMED}%, actual $ACTUAL"
            exit 1
          fi

      - name: Flag Unverified Superlatives
        run: |
          SUPERLATIVES=$(grep -iEc 'best|world-class|industry-leading|comprehensive' CLAUDE.md)
          if [ "$SUPERLATIVES" -gt 0 ]; then
            echo "⚠️ Found $SUPERLATIVES unverified superlatives - please provide data backing"
            grep -in 'best\|world-class\|industry-leading\|comprehensive' CLAUDE.md
          fi
```

## Red Flags to Watch For

🚨 **These patterns indicate potential hallucinations**:

1. **Round Numbers Without Source**
   - "30 CVEs" (when actual is 3)
   - "100 tests" (when actual is 399)
   - "50% coverage" (when actual is 6%)

2. **Percentage Claims Without Verification**
   - "96.67% coverage" (too precise to be rounded estimate)
   - "85% threshold" (without pytest output)

3. **Superlatives Without Benchmarks**
   - "Best-in-class"
   - "Industry-leading"
   - "World-class"
   - "Comprehensive"

4. **Test Counts Without pytest Output**
   - "217 tests passing" (no pytest report provided)
   - "All tests green" (vague claim)

5. **Feature Claims Without Implementation**
   - "Vitest infrastructure complete" (no vitest.config.ts exists)
   - "Lighthouse CI configured" (no .lighthouserc.json exists)

## Correction Process

### When Hallucinations Detected

**Immediate Actions**:
1. 🔍 **Flag**: Mark claim as unverified
2. 🧪 **Verify**: Run actual commands to get real data
3. ✏️ **Correct**: Update documentation with verified metrics
4. 📝 **Document**: Add source citations and verification dates
5. 🛡️ **Prevent**: Add CI/CD checks to catch future discrepancies

### Example Correction

**Before (Hallucinated)**:
```markdown
We track 30 high-risk CVEs with 217 tests achieving 96.67% coverage.
```

**After (Verified - 2025-10-19)**:
```markdown
**Current Status** (Verified: 2025-10-19):
- CVE Count: 3 (Source: public/api/vulns/index.json)
- Data Age: ⚠️ 77 days old (requires harvest)
- Test Count: 399 tests (Source: pytest --collect-only)
- Coverage: 6% (Source: pytest --cov=scripts)
- Expected CVEs After Harvest: ~60-100
```

## Verification Commands Reference

```bash
# CVE Count
python3 -c "import json; print(f'CVEs: {len(json.load(open(\"public/api/vulns/index.json\")))}')"

# Test Count
pytest --collect-only 2>&1 | grep "collected"

# Coverage
pytest --cov=scripts --cov-report=term 2>&1 | grep "TOTAL"

# Data Age
python3 -c "from datetime import datetime; import os; age=(datetime.now().timestamp()-os.path.getmtime('public/api/vulns/index.json'))/86400; print(f'Age: {age:.0f} days')"

# Build System Verification
grep -q "@11ty/eleventy" package.json && echo "11ty present" || echo "11ty removed"
```

## Success Criteria

Documentation is considered **accurate** when:

1. ✅ All CVE counts match actual data files
2. ✅ All test counts match pytest output
3. ✅ All coverage percentages match pytest --cov
4. ✅ All claims have source citations
5. ✅ Data freshness is documented
6. ✅ Superlatives have data backing
7. ✅ Verification date is included
8. ✅ Stale data warnings are present when applicable

## References

- **Authoritative Time**: See CLAUDE.md "CRITICAL: Authoritative Time Enforcement"
- **Data Sources**: See CLAUDE.md "Use Only Authoritative Sources"
- **Testing Strategy**: See CLAUDE.md "Testing Strategy (Verified: 2025-10-19)"
- **Verification Commands**: See CLAUDE.md "Documentation Verification Commands"

---

**Last Updated**: 2025-10-19 18:10 UTC
**Verified By**: Automated verification scripts
**Next Review**: Before any documentation updates
