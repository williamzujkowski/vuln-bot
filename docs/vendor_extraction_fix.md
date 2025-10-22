# Vendor/Product Extraction Fix

**Date**: 2025-10-22
**Issue**: Vendor chart showing common words like "the" (50 occurrences), "n/a" (11), "web" (6), "file" (3)
**Status**: ✅ RESOLVED

## Problem Analysis

The vendor extraction logic in `scripts/processing/vendor_product_extractor.py` contained an overly broad regex pattern (lines 145-150) that was matching common English words from CVE descriptions:

```python
# PROBLEMATIC PATTERN (removed):
(
    r"\b([A-Z][a-z]+)\s+(Server|Database|Framework|Engine|Browser)\b",
    r"\1",  # Captured first word as vendor
    r"\1 \2",  # Full phrase as product
),
```

This pattern matched phrases like:
- "The Server" → extracted "The" as vendor
- "Web Browser" → extracted "Web" as vendor
- "File Server" → extracted "File" as vendor

## Solution Implemented

### 1. Removed Problematic Regex Pattern

**File**: `scripts/processing/vendor_product_extractor.py`
**Lines**: 145-150 (deleted)
**Commit**: `84ff42bef` - "fix(vendor-extraction): remove overly broad text pattern"

Added comment explaining why:
```python
# NOTE: Removed overly broad generic pattern that was catching common words
# like "The", "Web", "File" from descriptions. Structured data from
# affected/CPE fields should be the primary source.
```

### 2. Enhanced Normalization Logic

**File**: `scripts/processing/vendor_product_extractor.py`
**Methods**: `_normalize_vendors()`, `_normalize_products()`

- Preserved multi-word vendor names with proper spacing (e.g., "Red Hat", "Apache Software Foundation")
- Preserved special capitalization (e.g., "iOS", "macOS", "eBay", "jQuery")
- Filtered placeholder values: "n/a", "na", "none", "unknown", "unspecified", "tbd", "pending", "*"
- **Did NOT add stopword filtering** (per user feedback)

### 3. Reprocessed Existing Data

**Script**: `scripts/reprocess_vendors.py` (new utility)
**Files Updated**:
- `api/vulns/index.json`
- `api/vulns/vulns-2024-MEDIUM.json`
- `api/vulns/vulns-2025-MEDIUM.json`
- `api/vulns/vulns-2025-NONE.json`

**Results**:
- 70 CVEs updated
- Vendor count reduced: 229 → 224 (5 invalid entries removed)
- Dashboard regenerated with cleaned data

**Commit**: `22b2df1b5` - "fix(data): clean vendor extraction - remove invalid entries"

## Verification Results

### Live Site Validation (2025-10-22 03:00 UTC)

**Top 10 Vendors (verified on live site)**:
1. WordPress (~70 CVEs)
2. Microsoft (~20 CVEs)
3. Ivanti
4. Oracle
5. Xwiki
6. Progress Software Corporation
7. Solarwinds
8. Red Hat
9. PHP
10. Fortinet

**Problematic Vendors**: ✅ **NONE FOUND**
- ❌ "The" - REMOVED (was 50 occurrences)
- ❌ "N/a" - REMOVED (was 11 occurrences)
- ❌ "Web" - REMOVED (was 6 occurrences)
- ❌ "File" - REMOVED (was 3 occurrences)
- ❌ "Application" - REMOVED (was 2 occurrences)

### Known Remaining Issues

**Product Names** (lower priority):
- Multi-word phrases like "The Server" (26), "The Database" (23), "Web Server" (5) still appear in the Products column
- These are complete phrases from existing data, not single-word vendor entries
- Future harvests will not generate these (regex pattern fixed)
- Can be addressed with extended reprocessing if needed

## Data Sources Priority

After this fix, vendor/product extraction prioritizes:

1. **Structured CVE data** (affected fields, CPE strings) - PRIMARY
2. **Specific product patterns** (Microsoft Windows, Adobe Flash, etc.)
3. **Reference URLs** (domain-based vendor inference)
4. ~~**Generic text patterns**~~ - REMOVED (too broad)

## Testing

### Pre-deployment Validation
```bash
python -m scripts.reprocess_vendors
# Output: ✅ Total CVEs updated: 70

python -m scripts.generate_alpine_dashboard
# Output: ✅ Dashboard generated with 224 unique vendors
```

### Post-deployment Validation
```bash
# Playwright browser verification
# URL: https://williamzujkowski.github.io/vuln-bot/
# Top vendor chart: ✅ All legitimate vendor names
# No problematic single-word entries found
```

## Lessons Learned

1. **User Feedback Was Critical**: Initial approach (stopword filtering) was rejected by user who wanted root cause fixed, not workarounds
2. **Structured Data > Text Extraction**: CVE affected fields and CPE strings are more reliable than description text parsing
3. **Multi-word Preservation**: Vendor/product names often contain spaces and special capitalization that must be preserved
4. **Reprocessing Utility**: Created reusable script for cleaning existing data when extraction logic changes

## Future Improvements

1. **Product Name Cleanup**: Extend reprocessing to also clean multi-word product artifacts
2. **CPE Validation**: Add validation against official CPE dictionary
3. **Manual Vendor Mappings**: Expand vendor_mappings dictionary for better normalization
4. **Automated Testing**: Add unit tests for vendor extraction edge cases

## Files Modified

```
scripts/processing/vendor_product_extractor.py (lines 145-150 removed, normalization enhanced)
scripts/reprocess_vendors.py (new utility script)
api/vulns/index.json (70 CVEs cleaned)
api/vulns/vulns-*.json (chunk files updated)
public/index.html (dashboard regenerated)
```

## References

- Issue: Vendor chart showing "the" with 50+ results
- Fix Commit: `84ff42bef` (pattern removal)
- Data Commit: `22b2df1b5` (reprocessed data)
- Live Site: https://williamzujkowski.github.io/vuln-bot/
