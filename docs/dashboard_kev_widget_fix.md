# KEV Widget Fix

**Date**: 2025-10-22
**Issue**: KEV Listed widget showing 0 instead of 75
**Status**: ✅ RESOLVED

## Problem

KEV (Known Exploited Vulnerabilities) widget was displaying "0" despite 75 CVEs being enriched with CISA KEV data in the source API files.

## Root Cause

**Incorrect Field Check**:
```python
# scripts/generate_tailwind_dashboard.py line 66 (BEFORE):
"kev": v.get("exploitationStatus") == "KNOWN_EXPLOITED",
```

**Why This Failed**:
- The `exploitationStatus` field contains values like `"EXPLOIT_AVAILABLE"`, not `"KNOWN_EXPLOITED"`
- CISA KEV enrichments are stored in the `enrichments.cisa_kev.isKnownExploited` field
- Dashboard was checking the wrong field, resulting in 0 matches

## Solution

**Correct Field Check** (line 66):
```python
# scripts/generate_tailwind_dashboard.py line 66 (AFTER):
"kev": v.get("enrichments", {}).get("cisa_kev", {}).get("isKnownExploited", False),
```

**How It Works**:
- Checks the `enrichments.cisa_kev.isKnownExploited` boolean field
- This field is populated by the CISA KEV enrichment agent during data harvesting
- Returns `False` if enrichment doesn't exist (safe fallback)

## Data Verification

**Before Fix**:
```python
# Check showing 0 KEV CVEs
python3 -c "
import json
data = json.load(open('api/vulns/index.json'))
kev_count = sum(1 for v in data['vulnerabilities'] if v.get('exploitationStatus') == 'KNOWN_EXPLOITED')
print(f'KEV Count (exploitationStatus): {kev_count}')
"
# Output: KEV Count (exploitationStatus): 0
```

**After Fix**:
```python
# Check showing 75 KEV CVEs
python3 -c "
import json
data = json.load(open('api/vulns/index.json'))
kev_count = sum(1 for v in data['vulnerabilities']
                if v.get('enrichments', {}).get('cisa_kev', {}).get('isKnownExploited', False))
print(f'KEV Count (enrichments.cisa_kev): {kev_count}')
"
# Output: KEV Count (enrichments.cisa_kev): 75 ✅
```

## Sample KEV CVE Data Structure

```json
{
  "cveId": "CVE-2025-47812",
  "exploitationStatus": "EXPLOIT_AVAILABLE",
  "enrichments": {
    "cisa_kev": {
      "isKnownExploited": true,
      "dateAdded": "2025-07-14",
      "vulnerabilityName": "Wing FTP Server Improper Neutralization...",
      "requiredAction": "Apply mitigations per vendor instructions...",
      "dueDate": "2025-08-04",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "https://www.wftpserver.com/serverhistory.htm ; ..."
    }
  }
}
```

## Files Modified

```
scripts/generate_tailwind_dashboard.py (line 66)
public/index.html (auto-regenerated with fix)
```

## Build Verification

```bash
$ python -m scripts.generate_tailwind_dashboard
Loading vulnerabilities...
✅ Tailwind dashboard generated successfully!
📁 Output: public/index.html
📊 Statistics:
   • Total CVEs: 297
   • Critical: 186
   • High: 111
   • KEV Listed: 75 ✅  # Was 0 before fix
```

## Deployment

**Commit**: `1a5839933` - "fix(dashboard): KEV widget now shows correct count (75 instead of 0)"
**Deployment**: GitHub Actions Pages workflow
**URL**: https://williamzujkowski.github.io/vuln-bot/

## Lessons Learned

1. **Field Naming Confusion**: `exploitationStatus` vs `enrichments.cisa_kev.isKnownExploited` - different purposes
2. **Data Source Verification**: Always verify the actual field structure in source data before writing queries
3. **Safe Nested Access**: Use `.get()` chains with defaults for nested dictionary access
4. **Build-Time Validation**: Dashboard generator should validate critical metrics during build

## Prevention

- Add data validation in dashboard generator to warn if KEV count is unexpectedly 0
- Document field mappings in CLAUDE.md for future reference
- Add unit tests for KEV count calculation

## Related Issues

- Part of user request: "the KEV listed widget is showing 0 results please fix"
- Related to broader dashboard chart accuracy improvements
- Complements vendor chart and EPSS distribution fixes
