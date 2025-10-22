# Dashboard Chart Fixes

**Date**: 2025-10-22
**Issues Fixed**: Top 10 Vendors chart stale data, EPSS distribution chart showing no spread
**Status**: ✅ RESOLVED

## Problem 1: Vendor Chart Showing Stale Data

**Symptom**: Live website vendor chart displayed problematic vendor names (The, N/a, Web) despite source data being cleaned.

**Root Cause**:
- Previous vendor cleaning only updated `api/vulns/index.json` (source)
- Dashboard generator read from `api/vulns/` but didn't copy to `public/api/`
- Browser loaded stale data from `public/api/vulns/index.json`
- Build pipeline had no step to sync API files to deployment directory

**Solution**:
1. Updated `package.json` build scripts to include API file copy:
   ```json
   "build": "npm run clean && python -m scripts.generate_tailwind_dashboard && cp -r api/vulns public/api/"
   ```
2. Fixed incorrect script reference (`generate_alpine_dashboard` → `generate_tailwind_dashboard`)
3. Copied cleaned API files to deployment directory

**Verification**:
```bash
# Before fix - problematic vendors in deployed data:
python3 -c "import json; data=json.load(open('public/api/vulns/index.json')); vendors={}; [vendors.update({v: vendors.get(v,0)+1}) for vuln in data['vulnerabilities'] for v in vuln.get('vendors',[])]; print({k:v for k,v in vendors.items() if k.lower() in ['the','n/a','web','file']})"
# Output: {'The': 50, 'N/a': 11, 'Web': 6, 'File': 3}

# After fix - problematic vendors removed:
# Output: {} (empty dict)
```

## Problem 2: EPSS Distribution Chart - No Spread

**Symptom**: All 297 CVEs displayed in single 95-100% bucket, other buckets empty.

**Root Cause**:
- Chart code used `v.epss_percentile` instead of `v.epss_score` (line 1034)
- `epss_percentile` = ranking percentile (0-100 showing how score ranks vs all CVEs)
- Most high-risk CVEs have percentile 95-100% (they rank highly)
- `epss_score` = actual exploitation probability (0-100 percentage)
- EPSS scores have good distribution across 60-95% range

**Solution**:
Changed line 1034 in `scripts/generate_tailwind_dashboard.py`:
```javascript
// Before (WRONG):
const epss = v.epss_percentile;

// After (CORRECT):
const epss = v.epss_score;
```

**Expected Distribution** (verified locally):
```bash
python3 -c "
import json
data = json.load(open('public/api/vulns/index.json'))
vulns = data['vulnerabilities']
buckets = {'60-70%':0, '70-80%':0, '80-90%':0, '90-95%':0, '95-100%':0}
for v in vulns:
    epss = v.get('epssScore', 0)
    if epss >= 95: buckets['95-100%'] += 1
    elif epss >= 90: buckets['90-95%'] += 1
    elif epss >= 80: buckets['80-90%'] += 1
    elif epss >= 70: buckets['70-80%'] += 1
    elif epss >= 60: buckets['60-70%'] += 1
print(buckets)
"
# Output: {'60-70%': 50, '70-80%': 53, '80-90%': 77, '90-95%': 117, '95-100%': 0}
```

## Files Modified

```
scripts/generate_tailwind_dashboard.py (line 1034 - EPSS fix)
package.json (lines 8, 10 - build script fixes)
public/index.html (auto-regenerated with fixes)
public/api/vulns/*.json (synced from cleaned source data)
```

## Deployment

**Commit**: `3beb2dc73` - "fix(dashboard): fix EPSS distribution chart using wrong field"
**Deployment**: GitHub Actions Pages workflow
**URL**: https://williamzujkowski.github.io/vuln-bot/

## Verification Commands

### Verify EPSS distribution locally:
```bash
python3 << 'EOF'
import json
with open('public/api/vulns/index.json') as f:
    data = json.load(f)
vulns = data['vulnerabilities']
buckets = {'60-70%':0, '70-80%':0, '80-90%':0, '90-95%':0, '95-100%':0}
for v in vulns:
    epss = v.get('epssScore', 0)
    if epss >= 95: buckets['95-100%'] += 1
    elif epss >= 90: buckets['90-95%'] += 1
    elif epss >= 80: buckets['80-90%'] += 1
    elif epss >= 70: buckets['70-80%'] += 1
    elif epss >= 60: buckets['60-70%'] += 1
print("EPSS Distribution:", buckets)
print(f"Total distributed: {sum(buckets.values())}/{len(vulns)}")
EOF
```

### Verify vendor data cleanup:
```bash
python3 -c "
import json
with open('public/api/vulns/index.json') as f:
    data = json.load(f)
vendors = {}
for vuln in data['vulnerabilities']:
    for v in vuln.get('vendors', []):
        vendors[v] = vendors.get(v, 0) + 1
problematic = {k:v for k,v in vendors.items() if k.lower() in ['the', 'n/a', 'web', 'file', 'application', 'server']}
print('Problematic vendors:', problematic if problematic else 'None found ✅')
"
```

## Lessons Learned

1. **Build Pipeline Gaps**: Always verify deployment directory matches source after cleaning operations
2. **Field Naming Confusion**: Similar field names (epss_score vs epss_percentile) can cause subtle bugs
3. **Data Validation**: Charts should have data distribution tests to catch "all in one bucket" issues
4. **Script References**: After file renames, audit all references in `package.json` and docs

## Future Improvements

1. Add automated test for EPSS distribution to catch this type of bug
2. Add CI/CD check to ensure `public/api/` stays in sync with `api/`
3. Consider renaming `epss_percentile` to `epss_ranking` for clarity
4. Add chart data validation in dashboard generator
