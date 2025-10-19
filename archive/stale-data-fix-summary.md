# Stale Data Fix Summary

## Problem Statement

The Vuln-Bot live site was showing ~15,000 CVEs instead of the expected ~60 CVEs after EPSS filtering.

## Root Causes Identified

1. **Eleventy's Incremental Builds**: The `--incremental` flag does NOT delete old output files from previous builds. When the filtering criteria changed (e.g., EPSS threshold increased), old CVE pages remained in the output directory.

2. **GitHub Pages CDN Caching**: Even after deployment, GitHub Pages CDN serves cached/stale files for extended periods (up to 10-15 minutes).

3. **Accumulation Over Time**: Each incremental build added new files without removing old ones, causing thousands of unfiltered CVEs to accumulate.

## Solution Implemented

### 1. Build Process Fixes

**Before (Problematic)**:
```bash
npx @11ty/eleventy --incremental --output=public
```

**After (Fixed)**:
```bash
# Always clean before building
rm -rf _site public && npx @11ty/eleventy --output=public
```

**Key Changes**:
- Removed all usage of `--incremental` flag
- Added mandatory clean step before every build
- Created `build:force` npm script for guaranteed clean builds

### 2. Deployment Process Fixes

**Before (Problematic)**:
```bash
# Simple copy to gh-pages
cp -r public/* .
git add .
git commit -m "Deploy"
git push origin gh-pages
```

**After (Fixed)**:
```bash
# Complete directory purge before copying
find . -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
cp -r public/* .
git add -A  # Include deletions
git commit -m "Force clean deployment"
git push origin gh-pages --force-with-lease
```

**Key Changes**:
- Complete removal of all existing files before copying new ones
- Use of `git add -A` to track deletions
- Force push with `--force-with-lease` for safety

### 3. Validation Enhancements

#### CI/CD Gatecheck
```yaml
# Added strict file count validation
CVE_FILE_COUNT=$(find public/cves -name "CVE-*" -type d | wc -l)
if [ "$CVE_FILE_COUNT" -gt 100 ]; then
  echo "❌ CRITICAL: Found $CVE_FILE_COUNT CVE files"
  exit 1
fi
```

#### Post-Deployment Validation
- Created Playwright tests that poll the live site
- Implements retry logic to handle CDN propagation delays
- Validates CVE count, EPSS thresholds, and absence of known stale CVEs

### 4. Monitoring & Prevention

#### Automated Monitoring
- Post-deployment QA workflow triggered after GitHub Pages deployment
- Continuous validation of live site data
- Alerts on excessive CVE counts

#### Build Scripts Updated
```json
{
  "scripts": {
    "clean": "rimraf _site public dist",
    "build": "npm run clean && python -m scripts.generate_alpine_dashboard",
    "build:force": "npm run clean && python -m scripts.force_rebuild --expected-count 60",
    "validate": "python -m scripts.ci_gatecheck --max-cve-count 100"
  }
}
```

## Results

- ✅ Live site now shows correct ~60 CVEs
- ✅ All CVEs have EPSS ≥ 60% as expected
- ✅ No stale data persists across deployments
- ✅ Automated validation prevents regression

## Key Learnings

1. **Never trust incremental builds** for production deployments
2. **Always clean output directories** before building
3. **Force overwrite deployments** to ensure no stale files remain
4. **Implement polling-based validation** for CDN-backed deployments
5. **Multiple validation layers** prevent bad deployments

## Emergency Response Procedure

If the issue recurs:

```bash
# 1. Force clean local build
npm run build:force

# 2. Validate locally
npm run validate

# 3. Emergency deploy
./emergency_deploy.sh

# 4. Wait and verify
sleep 600 && npm run test:e2e
```

## Prevention Checklist

- [ ] Never use `--incremental` in production
- [ ] Always run `npm run clean` before builds
- [ ] Use force deployment scripts
- [ ] Run post-deployment validation
- [ ] Monitor CVE counts on live site

---

**Status**: ✅ RESOLVED  
**Date**: 2025-08-02  
**Impact**: Critical - affected live site data integrity  
**Resolution Time**: Immediate fix with long-term prevention measures