# Stale Data Fix Summary

## 🚨 Issue Identified
The live site at https://williamzujkowski.github.io/vuln-bot/ shows 15,000+ CVEs instead of the expected ~30 that meet the EPSS ≥60% threshold.

## 🔍 Root Cause Analysis

1. **Incremental Builds**: The site uses incremental builds that don't remove old CVE pages
2. **GitHub Pages Caching**: Stale files persist in the `gh-pages` branch
3. **Incomplete Cleanup**: Previous cleanup processes only removed some files, not all

## ✅ Implemented Solutions

### 1. Enhanced Cleanup Agent (`scripts/agents/cleanup_agent.py`)
- Added `force_purge=True` option for complete directory removal
- New method `force_purge_and_verify()` for thorough cleanup
- Selective cleanup patterns for CVE-related files

### 2. Repository Audit Agent (`scripts/agents/repo_audit_agent.py`)
- Scans for stale files and unexpected CVEs
- Compares actual vs expected file counts
- Generates detailed audit reports with recommendations
- Identifies files by age and validates against EPSS threshold

### 3. Build & Deploy Agent (`scripts/agents/build_deploy_agent.py`)
- Forces complete rebuild with full cleanup
- Manages proper git deployment to gh-pages
- Creates deployment scripts for clean pushes
- Validates pre and post-build states

### 4. Enhanced Live Site Validation (`tests/e2e/test_live_site_sanity.py`)
- **Critical Test**: `test_cve_count_is_reasonable()` - Fails if >72 CVEs found
- Validates API data matches UI display
- Checks for stale CVE pages
- Verifies EPSS threshold compliance
- Tests chunk file integrity

### 5. CI/CD Pipeline Updates (`scheduled-harvest.yml`)
- Force cleans `public/` directory before build
- Attempts 11ty build with fallback to Python
- Quality gate: Fails if >100 CVE pages found
- Reduced artifact retention to ensure fresh deploys
- Added file count metrics to build summary

### 6. Force Rebuild Script (`scripts/force_rebuild.py`)
```bash
# Audit current state
python -m scripts.force_rebuild --audit-only

# Force complete rebuild
python -m scripts.force_rebuild --expected-count 30
```

## 🚀 Immediate Actions Required

### Step 1: Run Force Rebuild Locally
```bash
# 1. Audit current state
python -m scripts.force_rebuild --audit-only

# 2. If audit shows issues, force rebuild
python -m scripts.force_rebuild

# 3. This creates deploy_gh_pages.sh - run it
./deploy_gh_pages.sh

# 4. Push to GitHub
git push origin gh-pages --force-with-lease
```

### Step 2: Clear GitHub Pages Cache
1. Go to Settings → Pages
2. Change source to "None" and save
3. Wait 1 minute
4. Change back to "Deploy from branch" → "gh-pages" → Save

### Step 3: Validate Fix
```bash
# Wait 10 minutes for deployment
sleep 600

# Run validation tests
pytest tests/e2e/test_live_site_sanity.py -v
```

## 📋 Checklist for Production Fix

- [ ] Run audit to confirm issue scope
- [ ] Execute force rebuild locally
- [ ] Deploy with force push to gh-pages
- [ ] Clear GitHub Pages cache in settings
- [ ] Wait for deployment (10-15 minutes)
- [ ] Run live site validation tests
- [ ] Verify count shows ~30 CVEs, not 15,000
- [ ] Monitor next scheduled build

## 🔮 Long-Term Prevention

1. **Every Build**: Force clean directories before building
2. **Quality Gates**: Fail CI if file count exceeds threshold
3. **Post-Deploy Tests**: Automated validation after each deployment
4. **Monthly**: Manual audit of gh-pages branch for cruft

## 📊 Expected Results

After implementing these fixes:
- Live site should show ~30 CVEs (EPSS ≥60%)
- No stale CVE pages from previous thresholds
- CI/CD pipeline prevents future accumulation
- Automated tests catch any regression

## 🆘 If Issues Persist

1. Check `docs/TROUBLESHOOTING.md` for detailed diagnostics
2. Manually clean gh-pages branch:
   ```bash
   git checkout gh-pages
   find . -name "CVE-*" -mtime +1 -delete
   git add -A && git commit -m "Manual cleanup"
   git push
   ```
3. Consider migrating to a separate deployment repository
4. Implement blue-green deployment strategy