# Troubleshooting Guide

## 🚨 Critical Issue: Live Site Shows 15,000+ CVEs Instead of ~30

### Problem Description
The live GitHub Pages site displays over 15,000 CVEs even though:
- Local development shows only ~30 CVEs (EPSS ≥60%)
- CI/CD validations pass showing correct filtering
- API data confirms only ~30 CVEs meet criteria

### Root Cause
GitHub Pages deployment may retain stale files from previous builds when:
1. Incremental builds don't remove old CVE pages
2. The `gh-pages` branch accumulates files over time
3. Build directory isn't completely purged before regeneration

### Solution

#### Immediate Fix: Force Clean Deployment

1. **Run Force Rebuild Locally**:
```bash
# Audit current state
python -m scripts.repo_audit --build-dir public --expected-count 30

# Force clean all directories
python -m scripts.cleanup_stale_files \
  --build-dir _site \
  --api-dir api \
  --posts-dir src/_posts \
  --min-epss 0.6

# Force rebuild
rm -rf _site public
npm run build  # or npx eleventy

# Verify clean build
python -m scripts.cleanup_stale_files \
  --build-dir public \
  --min-epss 0.6 \
  --verify-only
```

2. **Deploy with Force Push**:
```bash
# Switch to gh-pages branch
git checkout gh-pages

# Remove ALL files except .git
find . -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +

# Copy fresh build
cp -r ../path-to-fresh-build/* .

# Commit everything
git add -A .
git commit -m "chore: force clean rebuild - remove all stale files"

# Force push
git push origin gh-pages --force-with-lease
```

3. **Clear GitHub Pages Cache**:
- Go to Settings → Pages
- Change source to "None" and save
- Wait 1 minute
- Change back to "gh-pages" branch and save

#### Permanent Fix: Updated CI/CD Pipeline

The updated `scheduled-harvest.yml` now includes:

1. **Pre-Build Force Clean**:
```yaml
- name: Clean build directories
  run: |
    rm -rf public/*
    python -m scripts.cleanup_stale_files --force-purge
```

2. **Force Clean Build**:
```yaml
- name: Force clean build with 11ty
  run: |
    rm -rf _site public
    npx eleventy --quiet
```

3. **File Count Quality Gate**:
```yaml
- name: Verify no stale files
  run: |
    CVE_COUNT=$(find public/cves -name "CVE-*" | wc -l)
    if [ "$CVE_COUNT" -gt 100 ]; then
      echo "::error::Found $CVE_COUNT CVE pages - expected <= 100"
      exit 1
    fi
```

### Prevention

#### Build Configuration

1. **Disable Incremental Builds**: When EPSS threshold changes, always do full rebuild
2. **Use Force Purge**: The CleanupAgent now supports `force_purge=True`
3. **Verify Post-Build**: Always run verification after build completes

#### Monitoring

Run these checks after each deployment:

1. **Live Site Sanity Test**:
```bash
pytest tests/e2e/test_live_site_sanity.py \
  --live-url https://williamzujkowski.github.io/vuln-bot/
```

2. **API Validation**:
```bash
curl -s https://williamzujkowski.github.io/vuln-bot/api/vulns/index.json | \
  jq '.vulnerabilities | length'
# Should return ~30, not 15,000
```

3. **Manual Spot Check**:
- Visit the live site
- Check "Showing X of Y results" - Y should be ~30
- Open developer console and check: `Alpine.store('dashboard').stats.total`

### Common Pitfalls

1. **Partial Cleanup**: Only cleaning API files but not HTML pages
2. **Cache Issues**: Browser or CDN caching old data
3. **Wrong Branch**: Deploying to wrong branch or directory
4. **Timing**: GitHub Pages can take 10+ minutes to fully update

### Diagnostic Commands

```bash
# Check what's in gh-pages branch
git checkout gh-pages
find . -name "CVE-*" | wc -l

# Check API data
cat api/vulns/index.json | jq '.vulnerabilities | length'

# Find old files
find . -name "*.html" -mtime +1 | head -20

# Check for files that shouldn't exist
find . -name "CVE-2024-*" | grep -v "CVE-2024-12345"  # Replace with valid CVE
```

### Emergency Rollback

If the site is critically broken:

1. **Revert to Last Known Good**:
```bash
git checkout gh-pages
git revert HEAD
git push origin gh-pages
```

2. **Disable Scheduled Builds**:
- Comment out the cron schedule in `.github/workflows/scheduled-harvest.yml`
- Push to main branch

3. **Manual Recovery**:
- Clone the repo fresh
- Run harvest with correct threshold
- Manually verify output
- Deploy carefully

### Long-Term Solutions

1. **Separate Build Repo**: Use a separate repository for gh-pages to ensure clean deploys
2. **Versioned Deploys**: Tag each deployment with timestamp/version
3. **Blue-Green Deployment**: Deploy to alternate URL first, verify, then switch
4. **Automated Rollback**: Add automatic rollback if post-deploy tests fail

## Other Common Issues

### EPSS API Timeouts
- **Solution**: Increase timeout in harvest scripts, use caching

### Memory Issues During Build
- **Solution**: Process CVEs in smaller batches, increase runner memory

### SSL Certificate Errors
- **Solution**: Update certificates, use `--no-verify-ssl` temporarily

### Rate Limiting
- **Solution**: Add delays between API calls, use authenticated requests