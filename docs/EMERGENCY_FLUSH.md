# Emergency Flush Documentation

## 🚨 When to Use Emergency Flush

Use the emergency flush procedures when:

1. **Live site shows 15,000+ CVEs** instead of expected ~30-60
2. **Stale CVE pages persist** after regular cleanup
3. **GitHub Pages deployment is serving old data**
4. **Quality gates are failing** in CI/CD pipeline
5. **EPSS threshold changes** need immediate cleanup

## 🛠️ Emergency Flush Procedures

### 1. Local Emergency Flush

```bash
# Step 1: Audit current state
python -m scripts.force_rebuild --audit-only

# Step 2: Force complete rebuild
python -m scripts.force_rebuild --expected-count 30

# Step 3: Deploy with force overwrite
./deploy_gh_pages.sh

# Step 4: Push to GitHub with force
git push origin gh-pages --force-with-lease
```

### 2. Manual GitHub Pages Reset

```bash
# Navigate to repository settings
# Settings → Pages → Source → "None" → Save
# Wait 2 minutes
# Settings → Pages → Source → "Deploy from branch" → "gh-pages" → Save
```

### 3. CI/CD Emergency Trigger

```bash
# Trigger manual workflow with force cleanup
gh workflow run scheduled-harvest.yml
```

## 🔧 Available Emergency Tools

### Force Rebuild Script
```bash
# Full audit and rebuild
python -m scripts.force_rebuild [options]

Options:
  --audit-only          Run audit without making changes
  --expected-count INT  Expected number of CVEs (default: 60)
  --force-deploy        Also create deployment script
```

### Cleanup Agent with Force Purge
```bash
# Safe mode (audit only)
python -m scripts.cleanup_stale_files --safe-mode

# Force purge mode
python -m scripts.cleanup_stale_files --force-purge
```

### Build Deploy Agent
```bash
# Force complete rebuild
python -c "
from scripts.agents.build_deploy_agent import BuildDeployAgent
agent = BuildDeployAgent()
results = agent.force_full_rebuild()
print(agent.generate_build_report(results))
"
```

### Repository Audit Agent
```bash
# Generate detailed stale files report
python -c "
from scripts.agents.repo_audit_agent import RepoAuditAgent
from pathlib import Path
agent = RepoAuditAgent()
valid_ids = agent._get_valid_cve_ids(Path('api'), 0.6)
results = agent.audit_build_directory(Path('public'), valid_ids)
report = agent.generate_stale_files_report(Path('audit_report'))
print('Generated:', report)
"
```

## 🎯 Post-Flush Validation

### 1. Live Site Validation
```bash
# Install dependencies
pip install playwright
playwright install chromium

# Run live site validation
python -c "
from scripts.agents.post_deploy_validation_agent import PostDeployValidationAgent
agent = PostDeployValidationAgent()
results = agent.validate_live_site(
    'https://williamzujkowski.github.io/vuln-bot/',
    expected_cve_count=60,
    tolerance_percent=30
)
print(agent.generate_validation_report())
"
```

### 2. E2E Tests
```bash
# Run critical live site tests
pytest tests/e2e/test_live_site_sanity.py -v

# Specific test for CVE count
pytest tests/e2e/test_live_site_sanity.py::test_cve_count_is_reasonable -v
```

### 3. Manual Verification
```bash
# Check live site CVE count
curl -s https://williamzujkowski.github.io/vuln-bot/api/vulns/index.json | jq '.vulnerabilities | length'

# Verify EPSS threshold compliance
curl -s https://williamzujkowski.github.io/vuln-bot/api/vulns/index.json | jq '.vulnerabilities[] | select(.epss.score < 0.6) | .cveId' | wc -l
```

## 🆘 Troubleshooting Emergency Flush

### Issue: Force Flush Doesn't Remove All Files

**Solution 1: Manual gh-pages cleanup**
```bash
git checkout gh-pages
find . -name "CVE-*" -type d -mtime +1 -exec rm -rf {} +
git add -A
git commit -m "Manual emergency cleanup"
git push --force-with-lease
```

**Solution 2: Nuclear option - recreate gh-pages**
```bash
git branch -D gh-pages
git checkout --orphan gh-pages
git rm -rf .
# Copy fresh build files
cp -r public/* .
git add .
git commit -m "Emergency: complete gh-pages recreation"
git push origin gh-pages --force
```

### Issue: CI/CD Still Builds Too Many Files

**Check build process:**
```bash
# Verify cleanup agent is working
python -m scripts.cleanup_stale_files --safe-mode --build-dir public

# Check for incremental build issues
grep -r "incremental" .eleventy.js package.json || echo "No incremental flags found"
```

**Fix incremental builds:**
```bash
# Force non-incremental 11ty build
rm -rf _site public
npx eleventy --output=public
```

### Issue: GitHub Pages Cache Persists

**Clear GitHub Pages cache:**
1. Repository Settings → Pages
2. Change source to "None", save
3. Wait 2-3 minutes
4. Change back to "Deploy from branch" → "gh-pages"
5. Wait 10-15 minutes for propagation

**Alternative: Use different deployment method**
```bash
# Deploy to different branch temporarily
git checkout -b gh-pages-emergency
# Copy files and push
git push origin gh-pages-emergency
# Update Pages settings to use new branch
```

## 📋 Emergency Flush Checklist

### Pre-Flush
- [ ] Identify scope of stale data issue
- [ ] Run audit to confirm file counts
- [ ] Backup current state if needed
- [ ] Notify users of potential downtime

### During Flush
- [ ] Execute force purge cleanup
- [ ] Verify directories are actually empty
- [ ] Run complete rebuild (non-incremental)
- [ ] Check file counts meet expectations
- [ ] Deploy with force overwrite

### Post-Flush
- [ ] Wait for GitHub Pages propagation (10-15 min)
- [ ] Run live site validation tests
- [ ] Verify CVE count is reasonable (~30-60)
- [ ] Check EPSS threshold compliance
- [ ] Monitor next scheduled build

### If Issues Persist
- [ ] Check TROUBLESHOOTING.md for detailed steps
- [ ] Consider manual gh-pages branch cleanup
- [ ] Review build process for incremental issues
- [ ] Escalate to repository maintainers

## 🔍 Monitoring and Prevention

### Regular Monitoring
```bash
# Weekly audit (add to cron)
python -m scripts.cleanup_stale_files --verify-only

# Monthly deep audit
python -m scripts.force_rebuild --audit-only
```

### Prevention Measures
1. **CI/CD Quality Gates**: Fail builds if >100 CVE files
2. **Post-Deploy Validation**: Automated live site checks
3. **Non-Incremental Builds**: Always force full rebuilds
4. **Stale File Detection**: Regular cleanup agent runs

### Alerts and Notifications
```bash
# Set up webhook alerts for quality gate failures
python -m scripts.main send-alerts --risk-threshold 80
```

## 📞 Emergency Contacts

- **Repository Owner**: Check GitHub repository settings
- **CI/CD Issues**: Review GitHub Actions logs
- **Live Site Problems**: Check GitHub Pages deployment status
- **Data Issues**: Review harvest logs and compliance reports

## 📚 Related Documentation

- [`docs/stale-data-fix-summary.md`](./stale-data-fix-summary.md) - Comprehensive fix overview
- [`docs/TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) - Detailed troubleshooting guide
- [`scripts/force_rebuild.py`](../scripts/force_rebuild.py) - Force rebuild implementation
- [`tests/e2e/test_live_site_sanity.py`](../tests/e2e/test_live_site_sanity.py) - Live site validation tests