# Troubleshooting Guide

This guide provides step-by-step solutions for common issues encountered with the Vuln-Bot vulnerability intelligence platform.

## 🚨 Emergency: 15,000+ CVE Issue

**Symptoms**: Live site shows 15,000+ CVEs instead of expected ~30-60 CVEs after EPSS filtering.

**Root Cause**: Incremental builds preserve stale files, causing old CVE data to persist.

### Immediate Response

```bash
# Step 1: Force clean rebuild locally
rm -rf _site public && npm run clean && npm run build

# Step 2: Validate locally before deploy
python -m scripts.ci_gatecheck \
  --max-cve-count 100 \
  --min-epss 0.6 \
  --fail-on-violations

# Step 3: If validation passes, force deploy
./deploy_gh_pages.sh

# Step 4: Monitor deployment (wait 10-15 minutes for CDN)
pytest tests/e2e/test_live_site_sanity.py -v
```

### Detailed Emergency Procedure

1. **Identify the Issue**
   ```bash
   # Check live site CVE count
   curl -s "https://williamzujkowski.github.io/vuln-bot/api/vulns/index.json" | \
     jq '.vulnerabilities | length'
   
   # If result > 100, proceed with emergency response
   ```

2. **Force Local Rebuild**
   ```bash
   # Clean all build artifacts
   npm run clean
   
   # Force rebuild without incremental mode
   npm run build:force
   
   # Verify local data integrity
   npm run validate
   ```

3. **Emergency Deployment**
   ```bash
   # Create emergency deployment script
   cat > emergency_deploy.sh << 'EOF'
   #!/bin/bash
   set -e
   echo "🚨 EMERGENCY DEPLOYMENT: Force overwriting gh-pages"
   
   # Backup current branch
   git branch backup-$(date +%s) 2>/dev/null || true
   
   # Force reset gh-pages branch
   git fetch origin gh-pages:gh-pages || git checkout --orphan gh-pages
   git checkout gh-pages
   
   # Remove ALL existing files (critical!)
   find . -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
   
   # Copy clean build
   git checkout main -- public/
   cp -r public/* . 2>/dev/null || echo "No public directory"
   
   # Force commit and push
   git add -A
   git commit -m "EMERGENCY: Force clean deployment - $(date -u)"
   git push origin gh-pages --force
   
   echo "✅ Emergency deployment complete"
   EOF
   
   chmod +x emergency_deploy.sh
   ./emergency_deploy.sh
   ```

4. **Verification**
   ```bash
   # Wait for GitHub Pages propagation (10-15 minutes)
   echo "Waiting for deployment to propagate..."
   sleep 600  # 10 minutes
   
   # Run live site validation
   pytest tests/e2e/test_live_site_sanity.py::TestLiveSiteSanity::test_cve_count_is_reasonable -v
   ```

## 🔧 Common Issues

### Issue: npm run build fails

**Symptoms**: Build command returns errors or doesn't generate files.

**Solutions**:

1. **Check Node.js version**
   ```bash
   node --version  # Should be 18+ LTS
   npm --version
   ```

2. **Clean install dependencies**
   ```bash
   rm -rf node_modules package-lock.json
   npm install
   ```

3. **Check Python dependencies**
   ```bash
   pip install -r requirements.txt
   python -m scripts.generate_alpine_dashboard --help
   ```

### Issue: Gatecheck validation fails

**Symptoms**: `python -m scripts.ci_gatecheck` reports violations.

**Solutions**:

1. **API directory missing**
   ```bash
   # Solution: Run build first
   npm run build
   ```

2. **EPSS threshold violations**
   ```bash
   # Check violation details
   python -m scripts.ci_gatecheck \
     --api-dir public/api \
     --output-report gatecheck-debug.json
   
   # Review violations
   jq '.errors' gatecheck-debug.json
   ```

3. **Excessive CVE count**
   ```bash
   # Run force purge
   python -m scripts.cleanup_stale_files --force-purge
   npm run build
   ```

### Issue: GitHub Pages deployment fails

**Symptoms**: GitHub Actions deployment fails or pages don't update.

**Solutions**:

1. **Check GitHub Actions logs**
   - Go to Actions tab in GitHub repository
   - Check latest workflow run for errors

2. **Force reset gh-pages branch**
   ```bash
   git checkout gh-pages
   git reset --hard origin/main
   git push origin gh-pages --force
   ```

3. **Manual deployment**
   ```bash
   npm run deploy
   ```

### Issue: Live site shows stale data

**Symptoms**: Site content doesn't match local build.

**Solutions**:

1. **Clear CDN cache** (wait 10-15 minutes)
2. **Force refresh browser** (Ctrl+F5 or Cmd+Shift+R)
3. **Check in incognito/private mode**
4. **Verify deployment timestamp**:
   ```bash
   curl -I "https://williamzujkowski.github.io/vuln-bot/" | grep -i last-modified
   ```

## 🛠️ Maintenance Commands

### Daily Health Check
```bash
# Check live site status
npm run test:e2e

# Validate local data integrity
npm run validate

# Clean build and verify
npm run clean && npm run build && npm run validate
```

### Weekly Maintenance
```bash
# Update dependencies
npm update
pip install -r requirements.txt --upgrade

# Clean old cache
rm -rf .cache/
npm run clean

# Full validation
npm run build
npm run validate
npm run test:e2e
```

### Monthly Audit
```bash
# Run comprehensive audit
python -m scripts.agents.repo_audit_agent \
  --build-dir public \
  --expected-count 60

# Check for security issues
bandit -r scripts/ -ll
npm audit

# Performance check
npm run lighthouse || echo "Lighthouse not configured"
```

## 📊 Monitoring and Alerts

### Key Metrics to Monitor

1. **CVE Count**: Should be ≤100, ideally 30-60
2. **EPSS Compliance**: All CVEs should have EPSS ≥60%
3. **Build Time**: Should complete in <5 minutes
4. **Deployment Time**: Should propagate in <15 minutes

### Automated Monitoring Script

```bash
#!/bin/bash
# monitor_site.sh - Run this via cron every hour

SITE_URL="https://williamzujkowski.github.io/vuln-bot/"
MAX_CVES=100

# Get CVE count
CVE_COUNT=$(curl -s "${SITE_URL}api/vulns/index.json" | jq '.vulnerabilities | length')

if [ "$CVE_COUNT" -gt "$MAX_CVES" ]; then
    echo "🚨 ALERT: Site showing $CVE_COUNT CVEs (max: $MAX_CVES)"
    echo "Triggering emergency rebuild..."
    # Add webhook notification here
else
    echo "✅ Site healthy: $CVE_COUNT CVEs"
fi
```

## 🔍 Debugging Commands

### Get detailed site statistics
```bash
# API data summary
curl -s "https://williamzujkowski.github.io/vuln-bot/api/vulns/index.json" | \
  jq '{total: (.vulnerabilities | length), sample: (.vulnerabilities[0:3] | map(.cveId))}'

# Chunk file analysis
curl -s "https://williamzujkowski.github.io/vuln-bot/api/vulns/chunk-index.json" | \
  jq '.chunks[] | {file: .file, count: .count}'
```

### Local debugging
```bash
# Audit build directory
python -m scripts.cleanup_stale_files --safe-mode

# Check for vestigial files
find _site -name "CVE-*" | head -10

# Validate specific CVE
python -c "
import json
with open('public/api/vulns/index.json') as f:
    data = json.load(f)
    for vuln in data['vulnerabilities'][:3]:
        print(f'{vuln[\"cveId\"]}: EPSS {vuln[\"epss\"][\"score\"]*100:.1f}%')
"
```

## ⚡ Performance Issues

### Slow build times
```bash
# Enable parallel processing
export PYTHONPATH=.
python -m scripts.main harvest --parallel

# Use cache effectively
python -m scripts.main harvest --cache-dir .cache --use-cache
```

### High memory usage
```bash
# Monitor memory during build
top -p $(pgrep -f python)

# Use chunked processing
python -m scripts.main generate-briefing --storage-strategy severity-year
```

## 🚦 Prevention Measures

### Pre-commit checks
```bash
# Add to .git/hooks/pre-commit
#!/bin/bash
npm run precommit
python -m scripts.ci_gatecheck --max-cve-count 100 --fail-on-violations
```

### CI/CD best practices
1. **Always use `npm run clean` before builds**
2. **Never use `--incremental` flag in production**
3. **Run gatecheck validation before deployment**
4. **Monitor live site after each deployment**

## 📞 Emergency Contacts

If automated recovery fails:

1. **Check GitHub Actions logs** for detailed error messages
2. **Review recent commits** for potential breaking changes
3. **Rollback to last known good deployment** if necessary:
   ```bash
   git checkout gh-pages
   git reset --hard <last-good-commit>
   git push origin gh-pages --force
   ```

## 📚 Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitHub Pages Troubleshooting](https://docs.github.com/en/pages/getting-started-with-github-pages/troubleshooting-404-errors-for-github-pages-sites)
- [Eleventy Documentation](https://www.11ty.dev/docs/)
- [EPSS Framework](https://www.first.org/epss/)

---

**Last Updated**: 2025-08-02  
**Version**: 2.1.0

For additional support, check the project's GitHub Issues or create a new issue with the `troubleshooting` label.