#!/bin/bash
# Migration script from 11ty to HTMX

echo "🚀 Migrating Vuln-Bot from 11ty to HTMX architecture"
echo "=================================================="

# Backup current state
echo "📦 Creating backup..."
cp package.json package.json.11ty-backup
cp -r src src-11ty-backup 2>/dev/null || true

# Clean up old build artifacts
echo "🧹 Cleaning up old build artifacts..."
rm -rf node_modules
rm -rf public dist
rm -f package-lock.json

# Update package.json for HTMX
echo "📝 Creating new package.json for HTMX..."
cat > package.json << 'EOF'
{
  "name": "vuln-bot",
  "version": "2.0.0",
  "description": "High-risk CVE intelligence platform with HTMX dashboard",
  "private": true,
  "scripts": {
    "test": "echo 'No tests for static site'",
    "serve": "python test-htmx-dashboard.py",
    "lint": "eslint public/sw.js",
    "format": "prettier --write 'public/**/*.{html,js,css}'",
    "precommit": "npm run lint && npm run format"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/williamzujkowski/vuln-bot.git"
  },
  "keywords": [
    "vulnerability",
    "cve",
    "security",
    "intelligence",
    "htmx"
  ],
  "author": "",
  "license": "MIT",
  "devDependencies": {
    "eslint": "^8.57.0",
    "eslint-config-google": "^0.14.0",
    "prettier": "^3.0.0",
    "husky": "^9.0.0"
  },
  "eslintConfig": {
    "extends": "google",
    "env": {
      "browser": true,
      "es2020": true,
      "serviceworker": true
    },
    "rules": {
      "max-len": ["error", { "code": 120 }],
      "require-jsdoc": "off"
    }
  },
  "prettier": {
    "semi": true,
    "singleQuote": false,
    "tabWidth": 2,
    "printWidth": 100
  }
}
EOF

# Install minimal dependencies
echo "📦 Installing minimal dependencies..."
npm install

# Update .gitignore
echo "📝 Updating .gitignore..."
cat >> .gitignore << 'EOF'

# HTMX specific
public/fragments/
public/data/
src-11ty-backup/
package.json.11ty-backup
EOF

# Create migration notes
echo "📄 Creating migration notes..."
cat > MIGRATION.md << 'EOF'
# Migration from 11ty to HTMX

## What Changed

### Removed
- 11ty static site generator
- TypeScript compilation
- Webpack bundling
- Complex Alpine.js components
- All build dependencies

### Added
- HTMX for progressive enhancement
- Python-based static fragment generation
- Service worker for offline support
- Simplified dashboard with pre-rendered states

## File Changes

### Deleted/Archived
- `src/assets/ts/` - TypeScript files (archived to src-11ty-backup)
- `.eleventy.js` - 11ty configuration
- `webpack.config.js` - Webpack configuration
- `tsconfig.json` - TypeScript configuration

### New Files
- `scripts/generate_htmx_dashboard.py` - Generates static HTMX fragments
- `src/dashboard-htmx.html` - HTMX dashboard template
- `public/sw.js` - Service worker for enhanced functionality
- `test-htmx-dashboard.py` - Local testing script

## Development Workflow

1. Run harvest: `python -m scripts.main harvest`
2. Generate dashboard: `python scripts/generate_htmx_dashboard.py`
3. Test locally: `python test-htmx-dashboard.py`

## Deployment

GitHub Actions automatically:
1. Harvests vulnerabilities every 4 hours
2. Generates HTMX dashboard
3. Deploys to GitHub Pages

No manual build step required!
EOF

echo "✅ Migration preparation complete!"
echo ""
echo "Next steps:"
echo "1. Review MIGRATION.md for details"
echo "2. Test locally with: python test-htmx-dashboard.py"
echo "3. Commit changes and push"
echo "4. GitHub Actions will handle the rest"
echo ""
echo "Old files backed up to:"
echo "- package.json.11ty-backup"
echo "- src-11ty-backup/"