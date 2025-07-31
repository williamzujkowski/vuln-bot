#!/bin/bash
# Deploy Alpine.js dashboard to GitHub Pages manually
# This script generates and deploys the dashboard without waiting for scheduled harvest

set -e

echo "🚀 Manual Alpine.js Dashboard Deployment"
echo "======================================="

# Check if database exists
if [ ! -f ".cache/vulns.db" ]; then
    echo "❌ Database not found at .cache/vulns.db"
    echo "   Run 'python -m scripts.main harvest' first to populate the database"
    exit 1
fi

# Generate Alpine.js dashboard
echo "📦 Generating Alpine.js dashboard..."
python scripts/generate_alpine_dashboard.py

# Copy service worker if needed
if [ ! -f "public/sw.js" ] && [ -f "src/sw.js" ]; then
    echo "📄 Copying service worker..."
    cp src/sw.js public/
fi

# Create a temporary branch for deployment
echo "🌿 Creating temporary deployment branch..."
git checkout -b gh-pages-temp

# Force add public directory (it's gitignored)
echo "📁 Adding public directory..."
git add -f public/

# Commit
echo "💾 Committing dashboard..."
git commit -m "Deploy Alpine.js dashboard" || echo "No changes to commit"

# Push to gh-pages branch
echo "🚀 Pushing to gh-pages branch..."
git push origin gh-pages-temp:gh-pages --force

# Switch back to main
echo "🔄 Switching back to main branch..."
git checkout main
git branch -D gh-pages-temp

echo ""
echo "✅ Dashboard deployed successfully!"
echo "🌐 Visit: https://williamzujkowski.github.io/vuln-bot/"
echo ""
echo "Note: It may take a few minutes for GitHub Pages to update."