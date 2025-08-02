#!/bin/bash
set -e

echo "Preparing GitHub Pages deployment with FORCE OVERWRITE..."

# Save current branch
CURRENT_BRANCH="main"

# Ensure source directory exists
if [ ! -d "public" ]; then
    echo "Error: Source directory public does not exist"
    exit 1
fi

# Create temporary directory for deployment
TEMP_DIR=$(mktemp -d)
cp -r public/* $TEMP_DIR/

# Fetch latest gh-pages to ensure we're up to date
git fetch origin gh-pages:gh-pages || true

# Switch to gh-pages branch
git checkout gh-pages || git checkout -b gh-pages

# CRITICAL: Remove ALL existing files (except .git)
# This ensures no stale files remain
echo "Removing all existing files from gh-pages branch..."
find . -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +

# Verify directory is clean
FILE_COUNT=$(find . -mindepth 1 ! -path './.git*' | wc -l)
echo "Files remaining after cleanup: $FILE_COUNT (should be 0)"

# Copy new files
echo "Copying fresh build files..."
cp -r $TEMP_DIR/* .

# Touch .nojekyll to ensure GitHub Pages processes correctly
touch .nojekyll

# Add all files (including deletions)
git add -A .

# Show what will be committed
echo "Files to be committed:"
git status --short

# Check if there are changes
if git diff --cached --quiet; then
    echo "No changes to deploy"
else
    # Commit changes with descriptive message
    TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    git commit -m "chore: force full site rebuild - complete overwrite ($TIMESTAMP)

This commit completely replaces all files in gh-pages branch to ensure
no stale CVE pages remain. All files have been regenerated from scratch.

[skip ci]"
fi

# Clean up
rm -rf $TEMP_DIR

# Push to GitHub Pages with force-with-lease for safety
echo "Pushing to GitHub Pages..."
git push origin gh-pages --force-with-lease

# Return to original branch
git checkout $CURRENT_BRANCH

echo "✅ Deployment complete!"
echo "⏱️  Note: GitHub Pages may take 5-10 minutes to update due to CDN caching."
echo "🔍 To check deployment status, visit: https://github.com/williamzujkowski/vuln-bot/actions"
