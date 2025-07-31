# Migration from 11ty to Alpine.js

## What Changed

### Removed
- 11ty static site generator
- TypeScript compilation
- Webpack bundling
- HTMX progressive enhancement
- Fragment-based rendering
- All build dependencies

### Added
- Alpine.js for reactive client-side functionality
- Python-based single-page dashboard generation
- Embedded JSON data approach
- Enhanced vulnerability analysis features
- Analyst-focused UI improvements

## File Changes

### Deleted/Archived
- `src/assets/ts/` - TypeScript files (archived to src-11ty-backup)
- `.eleventy.js` - 11ty configuration
- `webpack.config.js` - Webpack configuration
- `tsconfig.json` - TypeScript configuration
- All HTMX-related files

### Current Files
- `scripts/generate_alpine_dashboard.py` - Generates complete Alpine.js dashboard
- `public/index.html` - Generated Alpine.js dashboard (single page)
- `scripts/models.py` - Enhanced vulnerability data models
- `deploy-dashboard.sh` - Manual deployment script

## Development Workflow

1. Run harvest: `python -m scripts.main harvest --cache-dir .cache/`
2. Generate dashboard: `python scripts/generate_alpine_dashboard.py`
3. Manual deployment: `./deploy-dashboard.sh`

## Current Architecture

- **Single Page Application**: All data embedded as JSON in one HTML file
- **Client-Side Reactive**: Alpine.js handles all interactivity
- **Enhanced Analytics**: Product-focused columns, enhanced CVE modals
- **Static Hosting**: Perfect for GitHub Pages deployment

## Deployment

GitHub Actions automatically:
1. Harvests vulnerabilities every 4 hours
2. Generates Alpine.js dashboard with enhanced features
3. Deploys to GitHub Pages

No manual build step required!
