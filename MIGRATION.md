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
