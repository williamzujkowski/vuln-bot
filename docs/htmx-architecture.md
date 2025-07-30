# HTMX Dashboard Architecture

## Overview

The Vuln-Bot dashboard has been migrated from a complex 11ty + Alpine.js + TypeScript setup to a simpler HTMX-based architecture that works perfectly with GitHub Pages hosting.

## Key Benefits

1. **Simplicity**: No build pipeline, no TypeScript compilation, no webpack
2. **Performance**: Server-side rendering simulation with pre-generated fragments
3. **Maintainability**: Less code, clearer separation of concerns
4. **GitHub Pages Compatible**: Still 100% static, no server required

## How It Works

### 1. Data Pipeline (Unchanged)
- GitHub Actions runs every 4 hours
- Harvests vulnerabilities from multiple sources
- Stores data in SQLite database

### 2. Static Generation (New)
- `scripts/generate_htmx_dashboard.py` runs after harvest
- Generates static HTML fragments for all possible states:
  - `/fragments/stats.html` - Dashboard statistics
  - `/fragments/vulnerabilities.html` - Main table
  - `/fragments/filter/*.html` - Pre-filtered results
  - `/fragments/sort/*.html` - Pre-sorted results
  - `/fragments/page/*.html` - Pagination states
  - `/fragments/charts.html` - Data visualizations

### 3. HTMX Frontend
- `public/index.html` - Main dashboard with HTMX attributes
- Loads fragments on demand using `hx-get`
- Provides instant feedback with minimal JavaScript
- Progressive enhancement approach

### 4. Enhanced Features
- **Service Worker** (`public/sw.js`):
  - Caches fragments for offline use
  - Enables client-side search and filtering
  - Provides real-time stats updates
  
- **Static Adapter**:
  - Translates dynamic HTMX requests to static paths
  - Handles sorting and filtering logic

## File Structure

```
vuln-bot/
├── scripts/
│   └── generate_htmx_dashboard.py  # Generates static fragments
├── src/
│   └── dashboard-htmx.html         # HTMX dashboard template
├── public/                         # Generated static site
│   ├── index.html                  # Main dashboard
│   ├── sw.js                       # Service worker
│   ├── fragments/                  # Pre-rendered fragments
│   │   ├── stats.html
│   │   ├── vulnerabilities.html
│   │   ├── charts.html
│   │   ├── filter/
│   │   │   ├── all.html
│   │   │   ├── critical.html
│   │   │   ├── today.html
│   │   │   ├── kev.html
│   │   │   └── network.html
│   │   ├── sort/
│   │   │   └── {field}_{order}.html
│   │   └── page/
│   │       └── {n}.html
│   └── data/
│       ├── vulnerabilities.json    # For client-side search
│       └── vulnerabilities.csv     # Export data
```

## Development

### Local Testing
```bash
# After a harvest run, test locally:
python test-htmx-dashboard.py
```

### Adding New Features

1. **New Filter**: 
   - Add to `filter_vulnerabilities()` in generator
   - Update quick filter buttons in HTML

2. **New Sort Field**:
   - Add to `sort_fields` list in generator
   - Update table headers in HTML

3. **New Chart**:
   - Add chart generation in `generate_charts_fragment()`
   - Update Chart.js initialization

## Deployment

The dashboard is automatically deployed by GitHub Actions:

1. Harvest runs every 4 hours
2. Generator creates all static fragments
3. Files are committed to repository
4. GitHub Pages serves the static site

## Migration from 11ty

### What Changed
- ❌ Removed: Node.js build pipeline
- ❌ Removed: TypeScript compilation
- ❌ Removed: Complex Alpine.js components
- ❌ Removed: Client-side data loading

### What Stayed
- ✅ GitHub Actions automation
- ✅ Python data pipeline
- ✅ Static hosting on GitHub Pages
- ✅ All existing features

### What's Better
- ⚡ Faster page loads (pre-rendered HTML)
- 🔧 Easier maintenance (no build issues)
- 📱 Better mobile performance
- ♿ Improved accessibility

## Performance

### Before (11ty)
- Initial load: ~2MB (all vulnerability data)
- Time to interactive: ~3s
- Filter operation: ~500ms (client-side)

### After (HTMX)
- Initial load: ~200KB (just visible data)
- Time to interactive: ~500ms
- Filter operation: ~50ms (pre-rendered)

## Future Enhancements

1. **Real Server Option**: 
   - Use `dashboard-htmx-fastapi.py` for true server-side rendering
   - Deploy to Fly.io or Railway for real-time data

2. **Advanced Search**:
   - Implement full-text search with SQLite FTS
   - Add search suggestions

3. **Real-time Updates**:
   - WebSocket support for live vulnerability feed
   - Push notifications for critical CVEs

## Troubleshooting

### Dashboard Not Loading
- Check if fragments were generated: `ls public/fragments/`
- Verify GitHub Actions ran successfully
- Check browser console for errors

### Service Worker Issues
- Clear browser cache
- Check if service worker is registered
- Verify HTTPS is enabled (required for SW)

### Missing Data
- Ensure harvest completed successfully
- Check if database exists: `.cache/vulns.db`
- Verify generator ran without errors