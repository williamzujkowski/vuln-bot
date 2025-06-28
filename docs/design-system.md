# Design System Documentation

## Overview

The Morning Vuln Briefing design system provides a consistent, accessible, and maintainable approach to styling. It's built on design tokens and reusable components.

## Design Tokens

Design tokens are stored in `src/assets/css/tokens.css` and provide the foundation for all styling decisions.

### Color Tokens

#### Brand Colors
- `--color-brand-primary`: Primary brand color (blue)
- `--color-brand-secondary`: Secondary brand color (violet)
- `--color-brand-accent`: Accent color (cyan)

#### Severity Colors
Based on CVSS scoring standards:
- `--color-severity-critical`: Critical vulnerabilities (dark red)
- `--color-severity-high`: High severity (red)
- `--color-severity-medium`: Medium severity (amber)
- `--color-severity-low`: Low severity (emerald)
- `--color-severity-none`: No severity (gray)

#### Semantic Colors
- `--color-text-primary`: Primary text color
- `--color-text-secondary`: Secondary text color
- `--color-text-muted`: Muted text color
- `--color-bg-primary`: Primary background
- `--color-bg-secondary`: Secondary background
- `--color-border-primary`: Primary border color

### Typography Tokens

#### Font Families
- `--font-family-sans`: System sans-serif stack
- `--font-family-mono`: System monospace stack

#### Font Sizes
- `--font-size-xs`: 0.75rem (12px)
- `--font-size-sm`: 0.875rem (14px)
- `--font-size-base`: 1rem (16px)
- `--font-size-lg`: 1.125rem (18px)
- `--font-size-xl`: 1.25rem (20px)
- `--font-size-2xl`: 1.5rem (24px)
- `--font-size-3xl`: 1.875rem (30px)
- `--font-size-4xl`: 2.25rem (36px)

#### Font Weights
- `--font-weight-normal`: 400
- `--font-weight-medium`: 500
- `--font-weight-semibold`: 600
- `--font-weight-bold`: 700

### Spacing Tokens

Consistent spacing scale from 0 to 24:
- `--space-0`: 0
- `--space-1`: 0.25rem (4px)
- `--space-2`: 0.5rem (8px)
- `--space-3`: 0.75rem (12px)
- `--space-4`: 1rem (16px)
- `--space-6`: 1.5rem (24px)
- `--space-8`: 2rem (32px)
- And more...

### Other Tokens

- **Border Radius**: From `--radius-sm` to `--radius-full`
- **Shadows**: From `--shadow-xs` to `--shadow-xl`
- **Transitions**: Pre-defined transitions for common properties
- **Z-Index**: Layering system for modals, tooltips, etc.

## Component Classes

Components are defined in `src/assets/css/components.css`.

### Buttons

```html
<!-- Primary button -->
<button class="btn btn-primary">Save Changes</button>

<!-- Secondary button -->
<button class="btn btn-secondary">Cancel</button>

<!-- Danger button -->
<button class="btn btn-danger">Delete</button>

<!-- Button sizes -->
<button class="btn btn-sm">Small</button>
<button class="btn btn-lg">Large</button>
```

### Badges

```html
<!-- Severity badges -->
<span class="badge badge-severity-critical">Critical</span>
<span class="badge badge-severity-high">High</span>
<span class="badge badge-severity-medium">Medium</span>
<span class="badge badge-severity-low">Low</span>

<!-- Status badges -->
<span class="badge badge-success">Active</span>
<span class="badge badge-warning">Pending</span>
<span class="badge badge-danger">Failed</span>
```

### Cards

```html
<div class="card">
  <div class="card-header">
    <h3>Card Title</h3>
  </div>
  <div class="card-body">
    <p>Card content goes here.</p>
  </div>
  <div class="card-footer">
    <button class="btn btn-primary">Action</button>
  </div>
</div>
```

### Alerts

```html
<!-- Info alert -->
<div class="alert alert-info">
  <div class="alert-icon">ℹ️</div>
  <div class="alert-content">
    <div class="alert-title">Information</div>
    <p>This is an informational message.</p>
  </div>
</div>

<!-- Error alert -->
<div class="alert alert-error">
  <div class="alert-icon">❌</div>
  <div class="alert-content">
    <div class="alert-title">Error</div>
    <p>An error occurred.</p>
  </div>
</div>
```

### Forms

```html
<div class="form-group">
  <label class="form-label" for="email">Email</label>
  <input type="email" id="email" class="form-input" placeholder="you@example.com">
</div>

<div class="form-group">
  <label class="form-label" for="severity">Severity</label>
  <select id="severity" class="form-select">
    <option>Critical</option>
    <option>High</option>
    <option>Medium</option>
    <option>Low</option>
  </select>
</div>

<div class="form-group">
  <label class="form-label" for="description">Description</label>
  <textarea id="description" class="form-textarea" rows="4"></textarea>
</div>
```

### Tables

```html
<div class="table-container">
  <table class="table">
    <thead>
      <tr>
        <th class="table-sortable">CVE ID</th>
        <th class="table-sortable sort-desc">Risk Score</th>
        <th>Severity</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>CVE-2025-1234</td>
        <td>95</td>
        <td><span class="badge badge-severity-critical">Critical</span></td>
      </tr>
    </tbody>
  </table>
</div>
```

### Pagination

```html
<div class="pagination">
  <button class="pagination-item pagination-item-disabled">Previous</button>
  <span class="pagination-item pagination-item-active">1</span>
  <a href="#" class="pagination-item">2</a>
  <a href="#" class="pagination-item">3</a>
  <button class="pagination-item">Next</button>
</div>
```

## Utility Classes

### Text Utilities
- `.text-center`, `.text-right`, `.text-left`
- `.text-xs`, `.text-sm`, `.text-base`, `.text-lg`, `.text-xl`
- `.font-normal`, `.font-medium`, `.font-semibold`, `.font-bold`
- `.text-primary`, `.text-secondary`, `.text-muted`
- `.text-error`, `.text-success`, `.text-warning`

### Spacing Utilities
- `.mt-{0-8}`: Margin top
- `.mb-{0-8}`: Margin bottom
- `.gap-{1-6}`: Gap for flexbox/grid

### Display Utilities
- `.hidden`, `.block`, `.inline-block`, `.flex`, `.inline-flex`
- `.flex-col`, `.flex-wrap`
- `.items-center`, `.items-start`, `.items-end`
- `.justify-center`, `.justify-between`, `.justify-end`

### Responsive Utilities
- `.sm:block`, `.sm:hidden`, `.sm:flex` (640px+)
- `.md:block`, `.md:hidden`, `.md:flex` (768px+)
- `.lg:block`, `.lg:hidden`, `.lg:flex` (1024px+)

## Migration Guide

To migrate existing code to use the design system:

1. Replace hardcoded colors with token variables
2. Use component classes instead of custom styles
3. Apply utility classes for common patterns
4. Ensure all interactive elements meet WCAG touch target size (44px)

### Example Migration

Before:
```html
<button style="background: #2563eb; color: white; padding: 8px 16px;">
  Save
</button>
```

After:
```html
<button class="btn btn-primary">
  Save
</button>
```

## Accessibility

The design system is built with accessibility in mind:

- All interactive elements have a minimum touch target size of 44px
- Focus states are clearly visible with outline styles
- Color contrast ratios meet WCAG AA standards
- Semantic HTML is used throughout
- Screen reader friendly classes like `.sr-only` are provided

## Dark Mode Support

The design system automatically adapts to user's color scheme preference using CSS media queries. Colors are adjusted to maintain proper contrast in dark mode.

## Performance

- CSS is modular and can be tree-shaken
- Design tokens reduce repetition
- Component classes minimize custom CSS
- Utility classes enable rapid prototyping without new CSS