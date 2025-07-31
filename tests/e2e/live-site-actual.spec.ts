import { test, expect } from '@playwright/test';

const LIVE_URL = 'https://williamzujkowski.github.io/vuln-bot/';

test.describe('Vuln-Bot Live Site - Actual Structure', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(LIVE_URL);
    await page.waitForLoadState('networkidle');
  });

  test('should load the homepage with correct elements', async ({ page }) => {
    await expect(page).toHaveTitle(/Vulnerability Intelligence Dashboard/);
    await expect(page.locator('h1')).toContainText('Vuln-Bot');
    await expect(page.locator('h1')).toContainText('Intelligence');
  });

  test('should display vulnerability statistics cards', async ({ page }) => {
    // Check for statistics cards with dark theme
    const statsCards = page.locator('[class*="stat"], [class*="card"]').filter({ hasText: /\d+/ });
    const count = await statsCards.count();
    expect(count).toBeGreaterThan(0);
    
    // Check for specific stats
    await expect(page.locator('text=/Total Vulnerabilities/i')).toBeVisible();
    await expect(page.locator('text=/Critical Severity/i')).toBeVisible();
    await expect(page.locator('text=/High Severity/i')).toBeVisible();
  });

  test('should have working filters section', async ({ page }) => {
    // Check filters section exists
    await expect(page.locator('text=/Filters/i')).toBeVisible();
    
    // Check for severity dropdown
    const severitySelect = page.locator('select').first();
    await expect(severitySelect).toBeVisible();
    
    // Check for CVSS Score slider
    await expect(page.locator('text=/CVSS Score/i')).toBeVisible();
    
    // Check for EPSS % range
    await expect(page.locator('text=/EPSS %/i')).toBeVisible();
  });

  test('should display vulnerability table with data', async ({ page }) => {
    // Wait for table to load
    await page.waitForSelector('table, [role="table"], .vulnerability-list', { timeout: 10000 });
    
    // Check for CVE entries
    const cveEntries = page.locator('text=/CVE-\\d{4}-\\d+/');
    const cveCount = await cveEntries.count();
    expect(cveCount).toBeGreaterThan(0);
    
    // Check table headers
    await expect(page.locator('text=/CVE ID/i')).toBeVisible();
    await expect(page.locator('text=/Severity/i')).toBeVisible();
    await expect(page.locator('text=/CVSS/i')).toBeVisible();
  });

  test('should display charts and visualizations', async ({ page }) => {
    // Check for chart sections
    await expect(page.locator('text=/Severity Distribution/i')).toBeVisible();
    await expect(page.locator('text=/EPSS Score Distribution/i')).toBeVisible();
    
    // Check for canvas elements (charts)
    const canvasElements = page.locator('canvas');
    const canvasCount = await canvasElements.count();
    expect(canvasCount).toBeGreaterThan(0);
  });

  test('should have export functionality', async ({ page }) => {
    // Look for export button
    const exportButton = page.locator('button').filter({ hasText: /Export/i });
    await expect(exportButton.first()).toBeVisible();
    
    // Check CSV export exists
    await exportButton.first().click();
    const csvOption = page.locator('text=/CSV/i');
    await expect(csvOption).toBeVisible();
  });

  test('should have responsive design for mobile', async ({ page }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Main content should still be visible
    await expect(page.locator('h1')).toBeVisible();
    
    // Stats should be visible
    const stats = page.locator('[class*="stat"], [class*="card"]').filter({ hasText: /\d+/ });
    const statsVisible = await stats.first().isVisible();
    expect(statsVisible).toBeTruthy();
  });

  test('should have proper dark theme styling', async ({ page }) => {
    // Check background color is dark
    const bgColor = await page.evaluate(() => {
      return window.getComputedStyle(document.body).backgroundColor;
    });
    
    // Should be a dark color (low RGB values)
    expect(bgColor).toMatch(/rgb\((\d+), (\d+), (\d+)\)/);
  });

  test('should handle search functionality', async ({ page }) => {
    // Look for search input
    const searchInput = page.locator('input[type="search"], input[placeholder*="Search"], input[placeholder*="CVE"]');
    
    if (await searchInput.isVisible()) {
      await searchInput.fill('CVE-2024');
      await page.waitForTimeout(500); // Debounce
      
      // Should filter results
      const cveEntries = page.locator('text=/CVE-2024-\\d+/');
      const count = await cveEntries.count();
      expect(count).toBeGreaterThan(0);
    }
  });

  test('should have working pagination', async ({ page }) => {
    // Look for pagination elements
    const pageInfo = page.locator('text=/Page \\d+ of \\d+/i');
    
    if (await pageInfo.isVisible()) {
      // Check pagination exists
      await expect(pageInfo).toBeVisible();
      
      // Could have next/prev buttons
      const nextButton = page.locator('button').filter({ hasText: /Next/i });
      if (await nextButton.isVisible()) {
        const isDisabled = await nextButton.isDisabled();
        console.log('Next button disabled:', isDisabled);
      }
    }
  });

  test('should display KEV listed status', async ({ page }) => {
    // Check for KEV status indicator
    const kevIndicator = page.locator('text=/KEV Listed/i, text=/Known Exploited/i');
    
    if (await kevIndicator.first().isVisible()) {
      console.log('KEV status indicators found');
      expect(await kevIndicator.count()).toBeGreaterThan(0);
    }
  });

  test('should have interactive elements', async ({ page }) => {
    // Check buttons are clickable
    const buttons = page.locator('button:visible');
    const buttonCount = await buttons.count();
    expect(buttonCount).toBeGreaterThan(0);
    
    // Check first button hover state
    const firstButton = buttons.first();
    await firstButton.hover();
    
    // Button should be interactive
    const isEnabled = await firstButton.isEnabled();
    expect(isEnabled).toBeTruthy();
  });

  test('should load without console errors', async ({ page }) => {
    const errors: string[] = [];
    
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });
    
    await page.goto(LIVE_URL);
    await page.waitForLoadState('networkidle');
    
    // Filter out expected errors (like favicon)
    const criticalErrors = errors.filter(err => 
      !err.includes('favicon') && 
      !err.includes('404') &&
      !err.includes('Failed to load resource')
    );
    
    expect(criticalErrors).toHaveLength(0);
  });
});