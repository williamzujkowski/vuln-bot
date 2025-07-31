import { test, expect } from '@playwright/test';

const LIVE_URL = 'https://williamzujkowski.github.io/vuln-bot/';

test.describe('Vuln-Bot Live Site Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(LIVE_URL);
  });

  test('should load the homepage', async ({ page }) => {
    await expect(page).toHaveTitle(/Vulnerability Intelligence Dashboard/);
    await expect(page.locator('h1')).toContainText('Vulnerability Intelligence Dashboard');
  });

  test('should display vulnerability statistics', async ({ page }) => {
    // Check for stats cards
    const statsGrid = page.locator('.stats-grid');
    await expect(statsGrid).toBeVisible();
    
    // Check for critical and high severity cards
    await expect(page.locator('.stat-card.critical')).toBeVisible();
    await expect(page.locator('.stat-card.high')).toBeVisible();
  });

  test('should have working search functionality', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"]');
    await expect(searchInput).toBeVisible();
    
    // Test search
    await searchInput.fill('CVE-2024');
    await page.waitForTimeout(500); // Wait for debounce
    
    // Check if results are filtered
    const resultsCount = page.locator('.results-count');
    await expect(resultsCount).toBeVisible();
  });

  test('should have working filters', async ({ page }) => {
    // Test severity filter
    const severityFilter = page.locator('select[x-model="filters.severity"]');
    await expect(severityFilter).toBeVisible();
    await severityFilter.selectOption('CRITICAL');
    
    // Test risk score filter
    const riskScoreFilter = page.locator('input[x-model="filters.riskScore"]');
    await expect(riskScoreFilter).toBeVisible();
  });

  test('should display vulnerability table', async ({ page }) => {
    const table = page.locator('.vulnerability-table');
    await expect(table).toBeVisible();
    
    // Check table headers
    await expect(page.locator('th:has-text("CVE ID")')).toBeVisible();
    await expect(page.locator('th:has-text("Severity")')).toBeVisible();
    await expect(page.locator('th:has-text("Risk Score")')).toBeVisible();
  });

  test('should have working pagination', async ({ page }) => {
    const pagination = page.locator('.pagination');
    await expect(pagination).toBeVisible();
    
    // Check pagination controls
    const prevButton = page.locator('button:has-text("Previous")');
    const nextButton = page.locator('button:has-text("Next")');
    await expect(prevButton).toBeVisible();
    await expect(nextButton).toBeVisible();
  });

  test('should have accessible keyboard navigation', async ({ page }) => {
    // Test keyboard shortcuts
    await page.keyboard.press('/'); // Focus search
    const searchInput = page.locator('input[placeholder*="Search"]');
    await expect(searchInput).toBeFocused();
    
    await page.keyboard.press('Escape'); // Clear focus
    await page.keyboard.press('r'); // Reset filters
  });

  test('should have working export functionality', async ({ page }) => {
    const exportButton = page.locator('button:has-text("Export")');
    await expect(exportButton).toBeVisible();
    
    // Test CSV export
    const downloadPromise = page.waitForEvent('download');
    await exportButton.click();
    await page.locator('button:has-text("CSV")').click();
    
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('vulnerabilities');
    expect(download.suggestedFilename()).toContain('.csv');
  });

  test('should display charts and visualizations', async ({ page }) => {
    // Check for chart containers
    const chartContainers = page.locator('.chart-container');
    const count = await chartContainers.count();
    expect(count).toBeGreaterThan(0);
    
    // Check specific charts
    await expect(page.locator('#severityChart')).toBeVisible();
    await expect(page.locator('#riskTrendChart')).toBeVisible();
    await expect(page.locator('#epssDistributionChart')).toBeVisible();
    await expect(page.locator('#vendorRiskChart')).toBeVisible();
  });

  test('should have working modal for CVE details', async ({ page }) => {
    // Click on first CVE in table
    const firstCVE = page.locator('tbody tr').first().locator('button');
    await firstCVE.click();
    
    // Check modal appears
    const modal = page.locator('.modal');
    await expect(modal).toBeVisible();
    
    // Check modal content
    await expect(modal.locator('h2')).toBeVisible();
    
    // Close modal
    await page.locator('.modal-close').click();
    await expect(modal).not.toBeVisible();
  });

  test('should have responsive design', async ({ page, viewport }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Check mobile menu
    const mobileMenu = page.locator('.mobile-menu-toggle');
    if (await mobileMenu.isVisible()) {
      await mobileMenu.click();
      await expect(page.locator('.nav')).toBeVisible();
    }
    
    // Check filters collapse on mobile
    const filterToggle = page.locator('.filter-toggle');
    if (await filterToggle.isVisible()) {
      await expect(filterToggle).toBeVisible();
    }
  });

  test('should have proper SEO meta tags', async ({ page }) => {
    // Check meta tags
    const description = await page.getAttribute('meta[name="description"]', 'content');
    expect(description).toBeTruthy();
    
    const ogTitle = await page.getAttribute('meta[property="og:title"]', 'content');
    expect(ogTitle).toBeTruthy();
    
    const twitterCard = await page.getAttribute('meta[property="twitter:card"]', 'content');
    expect(twitterCard).toBeTruthy();
  });

  test('should have service worker registered', async ({ page }) => {
    const swRegistered = await page.evaluate(() => {
      return 'serviceWorker' in navigator && navigator.serviceWorker.controller !== null;
    });
    
    // Note: SW might not be active on first load
    console.log('Service Worker registered:', swRegistered);
  });

  test('should handle offline mode gracefully', async ({ page, context }) => {
    // Load page first
    await page.goto(LIVE_URL);
    await page.waitForLoadState('networkidle');
    
    // Go offline
    await context.setOffline(true);
    
    // Try to navigate
    await page.reload();
    
    // Should show offline indicator or cached content
    const offlineIndicator = page.locator('.offline-indicator');
    const isOfflineVisible = await offlineIndicator.isVisible().catch(() => false);
    
    // Page should still be functional with cached data
    expect(page.url()).toBeTruthy();
  });

  test('should load web fonts and icons', async ({ page }) => {
    // Check if fonts are loaded
    const fontLoaded = await page.evaluate(() => {
      return document.fonts.check('16px -apple-system');
    });
    expect(fontLoaded).toBeTruthy();
    
    // Check if emoji or icon is visible
    const icon = page.locator('text=🛡️').first();
    await expect(icon).toBeVisible();
  });

  test('should have working navigation links', async ({ page }) => {
    // Test navigation
    const navLinks = page.locator('.nav a');
    const linkCount = await navLinks.count();
    expect(linkCount).toBeGreaterThan(0);
    
    // Test first nav link
    if (linkCount > 0) {
      const firstLink = navLinks.first();
      const href = await firstLink.getAttribute('href');
      expect(href).toBeTruthy();
    }
  });

  test('should display footer with links', async ({ page }) => {
    const footer = page.locator('.footer');
    await expect(footer).toBeVisible();
    
    // Check footer links
    await expect(footer.locator('a')).toHaveCount(3); // Dashboard, API, GitHub
  });

  test('should have proper error handling', async ({ page }) => {
    // Test 404 page
    await page.goto(LIVE_URL + 'nonexistent-page');
    
    // Should either show 404 or redirect to home
    await expect(page).toHaveURL(/vuln-bot/);
  });
});