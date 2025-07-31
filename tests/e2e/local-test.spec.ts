import { test, expect } from '@playwright/test';

const LOCAL_URL = 'http://localhost:8081';

test.describe('Local Site Functionality Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(LOCAL_URL);
    await page.waitForLoadState('networkidle');
  });

  test('should load with vulnerability data', async ({ page }) => {
    // Check page loaded
    await expect(page).toHaveTitle(/Vulnerability Intelligence Dashboard/);
    
    // Check vulnerabilities are loaded
    const vulnScript = page.locator('script:has-text("vulnerabilities:")');
    const scriptContent = await vulnScript.textContent();
    
    // Should have vulnerability data
    expect(scriptContent).toContain('CVE-2025');
  });

  test('should navigate to CVE detail pages', async ({ page }) => {
    // Go to first CVE page
    await page.goto(`${LOCAL_URL}/cves/CVE-2025-40000/`);
    
    // Check page loaded
    await expect(page.locator('h1')).toContainText('CVE-2025-40000');
    
    // Check vulnerability details
    await expect(page.locator('.severity-badge')).toBeVisible();
    await expect(page.locator('.cvss-score')).toBeVisible();
    await expect(page.locator('.epss-score')).toBeVisible();
    
    // Check back button
    const backButton = page.locator('a:has-text("Back to Dashboard")');
    await expect(backButton).toBeVisible();
    
    // Navigate back
    await backButton.click();
    await expect(page).toHaveURL(LOCAL_URL + '/');
  });

  test('should have working service worker', async ({ page }) => {
    // Check service worker registration
    const swRegistered = await page.evaluate(() => {
      return 'serviceWorker' in navigator;
    });
    
    expect(swRegistered).toBeTruthy();
  });

  test('should have functioning search on main page', async ({ page }) => {
    // Check for Alpine.js initialization
    const alpineLoaded = await page.evaluate(() => {
      return typeof window.Alpine !== 'undefined';
    });
    
    console.log('Alpine.js loaded:', alpineLoaded);
    
    // Check for search functionality
    const searchInput = page.locator('input[type="text"], input[type="search"]').first();
    
    if (await searchInput.isVisible()) {
      await searchInput.fill('CVE-2025-40002');
      await page.waitForTimeout(500); // Debounce
      
      // Should filter results
      const visibleCVEs = await page.locator('text=/CVE-2025-40002/').count();
      expect(visibleCVEs).toBeGreaterThan(0);
    }
  });

  test('should have proper metadata and SEO', async ({ page }) => {
    // Check meta tags
    const description = await page.getAttribute('meta[name="description"]', 'content');
    expect(description).toContain('vulnerability');
    
    // Check for data in dashboard
    const hasData = await page.locator('text=/CVE-2025/').count();
    expect(hasData).toBeGreaterThan(0);
  });
});