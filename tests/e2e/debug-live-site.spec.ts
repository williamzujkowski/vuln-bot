import { test } from '@playwright/test';

const LIVE_URL = 'https://williamzujkowski.github.io/vuln-bot/';

test('debug: capture live site state', async ({ page }) => {
  await page.goto(LIVE_URL, { waitUntil: 'networkidle' });
  
  // Take full page screenshot
  await page.screenshot({ 
    path: 'live-site-screenshot.png', 
    fullPage: true 
  });
  
  // Log page title
  const title = await page.title();
  console.log('Page title:', title);
  
  // Log page URL
  console.log('Current URL:', page.url());
  
  // Get page content
  const h1Text = await page.locator('h1').textContent().catch(() => 'No h1 found');
  console.log('H1 text:', h1Text);
  
  // Check for any error messages
  const bodyText = await page.locator('body').textContent();
  console.log('Page content preview:', bodyText?.substring(0, 500));
  
  // Check for 404 or error indicators
  const is404 = bodyText?.toLowerCase().includes('404') || 
                bodyText?.toLowerCase().includes('not found');
  console.log('Is 404 page:', is404);
  
  // Check console errors
  page.on('console', msg => {
    if (msg.type() === 'error') {
      console.log('Console error:', msg.text());
    }
  });
  
  // Check network failures
  page.on('response', response => {
    if (!response.ok() && !response.url().includes('favicon')) {
      console.log(`Network error: ${response.status()} ${response.url()}`);
    }
  });
  
  // Wait a bit to catch any async errors
  await page.waitForTimeout(2000);
});