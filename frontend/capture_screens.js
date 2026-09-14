const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1600, height: 900 },
    deviceScaleFactor: 2
  });
  const page = await context.newPage();

  console.log("Navigating to login...");
  await page.goto('http://localhost:3000', { waitUntil: 'load' });
  
  // Wait for login or main dashboard to load
  try {
    const title = await page.title();
    console.log("Title: ", title);
    
    // Explicitly check for email input to know we are on login
    const emailInput = page.locator('input[type="email"]');
    if (await emailInput.count() > 0) {
      console.log("Logging in...");
      await emailInput.fill('admin@netshield.ai');
      await page.locator('input[type="password"]').fill('admin123');
      await page.locator('button[type="submit"]').click();
      
      // Wait for URL to change
      await page.waitForTimeout(3000);
      console.log("Login successful, proceeding to screenshots.");
    }
  } catch(e) {
    console.log("Login flow skipped or failed:", e.message);
  }

  const capture = async (url, path) => {
    console.log(`Capturing ${path}...`);
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(4000); // Give React/Recharts time to render and fetch APIs
    await page.screenshot({ path: path, fullPage: true });
  };

  // 1. Dashboard
  await capture('http://localhost:3000/security-analytics', '../m3_dashboard.png');

  // 2. Threat Alerts
  await capture('http://localhost:3000/threat-alerts', '../m3_alerts.png');

  // 3. Incident Management
  await capture('http://localhost:3000/incidents', '../m3_incidents.png');
  
  // 3.b Click into an incident detail
  try {
    console.log("Capturing Incident Details...");
    const row = await page.locator('table tbody tr').first();
    if (await row.isVisible()) {
      await row.click();
      await page.waitForTimeout(3000);
      await page.screenshot({ path: '../m3_incident_detail.png', fullPage: true });
    }
  } catch (e) {
    console.log("Could not capture incident detail.", e.message);
  }

  // 4. Threat Intelligence
  await capture('http://localhost:3000/threat-intelligence', '../m3_threat_intel.png');
  
  // 5. Reports
  await capture('http://localhost:3000/reports', '../m3_reports.png');

  await browser.close();
  console.log("Done capturing all screenshots.");
})();
