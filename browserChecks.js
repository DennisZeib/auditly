'use strict';

/**
 * browserChecks.js
 * OPTIONAL deep checks that need a real browser (console errors, post-render
 * secret scan). Chromium is loaded LAZILY and the whole module degrades to a
 * no-op if no browser is available — this is what lets the core scanner run on
 * free hosting (256–512MB RAM) without ever crashing.
 *
 * Set ENABLE_BROWSER=1 in the environment to attempt browser checks.
 */

const { SECRET_PATTERNS } = require('./securityChecks');

let _pwChecked = false;
let _playwright = null;

function getPlaywright() {
  if (_pwChecked) return _playwright;
  _pwChecked = true;
  try {
    _playwright = require('playwright-core');
  } catch {
    _playwright = null;
  }
  return _playwright;
}

function resolveChromePath() {
  // Honor explicit override first (set this on your host if needed).
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const candidates = [
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
  ];
  const fs = require('fs');
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c; } catch { /* ignore */ }
  }
  return null;
}

async function runBrowserChecks(targetUrl) {
  const findings = [];
  const positives = [];

  // Feature-flagged off by default → guarantees free-tier stability.
  if (process.env.ENABLE_BROWSER !== '1') {
    return { findings, positives, skipped: 'disabled' };
  }

  const pw = getPlaywright();
  const execPath = resolveChromePath();
  if (!pw || !execPath) {
    return { findings, positives, skipped: 'no-chromium' };
  }

  let browser;
  try {
    browser = await pw.chromium.launch({
      executablePath: execPath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--single-process'],
      timeout: 15000,
    });
    const ctx = await browser.newContext({ userAgent: 'AuditlyScanner/2.0' });
    const page = await ctx.newPage();

    const consoleErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => consoleErrors.push(err.message));

    await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 20000 }).catch(() => {});
    const rendered = await page.content().catch(() => '');

    // Post-render secret scan (catches secrets injected by JS after load)
    for (const p of SECRET_PATTERNS) {
      const m = rendered.match(p.re);
      if (m) {
        if (p.guard && !p.guard.test(rendered)) continue;
        findings.push({
          id: 'rendered_secret_' + p.id,
          severity: 'critical',
          title: `Secret exposed after JS render: ${p.label}`,
          detail: 'A credential appeared in the DOM only after JavaScript ran — static scanners miss this.',
          evidence: m[0].slice(0, 12) + '…',
        });
      }
    }

    if (consoleErrors.length) {
      findings.push({
        id: 'console_errors',
        severity: 'low',
        title: `${consoleErrors.length} console error(s) on load`,
        detail: 'JavaScript errors in the console often signal broken features.',
        evidence: consoleErrors.slice(0, 3).join(' | ').slice(0, 160),
      });
    } else {
      positives.push({ id: 'no_console_errors', severity: 'positive', title: 'No console errors on load', detail: '' });
    }

    await browser.close();
  } catch (e) {
    if (browser) { try { await browser.close(); } catch { /* ignore */ } }
    return { findings, positives, skipped: 'launch-failed' };
  }

  return { findings, positives };
}

module.exports = { runBrowserChecks };
