'use strict';

/**
 * brokenLinks.js
 * Extracts links/images from the page HTML and checks their status codes.
 * Pure HTTP. Capped and concurrency-limited so it never hangs a free host.
 */

const cheerio = require('cheerio');
const { timeoutFetch } = require('./securityChecks');

const MAX_LINKS = 40;
const CONCURRENCY = 6;

async function mapLimit(items, limit, fn) {
  const results = [];
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx]);
    }
  });
  await Promise.all(workers);
  return results;
}

async function runBrokenLinks(targetUrl, html) {
  const findings = [];
  const positives = [];
  if (!html) return { findings, positives };

  const $ = cheerio.load(html);
  const base = new URL(targetUrl);
  const urls = new Set();

  $('a[href], img[src], link[href], script[src]').each((_, el) => {
    const raw = $(el).attr('href') || $(el).attr('src');
    if (!raw) return;
    if (/^(mailto:|tel:|javascript:|data:|#)/i.test(raw)) return;
    try { urls.add(new URL(raw, base).href); } catch { /* ignore */ }
  });

  const list = [...urls].slice(0, MAX_LINKS);
  if (!list.length) return { findings, positives };

  const checks = await mapLimit(list, CONCURRENCY, async (u) => {
    try {
      const res = await timeoutFetch(u, { method: 'HEAD', redirect: 'follow', timeout: 6000 });
      // Some servers reject HEAD; retry GET on 405.
      if (res.status === 405) {
        const g = await timeoutFetch(u, { method: 'GET', redirect: 'follow', timeout: 6000 });
        return { u, status: g.status };
      }
      return { u, status: res.status };
    } catch {
      return { u, status: 0 };
    }
  });

  const broken = checks.filter((c) => c.status === 0 || c.status >= 400);
  for (const b of broken.slice(0, 15)) {
    findings.push({
      id: 'link_' + Buffer.from(b.u).toString('base64').slice(0, 10),
      severity: b.status >= 500 || b.status === 0 ? 'medium' : 'low',
      title: `Broken resource (${b.status || 'no response'})`,
      detail: 'This link or asset failed to load. Broken resources hurt UX and SEO.',
      evidence: b.u.length > 80 ? b.u.slice(0, 80) + '…' : b.u,
    });
  }

  if (!broken.length) {
    positives.push({ id: 'links_ok', severity: 'positive', title: `All ${list.length} checked links resolve`, detail: '' });
  }

  return { findings, positives };
}

module.exports = { runBrokenLinks };
