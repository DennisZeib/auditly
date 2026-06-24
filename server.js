'use strict';

/**
 * server.js — Auditly scanner API
 * - POST /api/scan { url }  → full report with score, grade, findings, fixes
 * - GET  /health           → uptime check
 * - GET  /                 → serves the frontend (index.html)
 *
 * Designed to run on free tiers: core checks are pure-HTTP. Browser checks are
 * lazy/optional (see browserChecks.js) so the process never OOM-crashes.
 */

const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const net = require('net');
const path = require('path');

const { runSecurityChecks } = require('./securityChecks');
const { runNetworkChecks } = require('./networkChecks');
const { runBrokenLinks } = require('./brokenLinks');
const { runBrowserChecks } = require('./browserChecks');
const { getFix } = require('./fixSuggestions');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(__dirname)); // serves index.html

// ---- naive in-memory rate limit (per IP) ----
const RL = new Map();
const RL_WINDOW = 60_000;
const RL_MAX = 10;
function rateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  const now = Date.now();
  const rec = RL.get(ip) || { count: 0, start: now };
  if (now - rec.start > RL_WINDOW) { rec.count = 0; rec.start = now; }
  rec.count++;
  RL.set(ip, rec);
  if (rec.count > RL_MAX) return res.status(429).json({ error: 'Too many scans. Wait a minute and try again.' });
  next();
}

// ---- SSRF protection: block localhost / private / link-local targets ----
function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return (
      p[0] === 10 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      p[0] === 0
    );
  }
  const lc = ip.toLowerCase();
  return lc === '::1' || lc.startsWith('fc') || lc.startsWith('fd') || lc.startsWith('fe80') || lc === '::';
}

async function validateTarget(raw) {
  let url;
  try { url = new URL(raw.startsWith('http') ? raw : 'https://' + raw); }
  catch { return { ok: false, error: 'Invalid URL.' }; }

  if (!['http:', 'https:'].includes(url.protocol)) return { ok: false, error: 'Only http/https URLs are allowed.' };

  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) {
    return { ok: false, error: 'Local addresses are not allowed.' };
  }

  try {
    const records = await dns.lookup(host, { all: true });
    if (records.some((r) => isPrivateIP(r.address))) {
      return { ok: false, error: 'Private/internal addresses are not allowed.' };
    }
  } catch {
    return { ok: false, error: 'Could not resolve that domain.' };
  }

  return { ok: true, url: url.href };
}

// ---- scoring ----
const WEIGHTS = { critical: 25, high: 12, medium: 5, low: 2, positive: 0 };
function scoreFromFindings(findings) {
  let penalty = 0;
  for (const f of findings) penalty += WEIGHTS[f.severity] || 0;
  const score = Math.max(0, 100 - penalty);
  let grade = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 55) grade = 'D';
  return { score, grade };
}

function subScore(findings) {
  const { score } = scoreFromFindings(findings);
  return score;
}

app.get('/health', (_req, res) => res.json({ ok: true, version: '2.0.0', uptime: process.uptime() }));

app.post('/api/scan', rateLimit, async (req, res) => {
  const started = Date.now();
  const { url: raw } = req.body || {};
  if (!raw || typeof raw !== 'string') return res.status(400).json({ error: 'Provide a "url".' });

  const v = await validateTarget(raw);
  if (!v.ok) return res.status(400).json({ error: v.error });
  const target = v.url;

  try {
    // Core (pure-HTTP) checks first — these always run, even on free tiers.
    const sec = await runSecurityChecks(target);
    const html = sec.mainBody || '';
    const finalUrl = sec.finalUrl || target;

    const [net_, links, browser] = await Promise.all([
      runNetworkChecks(finalUrl),
      runBrokenLinks(finalUrl, html),
      runBrowserChecks(finalUrl), // no-op unless ENABLE_BROWSER=1 + Chromium present
    ]);

    const findings = [
      ...sec.findings,
      ...net_.findings,
      ...links.findings,
      ...browser.findings,
    ];
    const positives = [
      ...(sec.positives || []),
      ...(net_.positives || []),
      ...(links.positives || []),
      ...(browser.positives || []),
    ];

    // Attach fixes
    for (const f of findings) f.fix = getFix(f.id);

    // Sort by severity
    const order = { critical: 0, high: 1, medium: 2, low: 3, positive: 4 };
    findings.sort((a, b) => (order[a.severity] - order[b.severity]));

    const { score, grade } = scoreFromFindings(findings);

    const counts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});

    res.json({
      url: finalUrl,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      score,
      grade,
      counts,
      subscores: {
        security: subScore(sec.findings),
        network: subScore(net_.findings),
        links: subScore(links.findings),
      },
      browserChecks: browser.skipped ? `skipped (${browser.skipped})` : 'ran',
      findings,
      positives,
    });
  } catch (e) {
    res.status(500).json({ error: 'Scan failed unexpectedly.', detail: e.message });
  }
});

// SPA-ish fallback to the frontend
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Auditly API running on port ${PORT}`));
