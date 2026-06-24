'use strict';

/**
 * securityChecks.js
 * Pure-HTTP security & hygiene checks. No browser required.
 * Each finding: { id, severity, title, detail, evidence }
 * severity: 'critical' | 'high' | 'medium' | 'low' | 'positive'
 */

const fetch = require('node-fetch');

const UA = 'AuditlyScanner/2.0 (+https://auditly.app)';
const TIMEOUT_MS = 8000;

// Exported so browserChecks can reuse the same patterns post-render.
const SECRET_PATTERNS = [
  { id: 'aws_key', label: 'AWS Access Key', re: /AKIA[0-9A-Z]{16}/ },
  { id: 'aws_secret', label: 'AWS Secret Key', re: /aws_secret_access_key["'\s:=]+[A-Za-z0-9/+=]{40}/i },
  { id: 'stripe_live', label: 'Stripe Live Secret Key', re: /sk_live_[0-9a-zA-Z]{24,}/ },
  { id: 'stripe_restricted', label: 'Stripe Restricted Key', re: /rk_live_[0-9a-zA-Z]{24,}/ },
  { id: 'google_api', label: 'Google API Key', re: /AIza[0-9A-Za-z\-_]{35}/ },
  { id: 'supabase_service', label: 'Supabase service_role JWT', re: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, guard: /service_role/ },
  { id: 'private_key', label: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: 'github_pat', label: 'GitHub Personal Access Token', re: /ghp_[0-9A-Za-z]{36}/ },
  { id: 'openai_key', label: 'OpenAI API Key', re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/ },
  { id: 'slack_token', label: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
];

function timeoutFetch(url, opts = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), opts.timeout || TIMEOUT_MS);
  return fetch(url, {
    redirect: 'manual',
    ...opts,
    signal: controller.signal,
    headers: { 'User-Agent': UA, ...(opts.headers || {}) },
  }).finally(() => clearTimeout(t));
}

function scanText(text) {
  const hits = [];
  for (const p of SECRET_PATTERNS) {
    const m = text.match(p.re);
    if (m) {
      if (p.guard && !p.guard.test(text)) continue;
      hits.push({ label: p.label, sample: m[0].slice(0, 12) + '…' });
    }
  }
  return hits;
}

/** Probe a path; only treat as "exposed" if it differs from the site's 404 shape. */
async function probePath(base, path, baseline) {
  try {
    const res = await timeoutFetch(new URL(path, base).href, { method: 'GET' });
    const status = res.status;
    if (status >= 200 && status < 300) {
      const body = (await res.text()).slice(0, 4000);
      // Guard against SPA catch-all: if body matches the 404 baseline, ignore.
      if (baseline && body && baseline.sample && body.slice(0, 200) === baseline.sample) {
        return null;
      }
      return { status, body };
    }
    return null;
  } catch {
    return null;
  }
}

async function getBaseline(base) {
  try {
    const res = await timeoutFetch(new URL('/auditly-nonexistent-' + Date.now(), base).href);
    const body = (await res.text()).slice(0, 200);
    return { status: res.status, sample: body };
  } catch {
    return null;
  }
}

const SENSITIVE_PATHS = [
  { path: '/.env', sev: 'critical', title: 'Exposed .env file' },
  { path: '/.git/config', sev: 'critical', title: 'Exposed .git repository' },
  { path: '/.aws/credentials', sev: 'critical', title: 'Exposed AWS credentials' },
  { path: '/config.json', sev: 'high', title: 'Exposed config.json' },
  { path: '/wp-config.php.bak', sev: 'critical', title: 'Exposed WordPress config backup' },
  { path: '/firebase-debug.log', sev: 'medium', title: 'Exposed Firebase debug log' },
  { path: '/.DS_Store', sev: 'low', title: 'Exposed .DS_Store (directory listing leak)' },
  { path: '/server-status', sev: 'medium', title: 'Exposed Apache server-status' },
  { path: '/docs', sev: 'low', title: 'Public API docs (/docs)' },
];

const SECURITY_HEADERS = [
  { key: 'strict-transport-security', sev: 'high', title: 'Missing HSTS header', detail: 'Strict-Transport-Security forces HTTPS and blocks downgrade attacks.' },
  { key: 'content-security-policy', sev: 'high', title: 'Missing Content-Security-Policy', detail: 'CSP is the strongest defense against XSS and injection.' },
  { key: 'x-frame-options', sev: 'medium', title: 'Missing X-Frame-Options', detail: 'Protects against clickjacking via iframe embedding.' },
  { key: 'x-content-type-options', sev: 'medium', title: 'Missing X-Content-Type-Options', detail: 'Stops MIME-type sniffing (set to nosniff).' },
  { key: 'referrer-policy', sev: 'low', title: 'Missing Referrer-Policy', detail: 'Controls how much referrer data leaks to third parties.' },
  { key: 'permissions-policy', sev: 'low', title: 'Missing Permissions-Policy', detail: 'Restricts access to camera, mic, geolocation, etc.' },
];

async function runSecurityChecks(targetUrl) {
  const findings = [];
  const positives = [];
  let mainRes, mainBody = '', headers = {};

  try {
    mainRes = await timeoutFetch(targetUrl, { redirect: 'follow' });
    headers = Object.fromEntries(mainRes.headers.entries());
    mainBody = (await mainRes.text()).slice(0, 120000);
  } catch (e) {
    findings.push({
      id: 'unreachable', severity: 'critical',
      title: 'Site unreachable', detail: `Could not connect: ${e.message}`, evidence: '',
    });
    return { findings, positives };
  }

  // 1. HTTPS enforcement
  const finalUrl = mainRes.url || targetUrl;
  if (finalUrl.startsWith('https://')) {
    positives.push({ id: 'https', severity: 'positive', title: 'Serves over HTTPS', detail: 'Encrypted transport confirmed.' });
  } else {
    findings.push({ id: 'no_https', severity: 'critical', title: 'No HTTPS', detail: 'Site served over plain HTTP. All traffic is interceptable.', evidence: finalUrl });
  }

  // 2. Security headers
  for (const h of SECURITY_HEADERS) {
    if (headers[h.key]) {
      positives.push({ id: 'hdr_' + h.key, severity: 'positive', title: `${h.title.replace('Missing ', '')} present`, detail: '' });
    } else {
      findings.push({ id: 'hdr_' + h.key, severity: h.sev, title: h.title, detail: h.detail, evidence: '' });
    }
  }

  // 3. CORS misconfiguration
  const acao = headers['access-control-allow-origin'];
  if (acao === '*') {
    const acac = headers['access-control-allow-credentials'];
    findings.push({
      id: 'cors_wildcard',
      severity: acac === 'true' ? 'critical' : 'medium',
      title: acac === 'true' ? 'CORS wildcard WITH credentials' : 'CORS allows any origin (*)',
      detail: acac === 'true'
        ? 'Access-Control-Allow-Origin: * combined with credentials is forbidden by spec and a serious data-leak risk.'
        : 'Any website can read responses from this origin. Restrict to known origins.',
      evidence: `Access-Control-Allow-Origin: ${acao}`,
    });
  }

  // 4. Secrets in HTML/inline JS
  const secretHits = scanText(mainBody);
  for (const hit of secretHits) {
    findings.push({
      id: 'secret_' + hit.label.replace(/\s+/g, '_').toLowerCase(),
      severity: 'critical',
      title: `Exposed secret: ${hit.label}`,
      detail: 'A credential pattern was found in the page source. Rotate it immediately and move it server-side.',
      evidence: hit.sample,
    });
  }

  // 5. Source maps exposed
  if (/\/\/[#@]\s*sourceMappingURL=.+\.map/.test(mainBody)) {
    findings.push({ id: 'sourcemap', severity: 'low', title: 'Source maps referenced in production', detail: 'Source maps can expose original source code. Disable in production builds.', evidence: '' });
  }

  // 6. Cookie flags
  const setCookie = mainRes.headers.raw && mainRes.headers.raw()['set-cookie'];
  if (setCookie && setCookie.length) {
    for (const c of setCookie) {
      const name = c.split('=')[0];
      const lc = c.toLowerCase();
      const missing = [];
      if (!lc.includes('secure')) missing.push('Secure');
      if (!lc.includes('httponly')) missing.push('HttpOnly');
      if (!lc.includes('samesite')) missing.push('SameSite');
      if (missing.length) {
        findings.push({ id: 'cookie_' + name, severity: 'medium', title: `Cookie "${name}" missing flags`, detail: `Missing: ${missing.join(', ')}. These protect against theft and CSRF.`, evidence: '' });
      }
    }
  }

  // 7. Sensitive path probing (baseline-aware)
  const baseline = await getBaseline(finalUrl);
  await Promise.all(SENSITIVE_PATHS.map(async (sp) => {
    const hit = await probePath(finalUrl, sp.path, baseline);
    if (hit) {
      // Extra confidence: secrets inside exposed config-type files
      const inner = scanText(hit.body || '');
      findings.push({
        id: 'path_' + sp.path.replace(/[^a-z0-9]/gi, '_'),
        severity: sp.sev,
        title: sp.title,
        detail: inner.length ? `Reachable AND contains credential patterns (${inner.map(i => i.label).join(', ')}).` : 'This path is publicly reachable and returned a success status.',
        evidence: `GET ${sp.path} → ${hit.status}`,
      });
    }
  }));

  // 8. /admin — only flag if it's NOT a login page
  const adminHit = await probePath(finalUrl, '/admin', baseline);
  if (adminHit) {
    const looksLikeLogin = /type=["']password["']|login|sign[\s-]?in/i.test(adminHit.body || '');
    if (!looksLikeLogin) {
      findings.push({ id: 'admin_open', severity: 'high', title: 'Admin route reachable without auth gate', detail: '/admin returned content with no visible login. Verify it is access-controlled.', evidence: 'GET /admin → 200' });
    }
  }

  // 9. Server/tech disclosure
  if (headers['server']) {
    findings.push({ id: 'server_banner', severity: 'low', title: 'Server version disclosed', detail: 'The Server header reveals software/version, aiding targeted attacks.', evidence: `Server: ${headers['server']}` });
  }
  if (headers['x-powered-by']) {
    findings.push({ id: 'powered_by', severity: 'low', title: 'X-Powered-By disclosed', detail: 'Reveals backend framework. Remove this header.', evidence: `X-Powered-By: ${headers['x-powered-by']}` });
  }

  return { findings, positives, mainBody, finalUrl };
}

module.exports = { runSecurityChecks, SECRET_PATTERNS, scanText, timeoutFetch };
