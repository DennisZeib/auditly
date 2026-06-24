'use strict';

/**
 * networkChecks.js
 * SSL/TLS certificate inspection + DNS email security (SPF/DMARC).
 * Uses only Node built-ins (tls, dns). No browser, no extra deps.
 */

const tls = require('tls');
const dns = require('dns').promises;

function checkTLS(hostname, port = 443) {
  return new Promise((resolve) => {
    const findings = [];
    const positives = [];
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };

    const socket = tls.connect({ host: hostname, port, servername: hostname, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate();
      const proto = socket.getProtocol();

      if (!cert || !Object.keys(cert).length) {
        findings.push({ id: 'tls_nocert', severity: 'high', title: 'No TLS certificate returned', detail: 'Could not read a certificate from the server.', evidence: '' });
        socket.end();
        return done({ findings, positives });
      }

      // Expiry
      const now = Date.now();
      const valid_to = new Date(cert.valid_to).getTime();
      const daysLeft = Math.round((valid_to - now) / 86400000);
      if (daysLeft < 0) {
        findings.push({ id: 'tls_expired', severity: 'critical', title: 'TLS certificate expired', detail: `Expired ${Math.abs(daysLeft)} days ago. Browsers will block the site.`, evidence: cert.valid_to });
      } else if (daysLeft < 15) {
        findings.push({ id: 'tls_expiring', severity: 'high', title: `TLS certificate expires in ${daysLeft} days`, detail: 'Renew now to avoid an outage.', evidence: cert.valid_to });
      } else {
        positives.push({ id: 'tls_valid', severity: 'positive', title: `TLS certificate valid (${daysLeft} days left)`, detail: '' });
      }

      // Protocol version
      if (proto === 'TLSv1' || proto === 'TLSv1.1') {
        findings.push({ id: 'tls_old', severity: 'medium', title: `Weak TLS version (${proto})`, detail: 'TLS 1.0/1.1 are deprecated. Require TLS 1.2+.', evidence: proto });
      } else if (proto) {
        positives.push({ id: 'tls_proto', severity: 'positive', title: `Modern TLS (${proto})`, detail: '' });
      }

      socket.end();
      done({ findings, positives });
    });

    socket.on('error', (e) => {
      findings.push({ id: 'tls_error', severity: 'high', title: 'TLS handshake failed', detail: e.message, evidence: '' });
      done({ findings, positives });
    });
    socket.on('timeout', () => { socket.destroy(); done({ findings, positives }); });
  });
}

async function checkDNSEmail(hostname) {
  const findings = [];
  const positives = [];
  const root = hostname.split('.').slice(-2).join('.');

  // SPF
  try {
    const txt = await dns.resolveTxt(root);
    const flat = txt.map((r) => r.join(''));
    const spf = flat.find((r) => r.toLowerCase().startsWith('v=spf1'));
    if (spf) positives.push({ id: 'spf', severity: 'positive', title: 'SPF record present', detail: '' });
    else findings.push({ id: 'no_spf', severity: 'low', title: 'No SPF record', detail: 'Without SPF, attackers can spoof email from your domain.', evidence: root });
  } catch {
    findings.push({ id: 'no_spf', severity: 'low', title: 'No SPF record', detail: 'Without SPF, attackers can spoof email from your domain.', evidence: root });
  }

  // DMARC
  try {
    const txt = await dns.resolveTxt('_dmarc.' + root);
    const flat = txt.map((r) => r.join(''));
    const dmarc = flat.find((r) => r.toLowerCase().startsWith('v=dmarc1'));
    if (dmarc) positives.push({ id: 'dmarc', severity: 'positive', title: 'DMARC record present', detail: '' });
    else findings.push({ id: 'no_dmarc', severity: 'low', title: 'No DMARC record', detail: 'DMARC tells receivers how to handle spoofed mail. Add at least p=none to start.', evidence: root });
  } catch {
    findings.push({ id: 'no_dmarc', severity: 'low', title: 'No DMARC record', detail: 'DMARC tells receivers how to handle spoofed mail. Add at least p=none to start.', evidence: root });
  }

  return { findings, positives };
}

async function runNetworkChecks(targetUrl) {
  let hostname;
  try { hostname = new URL(targetUrl).hostname; }
  catch { return { findings: [], positives: [] }; }

  const [tlsR, dnsR] = await Promise.all([
    checkTLS(hostname).catch(() => ({ findings: [], positives: [] })),
    checkDNSEmail(hostname).catch(() => ({ findings: [], positives: [] })),
  ]);

  return {
    findings: [...tlsR.findings, ...dnsR.findings],
    positives: [...tlsR.positives, ...dnsR.positives],
  };
}

module.exports = { runNetworkChecks };
