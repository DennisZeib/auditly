'use strict';

/**
 * fixSuggestions.js
 * Maps finding IDs → concrete, copy-paste fixes per stack.
 * Stacks: nextjs (Next.js/Vercel), express, netlify, nginx.
 * This is the "agent logic" — deterministic, zero API cost.
 */

const STACKS = ['nextjs', 'express', 'netlify', 'nginx'];

const GENERIC_FIX = {
  why: 'This issue weakens your site’s security or reliability posture.',
  fixes: {
    nextjs: 'Review the relevant configuration in next.config.js or your middleware.',
    express: 'Add or adjust the relevant middleware in your Express app.',
    netlify: 'Configure this in netlify.toml under [[headers]] or [[redirects]].',
    nginx: 'Adjust the relevant directive in your nginx server block.',
  },
};

// Reusable header snippets
const HSTS = 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload';
const CSP = "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'";

const FIXES = {
  no_https: {
    why: 'Plain HTTP exposes all traffic to interception and tampering. HTTPS is non-negotiable.',
    fixes: {
      nextjs: 'On Vercel, HTTPS is automatic. If self-hosting, terminate TLS at your proxy and redirect HTTP→HTTPS.',
      express: 'Put Express behind a TLS-terminating proxy (Caddy/Nginx) or use a managed host. Force redirect:\n\napp.use((req,res,next)=>{ if(req.headers["x-forwarded-proto"]!=="https") return res.redirect("https://"+req.headers.host+req.url); next(); });',
      netlify: 'Netlify provisions HTTPS automatically via Let’s Encrypt. Enable "Force HTTPS" in Domain settings.',
      nginx: 'server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}',
    },
  },
  'hdr_strict-transport-security': {
    why: 'HSTS forces browsers to use HTTPS and prevents protocol-downgrade attacks.',
    fixes: {
      nextjs: `// next.config.js\nasync headers() {\n  return [{ source: '/(.*)', headers: [{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' }] }];\n}`,
      express: `const helmet = require('helmet');\napp.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));`,
      netlify: `# netlify.toml\n[[headers]]\n  for = "/*"\n  [headers.values]\n    ${HSTS}`,
      nginx: `add_header ${HSTS} always;`,
    },
  },
  'hdr_content-security-policy': {
    why: 'CSP is the single strongest defense against XSS by restricting what can load and execute.',
    fixes: {
      nextjs: `// next.config.js headers()\n{ key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'" }`,
      express: `const helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"] } }));`,
      netlify: `# netlify.toml\n[[headers]]\n  for = "/*"\n  [headers.values]\n    ${CSP}`,
      nginx: `add_header ${CSP} always;`,
    },
  },
  'hdr_x-frame-options': {
    why: 'Prevents your site from being embedded in an iframe for clickjacking.',
    fixes: {
      nextjs: `{ key: 'X-Frame-Options', value: 'DENY' }`,
      express: `app.use(require('helmet').frameguard({ action: 'deny' }));`,
      netlify: `[[headers]]\n  for = "/*"\n  [headers.values]\n    X-Frame-Options = "DENY"`,
      nginx: `add_header X-Frame-Options "DENY" always;`,
    },
  },
  'hdr_x-content-type-options': {
    why: 'Stops browsers from MIME-sniffing responses into a different content type.',
    fixes: {
      nextjs: `{ key: 'X-Content-Type-Options', value: 'nosniff' }`,
      express: `app.use(require('helmet').noSniff());`,
      netlify: `X-Content-Type-Options = "nosniff"`,
      nginx: `add_header X-Content-Type-Options "nosniff" always;`,
    },
  },
  'hdr_referrer-policy': {
    why: 'Limits how much referrer information leaks to other sites.',
    fixes: {
      nextjs: `{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }`,
      express: `app.use(require('helmet').referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));`,
      netlify: `Referrer-Policy = "strict-origin-when-cross-origin"`,
      nginx: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
    },
  },
  'hdr_permissions-policy': {
    why: 'Restricts powerful browser features (camera, mic, geolocation) by default.',
    fixes: {
      nextjs: `{ key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' }`,
      express: `app.use((req,res,next)=>{ res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()'); next(); });`,
      netlify: `Permissions-Policy = "camera=(), microphone=(), geolocation=()"`,
      nginx: `add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;`,
    },
  },
  cors_wildcard: {
    why: 'A wildcard CORS origin lets any website read your responses. With credentials it is a critical leak.',
    fixes: {
      nextjs: `// Restrict to known origins in your route/middleware\nconst allowed = ['https://yourapp.com'];\nconst origin = req.headers.origin;\nif (allowed.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);`,
      express: `const cors = require('cors');\napp.use(cors({ origin: ['https://yourapp.com'], credentials: true }));`,
      netlify: `# Avoid "*". Set a specific origin per route in your function responses.`,
      nginx: `# Replace "*" with an explicit origin\nadd_header Access-Control-Allow-Origin "https://yourapp.com" always;`,
    },
  },
  'path__env': {
    why: 'A reachable .env leaks database URLs, API keys, and secrets — full compromise risk.',
    fixes: {
      nextjs: `Never place .env in /public. Ensure it stays at project root and is in .gitignore. Vercel serves only /public + build output.`,
      express: `Do not serve your project root statically. Restrict express.static to a dedicated /public dir and block dotfiles:\napp.use(express.static('public', { dotfiles: 'deny' }));`,
      netlify: `Set your publish directory to the build output only (e.g. "dist"/"out"), never the repo root.`,
      nginx: `location ~ /\\.(?!well-known) { deny all; return 404; }`,
    },
  },
  'path__git_config': {
    why: 'An exposed .git directory lets attackers reconstruct your entire source code.',
    fixes: {
      nextjs: `Ensure .git is never inside /public. It should never be deployed.`,
      express: `app.use((req,res,next)=>{ if(req.path.includes('/.git')) return res.sendStatus(404); next(); });`,
      netlify: `.git is excluded from Netlify deploys by default — verify your publish dir isn’t the repo root.`,
      nginx: `location ~ /\\.git { deny all; return 404; }`,
    },
  },
  admin_open: {
    why: 'An admin area reachable without an auth gate is a direct path to takeover.',
    fixes: {
      nextjs: `Protect the route in middleware.ts:\nif (req.nextUrl.pathname.startsWith('/admin') && !isAuthed(req)) return NextResponse.redirect(new URL('/login', req.url));`,
      express: `function requireAuth(req,res,next){ if(!req.session?.user) return res.redirect('/login'); next(); }\napp.use('/admin', requireAuth);`,
      netlify: `Gate admin pages with Netlify Identity or an edge function that checks a session cookie.`,
      nginx: `location /admin { auth_basic "Restricted"; auth_basic_user_file /etc/nginx/.htpasswd; }`,
    },
  },
  server_banner: {
    why: 'Disclosing server software/version helps attackers target known CVEs.',
    fixes: {
      nextjs: `Vercel manages this. If self-hosting behind Nginx, hide the banner (see nginx tab).`,
      express: `app.disable('x-powered-by');`,
      netlify: `Netlify manages the server header; no action needed.`,
      nginx: `server_tokens off;`,
    },
  },
  powered_by: {
    why: 'X-Powered-By reveals your backend framework, narrowing an attacker’s search.',
    fixes: {
      nextjs: `// next.config.js\nmodule.exports = { poweredByHeader: false };`,
      express: `app.disable('x-powered-by');  // or use helmet()`,
      netlify: `Strip it in netlify.toml [[headers]] if present.`,
      nginx: `proxy_hide_header X-Powered-By;`,
    },
  },
  no_dmarc: {
    why: 'Without DMARC, attackers can spoof email from your domain for phishing.',
    fixes: {
      nextjs: 'Add a DNS TXT record (not a code change).',
      express: 'Add a DNS TXT record (not a code change).',
      netlify: 'Add this DNS TXT record in your domain settings:\nHost: _dmarc\nValue: v=DMARC1; p=none; rua=mailto:you@yourdomain.com',
      nginx: 'Add a DNS TXT record at _dmarc with: v=DMARC1; p=none; rua=mailto:you@yourdomain.com',
    },
  },
  no_spf: {
    why: 'Without SPF, mail servers can’t verify which hosts may send mail for your domain.',
    fixes: {
      nextjs: 'Add a DNS TXT record (not a code change).',
      express: 'Add a DNS TXT record (not a code change).',
      netlify: 'Add a DNS TXT record at root: v=spf1 include:_spf.google.com ~all (adjust for your mail provider).',
      nginx: 'Add a DNS TXT record at root: v=spf1 ~all (adjust to include your mail provider).',
    },
  },
};

function getFix(findingId) {
  // Normalize header/path ids to their base fix keys.
  const direct = FIXES[findingId];
  if (direct) return direct;
  // secrets, cookies, source maps, links → generic but tailored message
  if (findingId.startsWith('secret_') || findingId.startsWith('rendered_secret_')) {
    return {
      why: 'A live credential in client-accessible code can be used immediately by anyone who views source.',
      fixes: {
        nextjs: 'Move the secret to a server-only env var (no NEXT_PUBLIC_ prefix). Rotate the leaked key now.',
        express: 'Store secrets in process.env on the server only; never send them to the client. Rotate the key now.',
        netlify: 'Use Netlify environment variables accessed only inside functions. Rotate the key now.',
        nginx: 'Secrets should live server-side, never in delivered HTML/JS. Rotate the key now.',
      },
    };
  }
  if (findingId.startsWith('cookie_')) {
    return {
      why: 'Cookies without Secure/HttpOnly/SameSite can be stolen via XSS or sent over insecure channels.',
      fixes: {
        nextjs: `res.setHeader('Set-Cookie', 'session=...; Secure; HttpOnly; SameSite=Lax; Path=/');`,
        express: `res.cookie('session', val, { secure: true, httpOnly: true, sameSite: 'lax' });`,
        netlify: `Set cookies inside functions with Secure; HttpOnly; SameSite=Lax attributes.`,
        nginx: `proxy_cookie_flags ~ secure httponly samesite=lax;`,
      },
    };
  }
  if (findingId.startsWith('link_')) {
    return {
      why: 'Broken links and assets erode trust and reduce SEO crawl quality.',
      fixes: {
        nextjs: 'Fix or remove the dead URL; use next/link for internal routes and verify asset paths.',
        express: 'Update or remove the dead reference; confirm the static asset exists.',
        netlify: 'Fix the URL or add a redirect in netlify.toml for moved resources.',
        nginx: 'Update the reference or add a rewrite/redirect for the moved resource.',
      },
    };
  }
  return GENERIC_FIX;
}

module.exports = { getFix, STACKS };
