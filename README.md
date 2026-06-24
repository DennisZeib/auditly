# Auditly — Scan before you ship

Free security & health scanner for web apps. Point it at a URL, get a graded
report (exposed secrets, missing headers, weak TLS, broken links, email
spoofing gaps) with **copy-paste fixes per stack** (Next.js · Express · Netlify · Nginx).

Built as a lead-gen tool for QA audit work — the free scan finds the surface
problems; the [Fiverr](https://www.fiverr.com/DennisZeib) full audit fixes them.

---

## Why it won't crash (the fix for the old version)

The previous build launched Chromium (Lighthouse + Playwright) on every scan,
which needs 512MB+ RAM and OOM-crashes free hosts. This version separates them:

- **Core checks** (security headers, exposed files/secrets, CORS, TLS, DNS,
  broken links) are **pure HTTP** — tiny RAM, run anywhere, never crash.
- **Browser checks** (console errors, post-render secret scan) are **lazy and
  optional** — off by default, and degrade to a no-op if Chromium isn't present.

So the deployed app runs comfortably in **256MB** free-tier RAM.

---

## Run locally

```bash
npm install
npm start
# open http://localhost:3001
```

---

## Deploy FREE (recommended split)

### Backend → Fly.io (free, scales to zero)

1. Install the CLI: https://fly.io/docs/hands-on/install-flyctl/
2. From the project folder:
   ```bash
   fly auth signup        # or: fly auth login
   fly launch --no-deploy # accept the detected Dockerfile; keep app name or pick one
   fly deploy
   ```
3. `fly deploy` prints your URL, e.g. `https://auditly.fly.dev`.
4. Test it: open `https://auditly.fly.dev/health` → should return `{"ok":true}`.

`auto_stop_machines = true` in `fly.toml` means the app sleeps when idle, so it
stays within the free allowance. First request after idle takes ~2s to wake.

### Frontend → already served by the backend

The backend serves `index.html` itself, so **your Fly URL is the whole app.**
Done. Share `https://auditly.fly.dev`.

### (Optional) Frontend on Netlify instead

If you want the UI on Netlify (custom domain, CDN) and the API on Fly:

1. Drag `index.html` to https://app.netlify.com/drop
2. In the deployed page, the API base must point to Fly. Easiest: open
   `index.html` before uploading and add this one line in the `<script>` near
   the top:
   ```js
   window.API_URL = 'https://auditly.fly.dev';
   ```
3. Re-upload. Netlify serves the UI; Fly answers `/api/scan`.

CORS is already open on the backend, so this works out of the box.

---

## (Optional) Enable deep browser checks

Only if your host has the RAM (≥512MB) and you want console-error + post-render
secret scanning:

1. In the `Dockerfile`, install Chromium and Playwright:
   ```dockerfile
   RUN apt-get update && apt-get install -y chromium && rm -rf /var/lib/apt/lists/*
   RUN npm install playwright-core
   ENV CHROME_PATH=/usr/bin/chromium
   ENV ENABLE_BROWSER=1
   ```
2. Bump `fly.toml` memory to `512mb`.
3. `fly deploy`.

If anything is missing, the scanner just skips browser checks — it never fails.

---

## API

`POST /api/scan` → `{ "url": "example.com" }`

Returns `{ score, grade, counts, subscores, findings[], positives[] }`.
Each finding includes a `fix` object with per-stack instructions.

`GET /health` → `{ ok: true, version, uptime }`

---

## Contact

Dennis Zeib — forensic QA engineer
- Fiverr: https://www.fiverr.com/DennisZeib
- Email: zeibdennis1@gmail.com

MIT licensed.
