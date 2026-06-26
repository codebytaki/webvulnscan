# WebVulnScan — Advanced Website Security & SEO Scanner

A free, open-source website scanner that runs **150+ automated checks** across security, SEO, performance, privacy, and accessibility — all from a single URL.

![Node.js](https://img.shields.io/badge/Node.js-18%2B-brightgreen)
![Express](https://img.shields.io/badge/Express-4.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What It Checks

| Category | Checks |
|---|---|
| **SSL / TLS** | Certificate validity, expiry, TLS version, weak ciphers |
| **Security Headers** | CSP, HSTS, X-Frame-Options, CORS, Referrer-Policy, Permissions-Policy |
| **Injection** | XSS (reflected + DOM), SQL injection, NoSQL injection, SSTI, XXE, LDAP |
| **Cookies** | Secure, HttpOnly, SameSite flags, expiry |
| **Exposed Files** | `.env`, `.git`, backup files, config files, SSH keys, phpinfo |
| **HTTP Methods** | TRACE, PUT, DELETE, CONNECT detection |
| **Authentication** | Admin panel exposure, JWT analysis, default credentials, HTTP Basic Auth |
| **DNS & Email** | SPF, DKIM, DMARC, CAA records |
| **Performance** | Response time, page size, compression, caching, render-blocking scripts |
| **SEO** | Title, meta description, H1, canonical, Open Graph, sitemap, robots.txt |
| **Privacy / GDPR** | Cookie consent, privacy policy, third-party trackers, data transfers |
| **Accessibility** | WCAG 2.1 — lang attribute, ARIA labels, skip links, tab order |
| **Supply Chain** | Subresource Integrity (SRI), outdated libraries, GTM consent |
| **API Security** | GraphQL introspection, unauthenticated endpoints, Swagger exposure |
| **Infrastructure** | HTTP→HTTPS redirect, dev subdomains, DNSSEC |
| **Rate Limiting** | Burst detection, payload size limits |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/codebytaki/webvulnscan.git
cd webvulnscan

# 2. Install
npm install

# 3. Run
npm start
# → http://localhost:3000
```

Node.js 18+ required. No API keys needed for the scanner.

---

## Optional: Save Scan History (Supabase)

The scanner works fully without an account. To enable login and scan history:

1. Create a free project at [supabase.com](https://supabase.com)
2. Run the SQL in `supabase-schema.sql` in your Supabase SQL editor
3. Open `public/supabase-client.js` and paste your project URL and anon key

```js
const SUPABASE_URL  = 'https://your-project.supabase.co';
const SUPABASE_ANON = 'your-anon-public-key';
```

> Use the **anon/public** key only — never the service role key.

---

## Project Structure

```
webvulnscan/
├── server.js              # Express backend — all 150+ scan checks
├── supabase-schema.sql    # DB schema + RLS policies (optional)
├── public/
│   ├── index.html         # Landing page with inline scanner
│   ├── scan.html          # Full-page scan results view
│   ├── dashboard.html     # Scan history dashboard
│   ├── login.html         # Auth page
│   ├── app.js             # Frontend scan logic & result rendering
│   ├── dashboard.js       # Dashboard data loading
│   ├── supabase-client.js # Supabase SDK init (configure here)
│   └── shared.css         # Global styles
└── package.json
```

---

## How Scoring Works

Each check produces a `passed` / `failed` result with a severity weight:

| Severity | Weight |
|---|---|
| Critical | 15 |
| High | 8 |
| Medium | 3 |
| Low | 1 |

The final score (0–100) penalises failed checks proportionally. A perfect site scores 100.

---

## Deploying

Works on any platform that runs Node.js:

```bash
# Railway / Render / Fly.io
npm start

# Docker
docker run -p 3000:3000 node:18-alpine sh -c "npm install && npm start"
```

Set `PORT` environment variable to change the default port (3000).

---

## Contributing

Pull requests are welcome. To add a new check:

1. Add a function `checkMyThing(urlStr, body, headers)` that returns an array of result objects
2. Call it inside the `Promise.all` in `/api/scan`
3. Spread the results into `allChecks`

Each result object shape:
```js
{
  passed: false,
  severity: 'high',        // critical | high | medium | low
  cat: 'Security',
  title: 'Short check name',
  description: 'What the issue means and why it matters.',
  fix: '// Optional code snippet showing the fix'
}
```

---

## License

MIT — free to use, modify, and deploy.
