<div align="center">

# 🔐 WebVulnScan

### 150+ Automated Security, SEO & Performance Checks

[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=17&pause=1200&color=58A6FF&center=true&vCenter=true&width=700&lines=SSL+%2F+TLS+%E2%80%A2+Security+Headers+%E2%80%A2+Injections;XSS+%E2%80%A2+SQLi+%E2%80%A2+NoSQL+%E2%80%A2+SSTI+%E2%80%A2+XXE;CORS+%E2%80%A2+Cookies+%E2%80%A2+Auth+%E2%80%A2+CSRF;SEO+%E2%80%A2+Performance+%E2%80%A2+Privacy+%E2%80%A2+WCAG;Scan+any+URL+in+seconds+%E2%80%94+no+signup+needed+%F0%9F%9A%80)](https://git.io/typing-svg)

<br/>

![Node.js](https://img.shields.io/badge/Node.js-18%2B-3C873A?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.x-000000?style=for-the-badge&logo=express&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-58a6ff?style=for-the-badge)
![Checks](https://img.shields.io/badge/Checks-150%2B-1f6feb?style=for-the-badge)
![Zero Signup](https://img.shields.io/badge/Zero%20Signup-Required-2ea043?style=for-the-badge)

</div>

---

## 🖼️ Preview

<div align="center">

**Sample scan output for a typical site:**

</div>

```
┌─────────────────────────────────────────────────────────┐
│  🔐 WebVulnScan — https://example.com                   │
│  Score: 74 / 100   ●  38 checks  ●  312ms               │
├──────────┬──────────┬──────────┬──────────┐             │
│ Critical │   High   │  Medium  │   Low    │             │
│    0     │    5     │    7     │    4     │             │
└──────────┴──────────┴──────────┴──────────┘             │
│                                                          │
│  ✗ HIGH    Missing Content-Security-Policy               │
│  ✗ HIGH    Missing HSTS Header                           │
│  ✗ HIGH    Missing X-Frame-Options                       │
│  ✗ MEDIUM  Missing X-Content-Type-Options                │
│  ✗ MEDIUM  robots.txt Missing                            │
│  ✗ MEDIUM  No Rate Limiting Detected                     │
│  ✓ LOW     SSL Certificate Valid (365 days)              │
│  ✓ LOW     TLS 1.3 Active                                │
│  ✓ LOW     Compression Enabled (br)                      │
│  ✓ LOW     CORS: Restrictive (Good)                      │
└─────────────────────────────────────────────────────────┘
```

<div align="center">

![SSL](https://img.shields.io/badge/%F0%9F%94%92%20SSL-Valid%20%E2%9C%93-2ea043?style=flat-square)
![TLS](https://img.shields.io/badge/TLS%201.3-Active%20%E2%9C%93-2ea043?style=flat-square)
![CSP](https://img.shields.io/badge/CSP-Missing%20%E2%9C%97-d73a49?style=flat-square)
![HSTS](https://img.shields.io/badge/HSTS-Missing%20%E2%9C%97-d73a49?style=flat-square)
![CORS](https://img.shields.io/badge/CORS-Restrictive%20%E2%9C%93-2ea043?style=flat-square)
![Rate](https://img.shields.io/badge/Rate%20Limit-Not%20Detected%20%E2%9C%97-e36209?style=flat-square)
![Compression](https://img.shields.io/badge/Compression-Enabled%20%E2%9C%93-2ea043?style=flat-square)
![Sitemap](https://img.shields.io/badge/Sitemap-Missing%20%E2%9C%97-d73a49?style=flat-square)

</div>

---

## ⚡ What It Scans

<div align="center">

| Category | Checks | What It Catches |
|:---:|:---:|:---|
| 🔒 **SSL / TLS** | 6 | Certificate expiry, weak ciphers, TLS version |
| 🛡️ **Security Headers** | 11 | CSP, HSTS, X-Frame, CORS, Referrer-Policy |
| 💉 **Injection** | 15 | XSS, SQLi, NoSQL, SSTI, XXE, LDAP, Command |
| 🍪 **Cookies** | 7 | Secure, HttpOnly, SameSite, expiry |
| 📁 **Exposed Files** | 25 | `.env`, `.git`, backups, SSH keys, phpinfo |
| 🔑 **Authentication** | 10 | Admin panels, JWT issues, default creds |
| 🌐 **DNS & Email** | 10 | SPF, DKIM, DMARC, CAA records |
| 🚀 **Performance** | 10 | Response time, compression, caching, CDN |
| 🔍 **SEO** | 13 | Title, meta, canonical, OG tags, sitemap |
| 🔐 **Privacy / GDPR** | 8 | Cookie consent, trackers, privacy policy |
| ♿ **Accessibility** | 10 | WCAG 2.1, ARIA, tab order, skip links |
| 🔗 **Supply Chain** | 5 | SRI hashes, outdated libraries, GTM |
| 📊 **API Security** | 5 | GraphQL, unauth endpoints, Swagger |
| 🏗️ **Infrastructure** | 5 | HTTP redirect, dev subdomains, DNSSEC |
| ⏱️ **Rate Limiting** | 4 | Burst detection, payload size |

</div>

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/codebytaki/webvulnscan.git
cd webvulnscan

# Install
npm install

# Run
npm start
```

Open **http://localhost:3000** — paste any URL and hit scan. That's it.

> **Node.js 18+** required. No API keys. No accounts. Fully offline-capable.

---

## 🖥️ API Usage

Scan programmatically via the REST endpoint:

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://yoursite.com"}'
```

**Response shape:**
```json
{
  "score": 74,
  "totalChecks": 38,
  "passedChecks": 22,
  "failedChecks": 16,
  "severityCounts": { "critical": 0, "high": 5, "medium": 7, "low": 4 },
  "issues": [
    {
      "passed": false,
      "severity": "high",
      "cat": "Headers",
      "title": "Missing Content-Security-Policy",
      "description": "No CSP header...",
      "fix": "res.setHeader('Content-Security-Policy', ...)"
    }
  ],
  "responseTime": 312,
  "pageSize": 14820
}
```

---

## 💾 Optional: Save History with Supabase

The scanner is fully functional without an account. To enable login + scan history:

1. Create a free project at [supabase.com](https://supabase.com)
2. Run `supabase-schema.sql` in your Supabase SQL editor
3. Edit `public/supabase-client.js`:

```js
const SUPABASE_URL  = 'https://your-project.supabase.co';
const SUPABASE_ANON = 'your-anon-public-key';   // public key only — never service role
```

Row Level Security is enforced — users only ever see their own scans.

---

## 📁 Project Structure

```
webvulnscan/
├── server.js              ← All 150+ scan checks (Node.js / Express)
├── supabase-schema.sql    ← DB schema + RLS (optional)
├── photos/                ← Screenshots for this README
├── public/
│   ├── index.html         ← Landing page + inline scanner modal
│   ├── scan.html          ← Full-page results view
│   ├── dashboard.html     ← Scan history (requires Supabase)
│   ├── login.html         ← Auth page
│   ├── app.js             ← Frontend logic + result rendering
│   ├── dashboard.js       ← Dashboard data loader
│   ├── supabase-client.js ← Configure your Supabase keys here
│   └── shared.css         ← Global dark theme styles
└── package.json
```

---

## 📐 How Scoring Works

Each check returns `passed: true/false` with a severity weight:

| Severity | Weight | Example |
|:---:|:---:|:---|
| 🔴 Critical | 15 | SQL injection confirmed |
| 🟠 High | 8 | Missing CSP header |
| 🟡 Medium | 3 | Missing canonical tag |
| 🔵 Low | 1 | Missing Twitter card |

`score = 100 − (total_penalty / max_possible_penalty × 100)`

A perfect site scores **100**. Real-world sites typically score 40–75.

---

## 🤝 Adding a New Check

```js
// 1. Write your check function
async function checkMyThing(urlStr, body, headers) {
  const r = [];
  // ... your logic
  r.push({
    passed: false,
    severity: 'high',          // critical | high | medium | low
    cat: 'Security',
    title: 'Short check name',
    description: 'What it means and why it matters.',
    fix: '// Optional code snippet'
  });
  return r;
}

// 2. Add to the Promise.all in /api/scan
// 3. Spread into allChecks
```

PRs are welcome.

---

## 🚢 Deploy

```bash
# Any Node.js host (Railway, Render, Fly.io, VPS)
PORT=8080 npm start

# Docker one-liner
docker run -p 3000:3000 -v $(pwd):/app -w /app node:18-alpine npm start
```

---

## 👤 Author

Built by **[MD Taki](https://github.com/codebytaki)** — Security Researcher · AI Developer · Bug Hunter

[![GitHub](https://img.shields.io/badge/GitHub-codebytaki-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/codebytaki)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Hunter-critical?style=for-the-badge&logo=bugcrowd&logoColor=white)](https://github.com/codebytaki/bug-hunter-toolkit)

---

## 📄 License

MIT — free to use, modify, fork, and deploy.

<div align="center">

---

*Built by [MD Taki](https://github.com/codebytaki) — Security Researcher · AI Developer · Bug Hunter*

</div>
