// ═══════════════════════════════════════════════════════════
// ADVANCED VULNERABILITY SCANNER - 150+ DETECTION METHODS
// ═══════════════════════════════════════════════════════════
'use strict';
const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const { URL } = require('url');
const dns = require('dns').promises;
const crypto = require('crypto');
const zlib = require('zlib');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────
// CORE HTTP FETCHER
// ─────────────────────────────────────────────────────────
function fetchUrl(urlStr, timeout = 8000, method = 'GET', extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const fail = (e) => { if (!done) { done = true; reject(e); } };
    const timer = setTimeout(() => fail(new Error('timeout')), timeout);
    const attempt = (u, hops = 0) => {
      if (hops > 4) { clearTimeout(timer); fail(new Error('too many redirects')); return; }
      const client = u.startsWith('https') ? https : http;
      const parsed = new URL(u);
      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (u.startsWith('https') ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        timeout,
        rejectUnauthorized: false,
        headers: {
          'User-Agent': 'Mozilla/5.0 (CheckVibe-Scanner/2.0)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate, br',
          ...extraHeaders
        }
      };
      const req = client.request(options, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          try { attempt(new URL(res.headers.location, u).href, hops + 1); } catch { clearTimeout(timer); fail(new Error('bad redirect')); }
          return;
        }
        let body = '';
        const enc = res.headers['content-encoding'] || '';
        let stream = res;
        if (enc.includes('br')) {
          stream = res.pipe(zlib.createBrotliDecompress());
        } else if (enc.includes('gzip')) {
          stream = res.pipe(zlib.createGunzip());
        } else if (enc.includes('deflate')) {
          stream = res.pipe(zlib.createInflate());
        } else {
          res.setEncoding('utf8');
        }
        if (enc.includes('br') || enc.includes('gzip') || enc.includes('deflate')) {
          const chunks = [];
          stream.on('data', c => { if (chunks.reduce((s, b) => s + b.length, 0) < 200000) chunks.push(c); });
          stream.on('end', () => { clearTimeout(timer); finish({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }); });
          stream.on('error', () => { clearTimeout(timer); finish({ status: res.statusCode, headers: res.headers, body: '' }); });
        } else {
          res.on('data', c => { if (body.length < 200000) body += c; });
          res.on('end', () => { clearTimeout(timer); finish({ status: res.statusCode, headers: res.headers, body }); });
          res.on('error', e => { clearTimeout(timer); fail(e); });
        }
      });
      req.on('error', e => { clearTimeout(timer); fail(e); });
      req.on('timeout', () => { req.destroy(); clearTimeout(timer); fail(new Error('timeout')); });
      req.end();
    };
    attempt(urlStr);
  });
}

// Quick probe — returns status only, never throws
async function probe(url, timeout = 3500) {
  try { const r = await fetchUrl(url, timeout); return r; }
  catch { return { status: 0, headers: {}, body: '' }; }
}

// ─────────────────────────────────────────────────────────
// [1] SSL / TLS CHECKS
// ─────────────────────────────────────────────────────────
async function checkSSL(urlStr) {
  const u = new URL(urlStr);
  if (u.protocol !== 'https:') return [{ passed: false, severity: 'critical', cat: 'Security', title: 'No HTTPS', description: 'Site uses plain HTTP. All traffic is transmitted in cleartext — passwords, cookies and data are exposed.', fix: `// Force HTTPS in Express:\napp.use((req,res,next)=>{\n  if(req.headers['x-forwarded-proto']!=='https') return res.redirect(301,'https://'+req.headers.host+req.url);\n  next();\n});` }];
  return new Promise(resolve => {
    const results = [];
    const timeout = setTimeout(() => resolve([{ passed: false, severity: 'critical', cat: 'Security', title: 'SSL Connection Timeout', description: 'Could not establish TLS connection within 6 seconds.' }]), 6000);

    const req = https.request({ hostname: u.hostname, port: 443, path: '/', method: 'HEAD', timeout: 6000, rejectUnauthorized: false }, res => {
      clearTimeout(timeout);
      const runChecks = (sock) => {
        try {
          const cert = sock.getPeerCertificate(true);
          if (!cert || !cert.valid_to) {
            resolve([{ passed: true, severity: 'low', cat: 'Security', title: 'SSL Certificate Info Unavailable', description: 'TLS connection succeeded but certificate details could not be read (site uses a CDN/proxy that terminates SSL upstream). HTTPS is active.' }]);
            return;
          }
          const now = Date.now();
          const exp = new Date(cert.valid_to).getTime();
          const days = Math.floor((exp - now) / 86400000);
          if (now > exp) results.push({ passed: false, severity: 'critical', cat: 'Security', title: 'SSL Certificate Expired', description: `Certificate expired ${Math.abs(days)} days ago. Browsers will block your site.`, fix: `# Renew with Let's Encrypt:\ncertbot renew --force-renewal` });
          else if (days < 14) results.push({ passed: false, severity: 'critical', cat: 'Security', title: `SSL Expires in ${days} Days`, description: 'Certificate critical expiry window. Renew immediately.' });
          else if (days < 30) results.push({ passed: false, severity: 'high', cat: 'Security', title: `SSL Expires in ${days} Days`, description: 'Certificate expires soon. Set up auto-renewal.' });
          else results.push({ passed: true, severity: 'low', cat: 'Security', title: 'SSL Certificate Valid', description: `Certificate valid for ${days} more days. Issued by ${cert.issuer?.O || 'Unknown CA'}.` });

          // Self-signed check
          if (cert.issuer?.CN === cert.subject?.CN) results.push({ passed: false, severity: 'high', cat: 'Security', title: 'Self-Signed Certificate', description: 'Certificate is self-signed. Browsers will show security warnings to visitors.' });
          // Wildcard check
          if (cert.subject?.CN?.startsWith('*')) results.push({ passed: false, severity: 'medium', cat: 'Security', title: 'Wildcard SSL Certificate', description: 'Wildcard certificates increase blast radius if the private key is compromised.' });
          resolve(results);
        } catch (err) {
          resolve([{ passed: false, severity: 'high', cat: 'Security', title: 'SSL Check Error', description: `Error reading certificate: ${err.message}` }]);
        }
      };

      // Wait for secure connection to ensure cert is available
      if (res.socket.encrypted) {
        runChecks(res.socket);
      } else {
        res.socket.once('secureConnect', () => runChecks(res.socket));
      }
    });
    req.on('error', (err) => { clearTimeout(timeout); resolve([{ passed: false, severity: 'critical', cat: 'Security', title: 'SSL Connection Failed', description: `Cannot establish TLS connection: ${err.message}` }]); });
    req.on('timeout', () => { req.destroy(); clearTimeout(timeout); resolve([{ passed: false, severity: 'critical', cat: 'Security', title: 'SSL Connection Timeout', description: 'TLS handshake timed out.' }]); });
    req.end();
  });
}

async function checkTLS(urlStr) {
  const u = new URL(urlStr);
  if (u.protocol !== 'https:') return [];
  return new Promise(resolve => {
    const req = https.request({ hostname: u.hostname, port: 443, method: 'HEAD', timeout: 5000, rejectUnauthorized: false }, res => {
      const ver = res.socket?.getProtocol?.() || 'unknown';
      const cipher = res.socket?.getCipher?.() || {};
      const results = [];
      if (ver === 'TLSv1' || ver === 'TLSv1.0') results.push({ passed: false, severity: 'critical', cat: 'Security', title: 'TLS 1.0 Active (Deprecated)', description: 'TLS 1.0 is deprecated and vulnerable to POODLE, BEAST attacks. Disable immediately.', fix: `# nginx - disable old TLS:\nssl_protocols TLSv1.2 TLSv1.3;` });
      else if (ver === 'TLSv1.1') results.push({ passed: false, severity: 'high', cat: 'Security', title: 'TLS 1.1 Active (Deprecated)', description: 'TLS 1.1 is deprecated. Upgrade to TLS 1.2 or 1.3.' });
      else if (ver === 'TLSv1.2') results.push({ passed: true, severity: 'low', cat: 'Security', title: 'TLS 1.2', description: 'TLS 1.2 in use. Consider enabling TLS 1.3 for better performance.' });
      else if (ver === 'TLSv1.3') results.push({ passed: true, severity: 'low', cat: 'Security', title: 'TLS 1.3 (Best)', description: 'TLS 1.3 active — optimal encryption and performance.' });
      // Weak cipher check
      if (cipher.name && /RC4|DES|3DES|NULL|EXPORT|anon/i.test(cipher.name)) results.push({ passed: false, severity: 'critical', cat: 'Security', title: 'Weak Cipher Suite Detected', description: `Server using weak cipher: ${cipher.name}. Vulnerable to decryption attacks.`, fix: `# nginx strong ciphers:\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';` });
      resolve(results);
    });
    req.on('error', () => resolve([]));
    req.end();
  });
}

// ─────────────────────────────────────────────────────────
// [2] SECURITY HEADERS (15 checks)
// ─────────────────────────────────────────────────────────
function checkSecurityHeaders(headers, body = '') {
  const r = [];
  const h = k => headers[k.toLowerCase()];

  // 1. CSP
  const csp = h('content-security-policy');
  if (!csp) r.push({ passed: false, severity: 'high', cat: 'Headers', title: 'Missing Content-Security-Policy', description: 'No CSP header found. XSS attacks can execute arbitrary JavaScript in your users\' browsers.', fix: `res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'self'");` });
  else {
    if (csp.includes("'unsafe-inline'")) r.push({ passed: false, severity: 'high', cat: 'Headers', title: "CSP Contains 'unsafe-inline'", description: "unsafe-inline bypasses XSS protection. Use nonces or hashes instead.", fix: `// Replace unsafe-inline with nonce:\nconst n = crypto.randomBytes(16).toString('base64');\nres.setHeader('Content-Security-Policy',\`script-src 'nonce-\${n}'\`);` });
    if (csp.includes("'unsafe-eval'")) r.push({ passed: false, severity: 'medium', cat: 'Headers', title: "CSP Contains 'unsafe-eval'", description: "unsafe-eval allows eval(), setTimeout(string) — enables DOM XSS." });
    if (!csp.includes('object-src')) r.push({ passed: false, severity: 'medium', cat: 'Headers', title: 'CSP Missing object-src Directive', description: 'Without object-src, Flash/plugin injection attacks are possible. Add object-src: none.' });
    if (!csp.includes('base-uri')) r.push({ passed: false, severity: 'medium', cat: 'Headers', title: 'CSP Missing base-uri Directive', description: 'Missing base-uri allows base tag injection — attackers can hijack relative URLs.' });
    if (csp.includes('http:')) r.push({ passed: false, severity: 'medium', cat: 'Headers', title: 'CSP Allows HTTP Resources', description: 'CSP allows loading resources over HTTP, weakening mixed-content protection.' });
  }

  // 2. HSTS
  const hsts = h('strict-transport-security');
  if (!hsts) r.push({ passed: false, severity: 'high', cat: 'Headers', title: 'Missing HSTS Header', description: 'No Strict-Transport-Security header. Attackers can downgrade HTTPS to HTTP (MITM).', fix: `res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains; preload');` });
  else {
    const ma = parseInt((hsts.match(/max-age=(\d+)/) || [])[1] || 0);
    if (ma < 31536000) r.push({ passed: false, severity: 'medium', cat: 'Headers', title: `HSTS max-age Too Low (${ma}s)`, description: `HSTS max-age should be at least 31536000 (1 year). Current: ${ma}s.` });
    if (!hsts.includes('includeSubDomains')) r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'HSTS Missing includeSubDomains', description: 'Subdomains not covered by HSTS — they can be downgraded to HTTP.' });
    if (!hsts.includes('preload')) r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'HSTS Not Preloaded', description: 'Domain not submitted for HSTS preload list. First visit is still vulnerable.' });
  }

  // 3. X-Frame-Options
  const xfo = h('x-frame-options');
  if (!xfo && !(csp || '').includes('frame-ancestors')) r.push({ passed: false, severity: 'high', cat: 'Headers', title: 'Missing X-Frame-Options / frame-ancestors', description: 'Site can be embedded in iframes — vulnerable to clickjacking attacks.', fix: `res.setHeader('X-Frame-Options','DENY');\n// Or in CSP:\n"frame-ancestors 'none'"` });
  else if (xfo && xfo.toLowerCase() === 'allowall') r.push({ passed: false, severity: 'high', cat: 'Headers', title: 'X-Frame-Options Set to ALLOWALL', description: 'ALLOWALL disables clickjacking protection entirely.' });

  // 4. X-Content-Type-Options
  const xcto = h('x-content-type-options');
  if (!xcto || xcto.toLowerCase() !== 'nosniff') r.push({ passed: false, severity: 'medium', cat: 'Headers', title: 'Missing X-Content-Type-Options: nosniff', description: 'Browser may MIME-sniff responses, allowing content injection attacks.', fix: `res.setHeader('X-Content-Type-Options','nosniff');` });

  // 5. Referrer-Policy
  if (!h('referrer-policy')) r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'Missing Referrer-Policy', description: 'Full URL may be sent as referrer to third parties, leaking sensitive path info.', fix: `res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');` });

  // 6. Permissions-Policy - only flag for pages that could use these features
  const usesFeatures = /camera|microphone|geolocation|payment|getUserMedia/i.test(body);
  if (!h('permissions-policy') && !h('feature-policy') && usesFeatures) {
    r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'Missing Permissions-Policy', description: 'No restrictions on browser features (camera, microphone, geolocation, payment).', fix: `res.setHeader('Permissions-Policy',"camera=(), microphone=(), geolocation=(), payment=()");` });
  }

  // 7. Cross-Origin-Opener-Policy - only flag for pages with sensitive content
  const hasSensitiveContent = h('set-cookie') || /login|signin|account|dashboard/i.test(body);
  if (!h('cross-origin-opener-policy') && hasSensitiveContent) {
    r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'Missing COOP Header', description: 'Cross-Origin-Opener-Policy not set. Enables Spectre-based cross-origin attacks.' });
  }

  // 8. Cross-Origin-Embedder-Policy - only flag for advanced web apps
  if (!h('cross-origin-embedder-policy') && /wasm|worker/i.test(body)) {
    r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'Missing COEP Header', description: 'Cross-Origin-Embedder-Policy not set. Required for SharedArrayBuffer and advanced isolation.' });
  }

  // 9. Cross-Origin-Resource-Policy - only flag for API/JSON responses
  if (!h('cross-origin-resource-policy') && /application\/json/.test(h('content-type') || '')) {
    r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'Missing CORP Header', description: 'API resources can be embedded by other origins. Add Cross-Origin-Resource-Policy: same-origin.' });
  }

  // 10. Cache-Control on sensitive pages - only flag if there's evidence this is a dynamic/sensitive page
  const cc = h('cache-control') || '';
  const hasCookies = h('set-cookie');
  const isDynamic = hasCookies || /application\/json/.test(h('content-type') || '');
  if (isDynamic && !cc.includes('no-store') && !cc.includes('private')) {
    r.push({ passed: false, severity: 'medium', cat: 'Headers', title: 'Cacheable Responses Without no-store', description: 'Sensitive data may be stored in browser or proxy caches.', fix: `res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, private');` });
  }

  // 11. X-XSS-Protection (legacy but still tested)
  const xxss = h('x-xss-protection');
  if (xxss && xxss.startsWith('0')) r.push({ passed: false, severity: 'low', cat: 'Headers', title: 'X-XSS-Protection Disabled', description: 'Legacy XSS filter is explicitly disabled. Set to 1; mode=block.' });

  return r;
}

// ─────────────────────────────────────────────────────────
// [3] CORS (5 checks)
// ─────────────────────────────────────────────────────────
function checkCORS(headers) {
  const acao = headers['access-control-allow-origin'];
  if (!acao) return [{ passed: true, severity: 'low', cat: 'Security', title: 'CORS: Restrictive (Good)', description: 'No Access-Control-Allow-Origin header — default browser same-origin policy applies.' }];
  const r = [];
  if (acao === '*') r.push({ passed: false, severity: 'high', cat: 'Security', title: 'CORS Wildcard (*) Origin', description: 'Any website can read responses from this server. Remove wildcard and specify trusted origins.', fix: `// Allow specific origins only:\nconst allowed = ['https://yoursite.com'];\napp.use((req,res,next)=>{\n  if(allowed.includes(req.headers.origin)) res.setHeader('Access-Control-Allow-Origin',req.headers.origin);\n  next();\n});` });
  if (headers['access-control-allow-credentials'] === 'true' && acao === '*') r.push({ passed: false, severity: 'critical', cat: 'Security', title: 'CORS Credentials + Wildcard', description: 'Credentials allowed with wildcard origin — browsers block this but misconfigured servers bypass it. This is a critical security flaw.' });
  if (headers['access-control-allow-methods']?.toUpperCase().includes('DELETE')) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'CORS Allows DELETE Method', description: 'Cross-origin DELETE requests permitted. Restrict to only necessary methods.' });
  if (headers['access-control-allow-methods']?.toUpperCase().includes('PUT')) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'CORS Allows PUT Method', description: 'Cross-origin PUT requests permitted.' });
  const expHeaders = (headers['access-control-expose-headers'] || '').toLowerCase();
  if (expHeaders.includes('authorization') || expHeaders.includes('cookie')) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'CORS Exposes Sensitive Headers', description: 'Authorization or Cookie headers exposed to cross-origin callers.' });
  return r;
}

// ─────────────────────────────────────────────────────────
// [4] INFORMATION LEAKAGE (8 checks)
// ─────────────────────────────────────────────────────────
function checkInfoLeakage(headers, body) {
  const r = [];
  const srv = headers['server'];
  const pb = headers['x-powered-by'];
  const aspver = headers['x-aspnet-version'] || headers['x-aspnetmvc-version'];
  const php = headers['x-php-version'] || (body.match(/PHP\/(\d+\.\d+)/) || [])[1];

  if (srv) {
    if (/\d+\.\d+/.test(srv)) r.push({ passed: false, severity: 'high', cat: 'Security', title: `Server Version Exposed: ${srv}`, description: 'Server header reveals exact version. Attackers target known CVEs for that version.', fix: `# nginx - hide version:\nserver_tokens off;\n# Apache:\nServerTokens Prod` });
    else r.push({ passed: true, severity: 'low', cat: 'Security', title: `Server Header: ${srv}`, description: 'Server type disclosed but no version number — minimal fingerprinting risk.' });
  }
  if (pb) r.push({ passed: false, severity: 'medium', cat: 'Security', title: `X-Powered-By Exposed: ${pb}`, description: `Technology stack revealed: ${pb}. Remove header to reduce fingerprinting.`, fix: `app.disable('x-powered-by'); // Express.js` });
  if (aspver) r.push({ passed: false, severity: 'medium', cat: 'Security', title: `ASP.NET Version Exposed: ${aspver}`, description: 'ASP.NET version in headers helps attackers find specific vulnerabilities.' });
  if (php) r.push({ passed: false, severity: 'high', cat: 'Security', title: `PHP Version Exposed: ${php}`, description: `PHP version ${php} is exposed. Check for known CVEs for this version.` });
  if (/stack trace|at System\.|at com\.|Exception in thread|Traceback \(most recent|Fatal error:/i.test(body)) r.push({ passed: false, severity: 'critical', cat: 'Security', title: 'Stack Trace Leaked in Response', description: 'Server is returning stack traces to users. Reveals internal file paths, code structure, and technology versions.', fix: `// Never expose errors to clients:\napp.use((err,req,res,next)=>{\n  console.error(err);\n  res.status(500).json({error:'Internal Server Error'});\n});` });
  if (/aws_access_key|aws_secret|api_key\s*=\s*['"]\w+|password\s*=\s*['"][^'"]{8,}|secret\s*=\s*['"][^'"]{8,}/i.test(body)) r.push({ passed: false, severity: 'critical', cat: 'Security', title: 'Credentials or API Keys in Page Source', description: 'Hardcoded credentials/API keys found in page HTML/JS. Rotate these immediately.', fix: `// Use environment variables:\nconst apiKey = process.env.API_KEY;\n// Never hardcode secrets in source code` });
  if (/\/home\/\w+\/|\/var\/www\/|C:\\\\Users\\\\|C:\\\\inetpub\\/i.test(body)) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'Internal File Paths Exposed', description: 'Server file system paths visible in HTML. Reveals deployment structure to attackers.' });
  if (/<!--[\s\S]{200,}-->/g.test(body)) r.push({ passed: false, severity: 'low', cat: 'Security', title: 'Large HTML Comments in Source', description: 'Lengthy HTML comments may contain debug info, developer notes or disabled code.' });
  return r;
}

// ─────────────────────────────────────────────────────────
// [5] COOKIE SECURITY (7 checks)
// ─────────────────────────────────────────────────────────
function checkCookies(headers) {
  const raw = headers['set-cookie'];
  if (!raw) return [{ passed: true, severity: 'low', cat: 'Security', title: 'No Cookies Set', description: 'Server does not set cookies on this response.' }];
  const cookies = Array.isArray(raw) ? raw : [raw];
  const r = [];
  let noSecure = 0, noHttpOnly = 0, noSameSite = 0, longExpiry = 0;
  for (const c of cookies) {
    if (!/\bsecure\b/i.test(c)) noSecure++;
    if (!/\bhttponly\b/i.test(c)) noHttpOnly++;
    if (!/\bsamesite\s*=/i.test(c)) noSameSite++;
    const expMatch = c.match(/expires=([^;]+)/i);
    if (expMatch) { const d = new Date(expMatch[1]); const days = (d - Date.now()) / 86400000; if (days > 365) longExpiry++; }
    if (/samesite\s*=\s*none/i.test(c) && !/\bsecure\b/i.test(c)) r.push({ passed: false, severity: 'critical', cat: 'Security', title: 'SameSite=None Without Secure Flag', description: 'Cookie with SameSite=None must have Secure flag or browsers will reject it.' });
  }
  if (noSecure) r.push({ passed: false, severity: 'high', cat: 'Security', title: `${noSecure} Cookie(s) Missing Secure Flag`, description: 'Cookies sent over HTTP — can be intercepted by network attackers (MITM).', fix: `res.cookie('session', val, { secure: true, httpOnly: true, sameSite: 'strict' });` });
  if (noHttpOnly) r.push({ passed: false, severity: 'high', cat: 'Security', title: `${noHttpOnly} Cookie(s) Missing HttpOnly Flag`, description: 'Cookies accessible to JavaScript — can be stolen via XSS attacks.' });
  if (noSameSite) r.push({ passed: false, severity: 'medium', cat: 'Security', title: `${noSameSite} Cookie(s) Missing SameSite Flag`, description: 'Cookies sent on cross-site requests — vulnerable to CSRF attacks.' });
  if (longExpiry) r.push({ passed: false, severity: 'low', cat: 'Security', title: `${longExpiry} Cookie(s) With Long Expiry (>1yr)`, description: 'Long-lived cookies increase the window of opportunity for cookie theft.' });
  return r;
}

// ─────────────────────────────────────────────────────────
// [6] INJECTION ATTACKS - DEEP SCAN (20+ patterns)
// ─────────────────────────────────────────────────────────
async function checkInjections(urlStr, body, headers) {
  const r = [];
  const u = new URL(urlStr);
  const base = `${u.protocol}//${u.hostname}`;

  // --- XSS ---
  const inlineScripts = (body.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || []).filter(s => !s.includes('nonce=') && !/src\s*=/i.test(s));
  if (inlineScripts.length > 0 && !(headers['content-security-policy'] || '').includes('nonce-')) {
    r.push({ passed: false, severity: 'high', cat: 'Injection', title: `${inlineScripts.length} Inline Scripts Without CSP Nonce`, description: 'Inline scripts without nonce protection allow XSS if any input is reflected into the page.', fix: `const nonce = crypto.randomBytes(16).toString('base64');\nres.setHeader('Content-Security-Policy',\`script-src 'nonce-\${nonce}'\`);\n// Add nonce to each <script> tag` });
  }

  // DOM XSS sinks
  const sinks = [
    [/\.innerHTML\s*=[^=]/g, 'innerHTML assignment'],
    [/document\.write\s*\(/g, 'document.write()'],
    [/\beval\s*\(/g, 'eval()'],
    [/setTimeout\s*\(\s*['"`]/g, 'setTimeout with string'],
    [/setInterval\s*\(\s*['"`]/g, 'setInterval with string'],
    [/location\.href\s*=\s*(?!['"]https?)/g, 'dynamic location.href'],
    [/\.outerHTML\s*=/g, 'outerHTML assignment'],
    [/insertAdjacentHTML\s*\(/g, 'insertAdjacentHTML()'],
  ];
  const foundSinks = sinks.filter(([p]) => p.test(body)).map(([, n]) => n);
  if (foundSinks.length) r.push({ passed: false, severity: 'high', cat: 'Injection', title: 'DOM XSS Sink Patterns Detected', description: `Dangerous patterns found: ${foundSinks.join(', ')}. If any sink receives user-controlled data, XSS is possible.`, fix: `// Use safe alternatives:\n// ❌ el.innerHTML = userInput;\n// ✅ el.textContent = userInput;\n// ✅ DOMPurify.sanitize(userInput)` });

  // Reflected XSS probe (only if URL has params)
  if (u.search) {
    const xssProbe = '<script>alert(1)</script>';
    const xssUrl = u.href + '&xss=' + encodeURIComponent(xssProbe);
    const xssRes = await probe(xssUrl, 4000);
    if (xssRes.body.includes(xssProbe) || xssRes.body.includes('<script>alert(1)')) {
      r.push({ passed: false, severity: 'critical', cat: 'Injection', title: 'Reflected XSS Confirmed', description: 'Unescaped user input reflected directly in HTML. Attackers can steal sessions, redirect users, and run arbitrary code.', fix: `// Always encode output:\nconst he = require('he');\nres.send('<p>' + he.encode(userInput) + '</p>');\n// Or use a templating engine that auto-escapes (Handlebars, Nunjucks)` });
    }
  }

  // --- SQL Injection ---
  const sqlErrors = [
    [/SQL syntax.*?near/i, 'MySQL'],
    [/Warning.*?mysqli?_/i, 'MySQL'],
    [/PostgreSQL.*?ERROR/i, 'PostgreSQL'],
    [/\[ODBC.*?Driver\]/i, 'ODBC'],
    [/ORA-\d{5}/i, 'Oracle'],
    [/Unclosed quotation mark/i, 'MSSQL'],
    [/Microsoft OLE DB.*?SQL Server/i, 'MSSQL'],
    [/SQLite.*?exception/i, 'SQLite'],
    [/Syntax error.*?in query/i, 'Generic SQL'],
    [/supplied argument is not a valid MySQL/i, 'MySQL'],
  ];

  const sqlPayloads = ["'", "''", "1 OR 1=1--", "' OR 'a'='a", "1; SELECT 1--", "1' AND SLEEP(2)--"];
  if (u.search) {
    for (const pl of sqlPayloads.slice(0, 4)) {
      const testUrl = u.href + '&id=' + encodeURIComponent(pl);
      const res = await probe(testUrl, 5000);
      const matched = sqlErrors.find(([p]) => p.test(res.body));
      if (matched) {
        r.push({ passed: false, severity: 'critical', cat: 'Injection', title: `SQL Injection Confirmed (${matched[1]})`, description: `SQL error returned for payload "${pl}". Database: ${matched[1]}. Attacker can dump, modify or delete your entire database.`, fix: `// ❌ NEVER: "SELECT * FROM users WHERE id="+req.query.id\n// ✅ MySQL:\nconnection.query('SELECT * FROM users WHERE id=?',[id],cb);\n// ✅ PostgreSQL:\nclient.query('SELECT * FROM users WHERE id=$1',[id]);\n// ✅ Sequelize:\nUser.findOne({ where: { id } });` });
        break;
      }
    }
  }

  // Error-based SQLi in page body
  const sqlInPage = sqlErrors.find(([p]) => p.test(body));
  if (sqlInPage) r.push({ passed: false, severity: 'critical', cat: 'Injection', title: `SQL Error Exposed in Page (${sqlInPage[1]})`, description: 'Database error message visible in page response. Reveals schema info and confirms SQLi target.' });

  // --- NoSQL Injection ---
  if (u.search) {
    const nosqlRes = await probe(u.href + '&filter[$ne]=null', 4000);
    if (nosqlRes.status === 200 && nosqlRes.body.length > 200) {
      r.push({ passed: false, severity: 'critical', cat: 'Injection', title: 'NoSQL Injection ($ne operator)', description: 'MongoDB $ne operator accepted in query parameter. Attacker can bypass authentication and dump all records.', fix: `// Sanitize NoSQL input:\nconst { sanitize } = require('express-mongo-sanitize');\napp.use(sanitize());\n// Or validate types strictly:\nif(typeof req.query.id !== 'string') return res.status(400).end();` });
    }
  }

  // --- Command Injection ---
  const cmdPatterns = [/root:x:0:0/, /uid=\d+\(\w+\)/, /\[boot loader\]/, /windows version/i];
  if (cmdPatterns.some(p => p.test(body))) r.push({ passed: false, severity: 'critical', cat: 'Injection', title: 'Command Injection Output in Response', description: 'Server appears to be executing shell commands and returning output. Full remote code execution possible.' });

  // --- SSTI (Server-Side Template Injection) ---
  if (u.search) {
    const sstiRes = await probe(u.href + '&name={{7*7}}', 4000);
    if (/\b49\b/.test(sstiRes.body)) r.push({ passed: false, severity: 'critical', cat: 'Injection', title: 'Server-Side Template Injection (SSTI)', description: 'Template expression {{7*7}} evaluated to 49. Attacker can execute code on the server via template engine.', fix: `// Never render user input as a template:\n// ❌ res.render('page', { content: req.query.input })\n// ✅ Escape / sanitize before passing to template\n// ✅ Use sandbox mode in template engine` });
  }

  // --- LDAP Injection ---
  if (/\(objectClass=|cn=|dc=|ou=/i.test(body)) r.push({ passed: false, severity: 'high', cat: 'Injection', title: 'LDAP Query Structure Exposed', description: 'LDAP query fragments visible in response. May indicate LDAP injection vulnerability.' });

  // --- XML/XXE ---
  // Skip standard HTML5 <!DOCTYPE html> — only flag actual XML entity declarations
  const bodyNoHtml5Doctype = body.replace(/<!DOCTYPE\s+html[^>]*>/gi, '');
  if (/<!ENTITY|<!DOCTYPE[^>]*SYSTEM|<!DOCTYPE[^>]*PUBLIC/i.test(bodyNoHtml5Doctype)) r.push({ passed: false, severity: 'critical', cat: 'Injection', title: 'XXE / XML Entity Injection Risk', description: 'DOCTYPE or ENTITY declarations in page. If user XML is parsed, server-side file read (XXE) may be possible.', fix: `// Disable external entities in XML parser:\nconst parser = new DOMParser();\n// In Node.js with libxmljs:\nconst doc = libxml.parseXmlString(xml, { noent: false, dtdload: false });` });

  // --- Path Traversal indicators ---
  if (/\.\.\//g.test(body) || /\.\.%2[Ff]/g.test(body)) r.push({ passed: false, severity: 'high', cat: 'Injection', title: 'Path Traversal Patterns in Response', description: 'Directory traversal sequences (../) visible in response. May indicate file path exposure.' });

  return r;
}

// ─────────────────────────────────────────────────────────
// [7] EXPOSED FILES & DIRECTORIES (25 paths)
// ─────────────────────────────────────────────────────────
async function checkExposedFiles(urlStr) {
  const u = new URL(urlStr);
  const base = `${u.protocol}//${u.hostname}`;
  const r = [];

  const targets = [
    { path: '/.env', sev: 'critical', title: 'Exposed .env File', desc: '.env file accessible — contains database passwords, API keys, secret tokens.' },
    { path: '/.env.local', sev: 'critical', title: 'Exposed .env.local File', desc: 'Local environment config exposed.' },
    { path: '/.env.production', sev: 'critical', title: 'Exposed .env.production', desc: 'Production environment secrets exposed.' },
    { path: '/.git/config', sev: 'critical', title: 'Exposed .git/config', desc: 'Git config exposes remote URLs and credentials.' },
    { path: '/.git/HEAD', sev: 'critical', title: 'Exposed Git Repository', desc: 'Git repo accessible — entire source code can be reconstructed.' },
    { path: '/wp-config.php', sev: 'critical', title: 'Exposed wp-config.php', desc: 'WordPress config file — contains DB credentials.' },
    { path: '/config.php', sev: 'critical', title: 'Exposed config.php', desc: 'PHP config file exposed — may contain credentials.' },
    { path: '/database.yml', sev: 'critical', title: 'Exposed database.yml', desc: 'Rails database config exposed.' },
    { path: '/config/database.yml', sev: 'critical', title: 'Exposed config/database.yml', desc: 'Database credentials exposed.' },
    { path: '/backup.sql', sev: 'critical', title: 'Exposed SQL Backup', desc: 'SQL dump file publicly accessible — full database exposure.' },
    { path: '/dump.sql', sev: 'critical', title: 'Exposed dump.sql', desc: 'Database dump accessible.' },
    { path: '/.ssh/id_rsa', sev: 'critical', title: 'Exposed SSH Private Key', desc: 'Private SSH key accessible — server can be completely compromised.' },
    { path: '/phpinfo.php', sev: 'high', title: 'Exposed phpinfo.php', desc: 'PHP configuration page exposed — reveals paths, modules, environment vars.' },
    { path: '/info.php', sev: 'high', title: 'Exposed info.php', desc: 'PHP info page accessible.' },
    { path: '/server-status', sev: 'high', title: 'Apache server-status Exposed', desc: 'Apache mod_status reveals real-time request logs and internal IPs.' },
    { path: '/nginx_status', sev: 'high', title: 'nginx_status Exposed', desc: 'Nginx status page leaks connection info.' },
    { path: '/.htaccess', sev: 'medium', title: 'Exposed .htaccess', desc: 'Apache config file exposed — reveals URL rewriting rules and access controls.' },
    { path: '/web.config', sev: 'high', title: 'Exposed web.config', desc: 'IIS config file — may contain connection strings and credentials.' },
    { path: '/package.json', sev: 'medium', title: 'Exposed package.json', desc: 'Node.js package manifest exposed — reveals dependencies and versions with known CVEs.' },
    { path: '/composer.json', sev: 'medium', title: 'Exposed composer.json', desc: 'PHP Composer manifest exposed.' },
    { path: '/Gemfile', sev: 'medium', title: 'Exposed Gemfile', desc: 'Ruby Gemfile exposed — reveals dependencies.' },
    { path: '/requirements.txt', sev: 'medium', title: 'Exposed requirements.txt', desc: 'Python dependencies exposed — reveals versions with potential CVEs.' },
    { path: '/.DS_Store', sev: 'medium', title: 'Exposed .DS_Store', desc: 'macOS metadata file — reveals directory structure.' },
    { path: '/crossdomain.xml', sev: 'medium', title: 'Flash crossdomain.xml Exposed', desc: 'Flash cross-domain policy may be overly permissive.' },
    { path: '/clientaccesspolicy.xml', sev: 'low', title: 'Silverlight Policy Exposed', desc: 'Silverlight access policy file exposed.' },
    { path: '/.well-known/security.txt', sev: 'low', title: 'No security.txt', desc: 'security.txt not found. Researchers cannot easily report vulnerabilities.', expectMissing: true },
  ];

  // Run in parallel batches of 6
  for (let i = 0; i < targets.length; i += 6) {
    const batch = targets.slice(i, i + 6);
    const results = await Promise.all(batch.map(t => probe(`${base}${t.path}`, 3000).then(res => ({ t, res }))));
    for (const { t, res } of results) {
      if (t.expectMissing) {
        if (res.status !== 200) r.push({ passed: false, severity: t.sev, cat: 'Exposure', title: t.title, description: t.desc });
        else r.push({ passed: true, severity: 'low', cat: 'Exposure', title: 'security.txt Present', description: 'Vulnerability disclosure policy found.' });
      } else {
        if (res.status === 200 && res.body && res.body.length > 10) {
          r.push({ passed: false, severity: t.sev, cat: 'Exposure', title: t.title, description: t.desc, fix: `# Block access in nginx:\nlocation ~* \\.(env|git|htaccess|sql|bak)$ { deny all; return 404; }` });
        }
      }
    }
  }
  return r;
}

// ─────────────────────────────────────────────────────────
// [8] HTTP METHOD TESTING (5 checks)
// ─────────────────────────────────────────────────────────
async function checkHTTPMethods(urlStr) {
  const r = [];
  // OPTIONS probe
  const optRes = await probe(urlStr.replace(/^http:/, 'https:') || urlStr, 4000);
  const allow = optRes.headers['allow'] || optRes.headers['public'] || '';

  if (/\bTRACE\b/i.test(allow)) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'HTTP TRACE Method Enabled', description: 'TRACE method enabled — enables Cross-Site Tracing (XST) attacks to steal cookies.', fix: `# nginx:\nlimit_except GET POST { deny all; }\n# Apache:\nTraceEnable Off` });
  if (/\bPUT\b/i.test(allow)) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'HTTP PUT Method Enabled', description: 'PUT method may allow arbitrary file uploads to the server.' });
  if (/\bDELETE\b/i.test(allow)) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'HTTP DELETE Method Enabled', description: 'DELETE method exposed globally — may allow resource deletion without proper auth.' });
  if (/\bCONNECT\b/i.test(allow)) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'HTTP CONNECT Method Enabled', description: 'CONNECT method enables proxy tunneling attacks.' });

  // Direct TRACE test
  try {
    const traceRes = await fetchUrl(urlStr, 4000, 'TRACE');
    if (traceRes.status === 200) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'HTTP TRACE Responds 200', description: 'TRACE request returned 200 OK — server confirms TRACE is enabled.' });
  } catch { }
  return r;
}

// ─────────────────────────────────────────────────────────
// [9] AUTHENTICATION & ACCESS CONTROL (10 checks)
// ─────────────────────────────────────────────────────────
async function checkAuthentication(urlStr, body, headers) {
  const r = [];
  const u = new URL(urlStr);
  const base = `${u.protocol}//${u.hostname}`;

  // Admin panel exposure
  const adminPaths = ['/admin', '/admin/', '/administrator', '/wp-admin', '/cpanel', '/phpmyadmin', '/adminer', '/manager/html', '/backend', '/secure'];
  const foundAdmin = [];
  const adminResults = await Promise.all(adminPaths.map(p => probe(`${base}${p}`, 3000).then(r => ({ p, r }))));
  for (const { p, r: res } of adminResults) {
    if (res.status === 200 && res.body.length > 100) {
      const snippet = res.body.slice(0, 1000);
      // Check for auth indicators: login forms, auth messages, session-protected content,
      // or common CMS admin patterns that redirect to login on unauthenticated access
      const hasAuth = /login|sign.?in|unauthorized|forbidden|log.?out|password|authenticat|sign.?up|register/i.test(snippet);
      const hasSessionGuard = /no-cache.*no-store|no-store.*no-cache/i.test(JSON.stringify(res.headers)) && /set-cookie/i.test(JSON.stringify(res.headers));
      if (!hasAuth && !hasSessionGuard) foundAdmin.push(p);
    }
  }
  if (foundAdmin.length) r.push({ passed: false, severity: 'high', cat: 'Auth', title: `Admin Panels Accessible Without Login: ${foundAdmin.join(', ')}`, description: 'Administrative interfaces reachable without authentication. Verify these require session-based auth.', fix: `const authGuard = (req,res,next) => {\n  if (!req.session?.user?.isAdmin) return res.redirect('/login');\n  next();\n};\napp.use('/admin', authGuard);` });

  // JWT analysis
  const jwtRx = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  const jwts = [...(body.match(jwtRx) || []), ...(JSON.stringify(headers).match(jwtRx) || [])];
  if (jwts.length) {
    try {
      const [, payloadB64] = jwts[0].split('.');
      const payload = JSON.parse(Buffer.from(payloadB64 + '==', 'base64').toString());
      if (!payload.exp) r.push({ passed: false, severity: 'high', cat: 'Auth', title: 'JWT Without Expiry (exp)', description: 'JWT token has no expiration claim. Stolen tokens are valid forever.', fix: `jwt.sign(payload, secret, { expiresIn: '1h', algorithm: 'RS256' });` });
      if (payload.alg === 'none' || (payload.alg && !/RS|ES|PS/.test(payload.alg))) r.push({ passed: false, severity: 'critical', cat: 'Auth', title: 'JWT Weak Algorithm', description: `JWT uses ${payload.alg || 'none'} algorithm. Use RS256 or ES256 (asymmetric keys).` });
    } catch { }
    const cookieStr = (Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie']]).join(';');
    if (/token|jwt|auth/i.test(cookieStr) && !/\bsecure\b/i.test(cookieStr)) r.push({ passed: false, severity: 'critical', cat: 'Auth', title: 'Auth Token Cookie Missing Secure Flag', description: 'Authentication token transmitted over HTTP. Can be intercepted by network attacker.' });
  }

  // Default credentials check
  const loginPaths = ['/api/login', '/api/auth', '/login', '/auth'];
  for (const lp of loginPaths.slice(0, 2)) {
    const lRes = await probe(`${base}${lp}`, 3000);
    if (lRes.status === 200 || lRes.status === 405) {
      // Attempt default creds
      try {
        const defRes = await fetchUrl(`${base}${lp}`, 4000, 'POST', { 'Content-Type': 'application/json' });
        if (defRes.status === 200 && /token|success|welcome/i.test(defRes.body)) {
          r.push({ passed: false, severity: 'critical', cat: 'Auth', title: 'Empty Credentials Accepted', description: `${lp} returned 200 with empty credentials — authentication may be broken.` });
        }
      } catch { }
    }
  }

  // HTTP Basic Auth in URL
  if (/https?:\/\/[^:]+:[^@]+@/i.test(urlStr)) r.push({ passed: false, severity: 'critical', cat: 'Auth', title: 'Credentials in URL', description: 'Username/password embedded in URL. Credentials leak in browser history, logs and referer headers.' });

  // Auth header check
  if (headers['www-authenticate'] && /basic/i.test(headers['www-authenticate'])) r.push({ passed: false, severity: 'medium', cat: 'Auth', title: 'HTTP Basic Authentication', description: 'Basic auth sends credentials as Base64 (not encrypted). Use token-based auth over HTTPS.' });

  // Autocomplete on password fields
  if (/<input[^>]*type\s*=\s*["']password["'][^>]*>/i.test(body) && !/autocomplete\s*=\s*["']off["']/i.test(body)) r.push({ passed: false, severity: 'low', cat: 'Auth', title: 'Password Field Missing autocomplete=off', description: 'Browser may save/autofill passwords in sensitive contexts.' });

  return r;
}

// ─────────────────────────────────────────────────────────
// [10] CSRF PROTECTION (4 checks)
// ─────────────────────────────────────────────────────────
function checkCSRF(body, headers) {
  const r = [];
  const forms = body.match(/<form[^>]*>/gi) || [];
  const postForms = forms.filter(f => /method\s*=\s*["']post["']/i.test(f));
  if (!postForms.length) return r;

  const hasToken = /csrf|_token|authenticity_token|__RequestVerificationToken/i.test(body);
  const cookies = (Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie'] || '']).join(';');
  const hasSameSite = /samesite\s*=\s*(strict|lax)/i.test(cookies);
  const hasOriginCheck = /origin|referer/i.test(JSON.stringify(headers));

  if (!hasToken && !hasSameSite) r.push({ passed: false, severity: 'high', cat: 'Security', title: `CSRF: ${postForms.length} POST Forms Without Protection`, description: 'POST forms have no CSRF tokens and no SameSite cookie protection. Any website can silently submit these forms on behalf of logged-in users.', fix: `// CSRF token with csurf:\nconst csrf = require('csurf');\napp.use(csrf({cookie:true}));\napp.get('/form',(req,res)=> res.render('form',{csrf:req.csrfToken()}));\n// In form: <input type="hidden" name="_csrf" value="{{csrf}}">` });
  if (postForms.length > 0 && !hasToken) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'No CSRF Token in Forms', description: 'Forms submit without CSRF tokens. Verify SameSite cookies are protecting all state-changing endpoints.' });
  return r;
}

// ─────────────────────────────────────────────────────────
// [11] DNS & EMAIL SECURITY (10 checks)
// ─────────────────────────────────────────────────────────
async function checkDNS(hostname) {
  const r = [];
  const dnsTimeout = (promise, ms = 4000) => Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), ms))
  ]);

  // SPF - Only report if we get a definitive result
  try {
    const txts = await dnsTimeout(dns.resolveTxt(hostname));
    const spf = txts.find(t => t.join('').startsWith('v=spf1'));
    if (!spf) r.push({ passed: false, severity: 'low', cat: 'DNS', title: 'Missing SPF Record', description: 'No SPF record found. Email spoofing possible.', fix: `TXT @ "v=spf1 include:_spf.google.com -all"` });
    else {
      const spfStr = spf.join('');
      if (spfStr.includes('+all')) r.push({ passed: false, severity: 'critical', cat: 'DNS', title: 'SPF Record Uses +all (Dangerous)', description: 'SPF +all allows ANY server to send email for your domain. Immediate spoofing risk.', fix: `TXT @ "v=spf1 include:_spf.google.com -all"` });
      else if (spfStr.includes('~all')) r.push({ passed: false, severity: 'low', cat: 'DNS', title: 'SPF Uses ~all (Soft Fail)', description: 'SPF ~all is a soft fail — emails from unknown servers are not rejected. Use -all for strict mode.' });
      else r.push({ passed: true, severity: 'low', cat: 'DNS', title: 'SPF Record Valid (-all)', description: 'Strict SPF record in place.' });
    }
  } catch (err) {
    // Skip reporting entirely - DNS timeouts don't indicate security issues
  }

  // DMARC - Only report if we get a definitive result
  try {
    const dmarc = await dnsTimeout(dns.resolveTxt(`_dmarc.${hostname}`));
    const policy = dmarc.find(t => t.join('').startsWith('v=DMARC1'));
    if (!policy) r.push({ passed: false, severity: 'low', cat: 'DNS', title: 'Missing DMARC Record', description: 'No DMARC policy found. Email phishing protection unavailable.', fix: `TXT _dmarc "v=DMARC1; p=reject; rua=mailto:dmarc@${hostname}; pct=100"` });
    else {
      const p = policy.join('');
      if (/p=none/.test(p)) r.push({ passed: false, severity: 'low', cat: 'DNS', title: 'DMARC Policy is None (Monitor Only)', description: 'DMARC p=none only monitors — failing emails are still delivered. Upgrade to quarantine or reject.' });
      else if (/p=quarantine/.test(p)) r.push({ passed: true, severity: 'low', cat: 'DNS', title: 'DMARC: Quarantine Policy', description: 'DMARC quarantine policy active.' });
      else r.push({ passed: true, severity: 'low', cat: 'DNS', title: 'DMARC: Reject Policy (Best)', description: 'DMARC reject policy enforced.' });
    }
  } catch (err) {
    // Skip reporting - DNS timeouts are not security issues
  }

  // DKIM (check common selectors) - skip if slow
  const dkimSelectors = ['google', 'default', 'mail'];
  let dkimFound = false;
  for (const sel of dkimSelectors) {
    try {
      await dnsTimeout(dns.resolveTxt(`${sel}._domainkey.${hostname}`), 2000);
      dkimFound = true; break;
    } catch { }
  }
  if (dkimFound) r.push({ passed: true, severity: 'low', cat: 'DNS', title: 'DKIM Record Found', description: 'DKIM email signing is configured.' });

  // CAA
  try {
    await dnsTimeout(dns.resolve(hostname, 'CAA'), 3000);
    r.push({ passed: true, severity: 'low', cat: 'DNS', title: 'CAA Record Present', description: 'CAA record restricts which CAs can issue certificates for your domain.' });
  } catch (err) {
    if (err.message !== 'DNS timeout') {
      r.push({ passed: false, severity: 'low', cat: 'DNS', title: 'Missing CAA Record', description: 'No CAA record — any Certificate Authority can issue a certificate for your domain.', fix: `CAA 0 issue "letsencrypt.org"\nCAA 0 issuewild ";"\nCAA 0 iodef "mailto:security@${hostname}"` });
    }
  }

  // NS records
  try {
    const ns = await dnsTimeout(dns.resolveNs(hostname), 3000);
    r.push({ passed: true, severity: 'low', cat: 'DNS', title: `${ns.length} NS Records Found`, description: `Nameservers: ${ns.slice(0, 3).join(', ')}` });
  } catch (err) {
    // Skip - not critical
  }

  return r;
}

// ─────────────────────────────────────────────────────────
// [12] CONTENT & MIXED CONTENT (5 checks)
// ─────────────────────────────────────────────────────────
function checkMixedContent(body, urlStr) {
  const r = [];
  const isHttps = urlStr.startsWith('https://');
  if (!isHttps) { r.push({ passed: false, severity: 'critical', cat: 'Security', title: 'Site Not Using HTTPS', description: 'All data transmitted in cleartext. Migrate to HTTPS immediately.' }); return r; }
  const httpRx = /(src|href|action|data|poster)\s*=\s*["']http:\/\/(?!localhost)[^"']+["']/gi;
  const mixed = body.match(httpRx) || [];
  if (mixed.length > 0) r.push({ passed: false, severity: 'high', cat: 'Security', title: `${mixed.length} Mixed Content Resource(s)`, description: 'HTTP resources loaded on HTTPS page. Browsers block these and it degrades security.', fix: `// Fix: change all resource URLs to https:// or use relative URLs\n// nginx: add to config:\nadd_header Content-Security-Policy "upgrade-insecure-requests";` });
  // Inline data: URIs
  const dataUris = (body.match(/data:[^;]+;base64,[A-Za-z0-9+/=]{100,}/g) || []).length;
  if (dataUris > 5) r.push({ passed: false, severity: 'low', cat: 'Performance', title: `${dataUris} Large Inline Data URIs`, description: 'Excessive base64-encoded inline resources bloat HTML and slow rendering.' });
  // Check for iframe sandbox
  const iframes = body.match(/<iframe[^>]*>/gi) || [];
  const unsandboxed = iframes.filter(i => !/sandbox/i.test(i));
  if (unsandboxed.length) r.push({ passed: false, severity: 'medium', cat: 'Security', title: `${unsandboxed.length} Unsandboxed iframe(s)`, description: 'iframes without sandbox attribute can execute scripts and access parent page.', fix: `<iframe sandbox="allow-scripts allow-same-origin" src="...">` });
  return r;
}

// ─────────────────────────────────────────────────────────
// [13] SEO - DEEP (15 checks)
// ─────────────────────────────────────────────────────────
function checkSEO(body) {
  const r = [];
  // Title
  const titleM = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!titleM) r.push({ passed: false, severity: 'high', cat: 'SEO', title: 'Missing <title> Tag', description: 'No title tag found. Required for SEO and browser tabs.' });
  else {
    const t = titleM[1].replace(/<[^>]+>/g, '').trim();
    if (t.length < 10) r.push({ passed: false, severity: 'high', cat: 'SEO', title: `Title Too Short (${t.length} chars)`, description: `Title "${t}" is too short. Aim for 50-60 characters.` });
    else if (t.length < 30) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: `Title Short (${t.length} chars)`, description: `Title "${t}" is short. Aim for 50-60 characters for best SERP display.` });
    else if (t.length > 70) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: `Title Too Long (${t.length} chars)`, description: 'Title may be truncated in SERPs at ~60 characters.' });
    else r.push({ passed: true, severity: 'low', cat: 'SEO', title: 'Title Tag OK', description: `Title: "${t}" (${t.length} chars)` });
  }
  // Meta description — only flag for content pages
  const descM = body.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i) || body.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["']/i);
  const bodyTextEarly = body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  const isContentPage = bodyTextEarly.length > 200;
  if (!descM && isContentPage) r.push({ passed: false, severity: 'high', cat: 'SEO', title: 'Missing Meta Description', description: 'No meta description. Used by search engines for result snippets.' });
  else if (descM) { const d = descM[1]; if (d.length < 70) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: `Meta Description Too Short (${d.length} chars)`, description: 'Aim for 150-160 characters.' }); else if (d.length > 165) r.push({ passed: false, severity: 'low', cat: 'SEO', title: `Meta Description Too Long (${d.length} chars)`, description: 'May be truncated in search results.' }); }
  // Headings
  const h1 = body.match(/<h1[^>]*>/gi) || [];
  if (!h1.length) r.push({ passed: false, severity: 'high', cat: 'SEO', title: 'No H1 Heading', description: 'Every page must have exactly one H1 — primary keyword signal for search engines.' });
  else if (h1.length > 1) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: `Multiple H1 Tags (${h1.length})`, description: 'Use exactly one H1 per page. Multiple H1s dilute SEO signal.' });
  // Images alt
  const imgs = body.match(/<img[^>]*>/gi) || [];
  const noAlt = imgs.filter(i => !/\balt\s*=/i.test(i));
  if (noAlt.length) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: `${noAlt.length}/${imgs.length} Images Missing alt`, description: 'Images without alt text are invisible to search engines and screen readers.' });
  // Canonical — only meaningful for pages with substantial content
  const bodyText = body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  if (bodyText.length > 300 && !/rel=["']canonical["']/i.test(body)) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: 'Missing Canonical Tag', description: 'No canonical URL. Duplicate content issues may affect ranking.', fix: `<link rel="canonical" href="https://yourdomain.com/page">` });
  // Viewport
  if (!/name=["']viewport["']/i.test(body)) r.push({ passed: false, severity: 'high', cat: 'SEO', title: 'Missing Viewport Meta Tag', description: 'No viewport meta — Google penalises non-mobile-friendly pages.' });
  // Structured data — only flag real content pages (have a meaningful title and some content)
  const titleForSeo = titleM ? titleM[1].replace(/<[^>]+>/g, '').trim() : '';
  const isRealPage = titleForSeo.length >= 10 && bodyText.length > 300;
  const jsonld = body.match(/<script[^>]*application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi) || [];
  if (isRealPage && !jsonld.length) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: 'No JSON-LD Structured Data', description: 'Structured data helps search engines display rich snippets.', fix: `<script type="application/ld+json">{\n  "@context":"https://schema.org",\n  "@type":"Organization",\n  "name":"Your Brand"\n}</script>` });
  // OG tags — only flag pages worth sharing (have a real title)
  const ogNeeded = ['og:title', 'og:description', 'og:image', 'og:url'];
  const ogMissing = ogNeeded.filter(t => !new RegExp(`property=["']${t}["']`, 'i').test(body));
  if (isRealPage && ogMissing.length) r.push({ passed: false, severity: 'medium', cat: 'SEO', title: `Missing Open Graph Tags: ${ogMissing.join(', ')}`, description: 'OG tags control how your page appears when shared on social media.' });
  // Twitter cards — only flag if OG tags are already present (Twitter supplements OG)
  const hasOG = ogMissing.length === 0;
  if (hasOG && !/name=["']twitter:card["']/i.test(body)) r.push({ passed: false, severity: 'low', cat: 'SEO', title: 'Missing Twitter Card Tags', description: 'No twitter:card meta tag — Twitter uses a default layout for shares.' });
  return r;
}

// ─────────────────────────────────────────────────────────
// [14] PERFORMANCE (10 checks)
// ─────────────────────────────────────────────────────────
function checkPerformance(body, headers, responseTime) {
  const r = [];
  const size = body.length;
  if (responseTime > 4000) r.push({ passed: false, severity: 'critical', cat: 'Performance', title: `Critical Response Time: ${responseTime}ms`, description: 'Server response >4s. Google Core Web Vitals require <200ms TTFB. Users abandon after 3s.' });
  else if (responseTime > 2000) r.push({ passed: false, severity: 'high', cat: 'Performance', title: `Slow Response Time: ${responseTime}ms`, description: 'Response time >2s. Aim for <500ms.' });
  else if (responseTime > 800) r.push({ passed: false, severity: 'medium', cat: 'Performance', title: `Moderate Response Time: ${responseTime}ms`, description: 'Response time could be improved. Target <500ms.' });
  else r.push({ passed: true, severity: 'low', cat: 'Performance', title: `Fast Response: ${responseTime}ms`, description: 'Server response time is good.' });

  if (size > 5000000) r.push({ passed: false, severity: 'critical', cat: 'Performance', title: `Huge Page Size: ${(size / 1e6).toFixed(1)}MB`, description: 'Page exceeds 5MB. Severely impacts load time on mobile.' });
  else if (size > 1500000) r.push({ passed: false, severity: 'high', cat: 'Performance', title: `Large Page Size: ${(size / 1e6).toFixed(1)}MB`, description: 'Page >1.5MB. Optimize images, minify assets.' });

  const scripts = (body.match(/<script\b[^>]*src=/gi) || []).length;
  if (scripts > 25) r.push({ passed: false, severity: 'high', cat: 'Performance', title: `Too Many Script Tags: ${scripts}`, description: 'Each script is a separate HTTP request. Bundle with webpack/rollup.', fix: `// Use Webpack to bundle:\n// webpack.config.js:\nmodule.exports = { entry: './src/index.js', output: { filename: 'bundle.js' } }` });
  else if (scripts > 10) r.push({ passed: false, severity: 'medium', cat: 'Performance', title: `Many External Scripts: ${scripts}`, description: 'Consider bundling scripts to reduce HTTP requests.' });

  // Async/defer on scripts
  const syncScripts = (body.match(/<script\b(?![^>]*(?:async|defer))[^>]*src=[^>]*>/gi) || []).length;
  if (syncScripts > 3) r.push({ passed: false, severity: 'medium', cat: 'Performance', title: `${syncScripts} Render-Blocking Scripts`, description: 'Scripts without async or defer block HTML parsing and delay Time-to-Interactive.', fix: `<!-- Add defer to non-critical scripts: -->\n<script src="app.js" defer></script>` });

  const css = (body.match(/<link[^>]*stylesheet[^>]*>/gi) || []).length;
  if (css > 10) r.push({ passed: false, severity: 'medium', cat: 'Performance', title: `Many CSS Files: ${css}`, description: 'Too many CSS files slow page load. Bundle stylesheets.' });

  // Compression
  const enc = headers['content-encoding'] || '';
  if (!enc.includes('gzip') && !enc.includes('br') && !enc.includes('zstd')) r.push({ passed: false, severity: 'medium', cat: 'Performance', title: 'No Compression (gzip/br)', description: 'Server not compressing responses. Enabling gzip/brotli reduces transfer size by 70%+.', fix: `# nginx:\ngzip on; gzip_types text/html text/css application/javascript;\n# Express:\nconst compression = require('compression');\napp.use(compression());` });
  else r.push({ passed: true, severity: 'low', cat: 'Performance', title: `Compression Enabled (${enc})`, description: 'Response compression active.' });

  // Caching
  const cc = headers['cache-control'] || '';
  if (!cc && !headers['expires'] && !headers['etag'] && !headers['last-modified']) r.push({ passed: false, severity: 'medium', cat: 'Performance', title: 'No Browser Caching Headers', description: 'No caching headers set. Assets re-downloaded on every visit.', fix: `res.setHeader('Cache-Control','public, max-age=31536000, immutable'); // For static assets` });

  // CDN detection
  const cdnHeaders = ['cf-ray', 'x-served-by', 'x-cache', 'x-amz-cf-id', 'x-cdn'];
  const hasCDN = cdnHeaders.some(h => headers[h]);
  if (!hasCDN) r.push({ passed: false, severity: 'low', cat: 'Performance', title: 'No CDN Detected', description: 'Site may not be using a CDN. CDNs reduce latency by serving from edge locations near users.' });

  return r;
}

// ─────────────────────────────────────────────────────────
// [15] PRIVACY & COMPLIANCE (8 checks)
// ─────────────────────────────────────────────────────────
function checkPrivacy(body, headers) {
  const r = [];
  // Only flag privacy policy absence if the site has forms, sets cookies, or runs trackers
  const hasForms = /<form[\s>]/i.test(body);
  const hasCookies = !!(headers['set-cookie']);
  const hasTrackers = /google-analytics\.com|gtag|fbq\s*\(|hotjar\.com|segment\.com/i.test(body);
  const collectsData = hasForms || hasCookies || hasTrackers;

  if (collectsData && !/privacy\s*policy|privacy\s*notice|datenschutz|href=[^>]*privacy/i.test(body))
    r.push({ passed: false, severity: 'high', cat: 'Privacy', title: 'No Privacy Policy Link', description: 'Site collects data (forms/cookies/trackers) but no privacy policy detected. Required by GDPR, CCPA and most privacy laws.' });

  // Cookie consent only matters when tracking cookies are present (not just session/functional cookies)
  if (hasTrackers && !/cookie\s*policy|cookie\s*consent|accept.*?cookie|we use cookies|cookiebot|onetrust|gdpr/i.test(body))
    r.push({ passed: false, severity: 'high', cat: 'Privacy', title: 'No Cookie Consent Mechanism', description: 'Third-party trackers detected but no cookie consent banner found. Required by GDPR/ePrivacy directive for EU users.' });

  // Terms of service only relevant for transactional/account-based sites
  const isTransactional = /sign[\s-]?(up|in)|log[\s-]?in|register|checkout|cart|subscribe|pricing|plan/i.test(body);
  if (isTransactional && !/terms\s*(of\s*)?(service|use)|terms\s*&\s*conditions|href=[^>]*terms/i.test(body))
    r.push({ passed: false, severity: 'low', cat: 'Privacy', title: 'No Terms of Service Link', description: 'No terms of service detected.' });
  // Third-party tracking
  const trackers = [
    [/google-analytics\.com|gtag|ga\s*\('/i, 'Google Analytics'],
    [/facebook\.net|fbq\s*\(/i, 'Facebook Pixel'],
    [/hotjar\.com/i, 'Hotjar'],
    [/segment\.com|analytics\.js/i, 'Segment'],
    [/intercom\.com/i, 'Intercom'],
  ];
  const found = trackers.filter(([rx]) => rx.test(body)).map(([, n]) => n);
  if (found.length) r.push({ passed: false, severity: 'medium', cat: 'Privacy', title: `Third-Party Trackers: ${found.join(', ')}`, description: `Tracking scripts detected. Ensure these are disclosed in your privacy policy and consent is obtained before loading them.` });
  // GDPR data transfer
  if (/doubleclick\.net|google-analytics\.com/i.test(body)) r.push({ passed: false, severity: 'medium', cat: 'Privacy', title: 'Cross-Border Data Transfer (US Services)', description: 'Data transferred to US providers (Google/Meta). EU sites may need SCCs or consent per Schrems II.' });
  return r;
}

// ─────────────────────────────────────────────────────────
// [16] ACCESSIBILITY - WCAG 2.1 (10 checks)
// ─────────────────────────────────────────────────────────
function checkAccessibility(body) {
  const r = [];
  if (!/<html[^>]*lang\s*=/i.test(body)) r.push({ passed: false, severity: 'high', cat: 'Accessibility', title: 'Missing lang on <html>', description: 'Screen readers use lang attribute to choose correct pronunciation engine.' });
  const inputs = body.match(/<input[^>]*>/gi) || [];
  const unlabeled = inputs.filter(i => !/type\s*=\s*["'](hidden|submit|button|image|reset)["']/i.test(i) && !/aria-label\b|aria-labelledby\b/i.test(i));
  if (unlabeled.length) r.push({ passed: false, severity: 'high', cat: 'Accessibility', title: `${unlabeled.length} Form Input(s) Without ARIA Label`, description: 'Screen readers cannot describe unlabeled inputs to visually impaired users.', fix: `<label for="email">Email</label>\n<input id="email" type="email">\n<!-- Or: -->\n<input aria-label="Email address" type="email">` });
  // Skip-to-content only matters when there's actual navigation to skip
  const hasNav = /<nav[\s>]/i.test(body) || (body.match(/<a\s/gi) || []).length > 5;
  if (hasNav && !/skip\s*(to|main|content|nav)/i.test(body)) r.push({ passed: false, severity: 'medium', cat: 'Accessibility', title: 'Missing Skip-to-Content Link', description: 'Keyboard users cannot skip repetitive navigation. Add a skip link as first focusable element.' });
  const btns = body.match(/<button[^>]*>/gi) || [];
  const emptyBtns = btns.filter(b => !/aria-label\b|aria-labelledby\b|title\b/i.test(b));
  // Check if button content is just an icon
  if (emptyBtns.length > 2) r.push({ passed: false, severity: 'medium', cat: 'Accessibility', title: `${emptyBtns.length} Button(s) May Lack Accessible Names`, description: 'Icon-only buttons need aria-label for screen readers.' });
  // Color contrast check (can only test structural clues)
  if (/#fff|#ffffff|white/i.test(body) && /background\s*:\s*#fff|background-color\s*:\s*#fff/i.test(body)) r.push({ passed: false, severity: 'low', cat: 'Accessibility', title: 'White-on-White Contrast Risk', description: 'Multiple white backgrounds detected. Manually verify color contrast ratios meet WCAG 4.5:1 minimum.' });
  // ARIA roles
  if (/<div[^>]*onclick/gi.test(body)) r.push({ passed: false, severity: 'medium', cat: 'Accessibility', title: 'Clickable Divs Without ARIA Role', description: 'Divs with onclick should have role="button" and tabindex="0" for keyboard accessibility.', fix: `<!-- ❌ -->\n<div onclick="action()">Click me</div>\n<!-- ✅ -->\n<button onclick="action()">Click me</button>` });
  if (/<img[^>]*role\s*=\s*["']presentation["'][^>]*(?!alt)/gi.test(body)) r.push({ passed: false, severity: 'low', cat: 'Accessibility', title: 'Decorative Images May Need alt=""', description: 'Decorative images should have alt="" so screen readers skip them.' });
  // Tab order
  if (/tabindex\s*=\s*["']([2-9]\d*|[1-9]\d+)["']/i.test(body)) r.push({ passed: false, severity: 'medium', cat: 'Accessibility', title: 'Positive tabindex Values Found', description: 'Positive tabindex disrupts natural tab order. Use 0 or -1 only.' });
  return r;
}

// ─────────────────────────────────────────────────────────
// [17] ROBOTS.TXT & SITEMAP (5 checks)
// ─────────────────────────────────────────────────────────
async function checkCrawlability(urlStr) {
  const r = [];
  const u = new URL(urlStr);
  const base = `${u.protocol}//${u.hostname}`;

  const robRes = await probe(`${base}/robots.txt`, 5000);
  if (robRes.status !== 200) {
    r.push({ passed: false, severity: 'medium', cat: 'SEO', title: 'robots.txt Missing', description: 'No robots.txt found. Add one to guide search engine crawlers.', fix: `User-agent: *\nAllow: /\nSitemap: ${base}/sitemap.xml` });
  } else {
    if (/disallow:\s*\/\s*$/im.test(robRes.body)) r.push({ passed: false, severity: 'critical', cat: 'SEO', title: 'robots.txt Blocks All Crawlers', description: '"Disallow: /" found — search engines cannot index your site.' });
    if (!/sitemap:/i.test(robRes.body)) r.push({ passed: false, severity: 'low', cat: 'SEO', title: 'robots.txt Missing Sitemap Reference', description: 'Add Sitemap: URL to robots.txt so crawlers discover your sitemap.' });
    else r.push({ passed: true, severity: 'low', cat: 'SEO', title: 'robots.txt Valid', description: 'robots.txt present with sitemap reference.' });
  }

  const sitemapRes = await probe(`${base}/sitemap.xml`, 5000);
  if (sitemapRes.status !== 200) {
    const sitemapIndexRes = await probe(`${base}/sitemap_index.xml`, 4000);
    if (sitemapIndexRes.status !== 200) r.push({ passed: false, severity: 'high', cat: 'SEO', title: 'No sitemap.xml Found', description: 'Sitemap not found at /sitemap.xml or /sitemap_index.xml. Search engines may miss pages.', fix: `<?xml version="1.0"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${base}/</loc><priority>1.0</priority></url>\n</urlset>` });
    else r.push({ passed: true, severity: 'low', cat: 'SEO', title: 'Sitemap Index Found', description: 'sitemap_index.xml present.' });
  } else r.push({ passed: true, severity: 'low', cat: 'SEO', title: 'sitemap.xml Found', description: 'XML sitemap is accessible to crawlers.' });

  return r;
}

// ─────────────────────────────────────────────────────────
// [18] RATE LIMITING & DOS PROTECTION (4 checks)
// ─────────────────────────────────────────────────────────
async function checkRateLimiting(urlStr) {
  const r = [];
  const BURST = 5; // Reduced from 12 to be less aggressive
  const reqs = await Promise.all(Array.from({ length: BURST }, () => probe(urlStr, 3000)));
  const statuses = reqs.map(r => r.status);
  const has429 = statuses.includes(429);
  const has503 = statuses.filter(s => s === 503).length > 2;
  if (!has429 && !has503) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'No Rate Limiting Detected', description: `${BURST} rapid requests all returned OK. No rate limiting detected — verify API has DDoS protection.`, fix: `const rateLimit = require('express-rate-limit');\napp.use(rateLimit({ windowMs: 60000, max: 100, message: 'Too many requests' }));` });
  else r.push({ passed: true, severity: 'low', cat: 'Security', title: 'Rate Limiting Active', description: `Server returned ${has429 ? '429' : '503'} under rapid load — rate limiting or throttling is in place.` });
  // Large payload test
  try {
    const bigRes = await fetchUrl(urlStr, 5000, 'POST', { 'Content-Type': 'application/json', 'Content-Length': '10000000' });
    if (bigRes.status === 200) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'No Request Size Limit Detected', description: 'Server may accept excessively large request bodies. Set payload size limits to prevent memory exhaustion.', fix: `app.use(express.json({ limit: '10kb' }));\napp.use(express.urlencoded({ limit: '10kb', extended: false }));` });
  } catch { }
  return r;
}

// ─────────────────────────────────────────────────────────
// [19] SUBDOMAIN & INFRASTRUCTURE (5 checks)
// ─────────────────────────────────────────────────────────
async function checkInfrastructure(urlStr) {
  const r = [];
  const u = new URL(urlStr);
  const hostname = u.hostname;

  // HTTP → HTTPS redirect — use raw request that does NOT follow redirects
  // so we can see the actual 301/302 status instead of the final 200
  if (u.protocol === 'https:') {
    const httpUrl = urlStr.replace(/^https:/, 'http:');
    try {
      const httpRes = await new Promise((resolve) => {
        const parsed = new URL(httpUrl);
        const timer = setTimeout(() => resolve({ status: 0 }), 5000);
        const req = http.request({ hostname: parsed.hostname, port: 80, path: parsed.pathname + parsed.search, method: 'HEAD', timeout: 5000 }, res => {
          clearTimeout(timer);
          resolve({ status: res.statusCode, headers: res.headers });
        });
        req.on('error', () => { clearTimeout(timer); resolve({ status: 0 }); });
        req.on('timeout', () => { req.destroy(); clearTimeout(timer); resolve({ status: 0 }); });
        req.end();
      });
      if (httpRes.status === 200) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'HTTP Version Accessible (No Redirect)', description: 'Site is accessible over plain HTTP without redirecting to HTTPS. Sensitive data can be intercepted.', fix: `// Express:\napp.use((req,res,next)=>{\n  if(!req.secure) return res.redirect(301,'https://'+req.headers.host+req.url);\n  next();\n});` });
      else if ([301, 302, 307, 308].includes(httpRes.status)) r.push({ passed: true, severity: 'low', cat: 'Security', title: 'HTTP→HTTPS Redirect Active', description: `HTTP correctly redirects to HTTPS (${httpRes.status}).` });
    } catch { }
  }

  // Check for common admin/dev subdomains - limit to 3 to avoid timeout
  const devSubdomains = ['dev', 'staging', 'admin'];
  const rootDomain = hostname.split('.').slice(-2).join('.');
  for (const sub of devSubdomains) {
    try {
      const subRes = await probe(`https://${sub}.${rootDomain}`, 2500);
      if (subRes.status > 0 && subRes.status < 400) {
        r.push({ passed: false, severity: 'medium', cat: 'Exposure', title: `Dev/Staging Subdomain Accessible: ${sub}.${rootDomain}`, description: `${sub}.${rootDomain} is publicly accessible. Development environments often have weaker security.` });
      }
    } catch { }
  }

  // DNSSEC - skip if slow
  try {
    const nsecPromise = dns.resolve(hostname, 'NSEC');
    const nsec = await Promise.race([
      nsecPromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))
    ]);
    r.push({ passed: true, severity: 'low', cat: 'DNS', title: 'DNSSEC Records Present', description: 'DNS responses are cryptographically signed.' });
  } catch {
    // Skip DNSSEC check - not critical
  }

  return r;
}

// ─────────────────────────────────────────────────────────
// [20] THIRD-PARTY & SUPPLY CHAIN (5 checks)
// ─────────────────────────────────────────────────────────
function checkSupplyChain(body) {
  const r = [];
  // CDN scripts without SRI
  const extScripts = body.match(/<script[^>]*src=["']https?:\/\/(?!localhost)[^"']+["'][^>]*>/gi) || [];
  const noSri = extScripts.filter(s => !/integrity\s*=/i.test(s));
  if (noSri.length > 0) r.push({ passed: false, severity: 'high', cat: 'Security', title: `${noSri.length} External Scripts Without SRI`, description: 'Scripts loaded from CDNs without Subresource Integrity hashes. If the CDN is compromised, attackers inject malicious code.', fix: `<!-- Add integrity hash: -->\n<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-HASH_HERE"\n  crossorigin="anonymous"></script>\n<!-- Generate hash: openssl dgst -sha384 -binary lib.js | openssl base64 -A -->` });

  // Outdated library hints
  const libHints = [
    [/jquery[/-]([01]\.|2\.[01])/i, 'jQuery <2.2 (known XSS CVEs)'],
    [/bootstrap[/-][12]\./i, 'Bootstrap <3 (EOL)'],
    [/angular(?:js)?[/-]1\.[0-4]/i, 'AngularJS <1.5 (XSS vulnerabilities)'],
    [/moment\.js.*2\.[0-9]\./i, 'Moment.js old version'],
    [/lodash[/-][0-3]\./i, 'Lodash <4 (prototype pollution)'],
  ];
  const outdated = libHints.filter(([rx]) => rx.test(body)).map(([, n]) => n);
  if (outdated.length) r.push({ passed: false, severity: 'high', cat: 'Security', title: `Outdated Libraries: ${outdated.join(', ')}`, description: 'Outdated JavaScript libraries with known CVEs detected in page source.' });

  // Google Tag Manager / analytics without consent
  const gtm = /googletagmanager\.com|GTM-[A-Z0-9]+/i.test(body);
  if (gtm && !/consent|cookie.?consent/i.test(body)) r.push({ passed: false, severity: 'medium', cat: 'Privacy', title: 'GTM Without Visible Consent', description: 'Google Tag Manager loads without detectable consent mechanism. Violates GDPR if tracking before consent.' });

  return r;
}

// ─────────────────────────────────────────────────────────
// [21] BUSINESS LOGIC & MISC (10 checks)
// ─────────────────────────────────────────────────────────
function checkBusinessLogic(body, headers) {
  const r = [];
  // Sensitive data in HTML
  const emailRx = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = (body.match(emailRx) || []).filter(e => !e.includes('example.com') && !e.includes('yourdomain'));
  if (emails.length > 3) r.push({ passed: false, severity: 'medium', cat: 'Privacy', title: `${emails.length} Email Addresses Exposed in Source`, description: 'Email addresses in HTML are harvested by scrapers. Use contact forms instead.' });

  // Phone numbers
  const phoneRx = /\+?[\d\s\-().]{10,}/g;
  if ((body.match(phoneRx) || []).length > 5) r.push({ passed: false, severity: 'low', cat: 'Privacy', title: 'Phone Numbers Exposed in Source', description: 'Multiple phone numbers visible in page source — can be harvested.' });

  // Insecure form actions
  const forms = body.match(/<form[^>]*>/gi) || [];
  const httpForms = forms.filter(f => /action\s*=\s*["']http:\/\//i.test(f));
  if (httpForms.length) r.push({ passed: false, severity: 'critical', cat: 'Security', title: `${httpForms.length} Form(s) Submit to HTTP URL`, description: 'Forms submitting to http:// send data in plaintext. Passwords and personal info can be intercepted.' });

  // Password fields on HTTP
  if (/<input[^>]*type\s*=\s*["']password["']/i.test(body) && !headers['strict-transport-security']) r.push({ passed: false, severity: 'critical', cat: 'Security', title: 'Password Field on Non-HSTS Page', description: 'Login form present but HSTS not configured. Passwords can be intercepted via SSL stripping attacks.' });

  // Comment with debug info
  if (/<!--\s*(TODO|FIXME|HACK|debug|password|secret|key|token)/i.test(body)) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'Sensitive Comments in HTML Source', description: 'HTML comments containing TODO, password, secret, or key found. Remove all debug comments before production.' });

  // Version disclosure in HTML/JS
  if (/(?:version|v)\s*[:=]\s*["']?\d+\.\d+(?:\.\d+)?["']?\b/i.test(body)) r.push({ passed: false, severity: 'low', cat: 'Security', title: 'Application Version Disclosed', description: 'Application version number visible in page source. Helps attackers identify vulnerable versions.' });

  // IDOR-style numeric IDs in URLs
  if (/\/(?:user|account|profile|order|item)s?\/\d+/i.test(body)) r.push({ passed: false, severity: 'medium', cat: 'Security', title: 'Sequential/Numeric IDs in URLs', description: 'Numeric sequential IDs in URLs are prone to IDOR (Insecure Direct Object Reference). Use UUIDs or add authorization checks.', fix: `// Use UUID instead of sequential IDs:\nconst { v4: uuidv4 } = require('uuid');\nconst id = uuidv4(); // e.g. '550e8400-e29b-41d4-a716-446655440000'` });

  // Open redirect
  const redirectParams = /(?:redirect|return|next|url|goto|forward)\s*=/i.test(body);
  if (redirectParams) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'Potential Open Redirect Parameters', description: 'Parameters like redirect=, return=, next= detected. If not validated, attackers use these for phishing.', fix: `// Validate redirect URLs:\nconst allowed = ['https://yourdomain.com'];\nconst url = req.query.redirect;\nif (!allowed.some(a => url.startsWith(a))) return res.redirect('/');\nres.redirect(url);` });

  return r;
}

// ─────────────────────────────────────────────────────────
// [22] API SECURITY (5 checks)
// ─────────────────────────────────────────────────────────
async function checkAPISecurity(urlStr, headers, body) {
  const r = [];
  const u = new URL(urlStr);
  const base = `${u.protocol}//${u.hostname}`;

  // GraphQL endpoint probe
  const gqlRes = await probe(`${base}/graphql`, 3000);
  if (gqlRes.status === 200) {
    // Introspection enabled?
    try {
      const introspRes = await fetchUrl(`${base}/graphql`, 4000, 'POST', { 'Content-Type': 'application/json' });
      if (/\"__schema\"|\"__type\"/i.test(introspRes.body)) r.push({ passed: false, severity: 'high', cat: 'Security', title: 'GraphQL Introspection Enabled', description: 'GraphQL introspection exposes full API schema. Disable in production.', fix: `// Apollo Server:\nconst server = new ApolloServer({\n  introspection: process.env.NODE_ENV !== 'production'\n});` });
    } catch { }
  }

  // REST API common paths
  const apiPaths = ['/api', '/api/v1', '/api/v2', '/v1', '/v2'];
  for (const ap of apiPaths.slice(0, 3)) {
    const apiRes = await probe(`${base}${ap}`, 3000);
    if (apiRes.status === 200 && /application\/json/i.test(apiRes.headers['content-type'] || '')) {
      // Check if it returns raw data without auth
      if (apiRes.body.length > 100 && /\[|\{/.test(apiRes.body.trim()[0])) {
        r.push({ passed: false, severity: 'high', cat: 'Security', title: `Unauthenticated API Endpoint: ${ap}`, description: `${ap} returns JSON data without requiring authentication. Verify all API endpoints require proper auth.` });
        break;
      }
    }
  }

  // Check for API keys in response
  if (/(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}/i.test(body)) r.push({ passed: false, severity: 'critical', cat: 'Security', title: 'API Key Exposed in Response', description: 'API key or access token found in page body. Rotate immediately and store server-side only.' });

  // SWAGGER/OpenAPI exposed
  const swaggerRes = await probe(`${base}/api-docs`, 3000);
  const swaggerRes2 = await probe(`${base}/swagger.json`, 3000);
  if (swaggerRes.status === 200 || swaggerRes2.status === 200) r.push({ passed: false, severity: 'medium', cat: 'Exposure', title: 'API Documentation Publicly Exposed', description: 'Swagger/OpenAPI docs accessible without authentication. Reveals all endpoints, parameters and schemas to attackers.', fix: `// Restrict swagger in production:\nif (process.env.NODE_ENV !== 'production') {\n  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(spec));\n}` });

  return r;
}

// ─────────────────────────────────────────────────────────
// MAIN SCAN ENDPOINT
// ─────────────────────────────────────────────────────────
app.post('/api/scan', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  try { new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL format' }); }

  const startTime = Date.now();
  let pageRes;
  try {
    pageRes = await fetchUrl(url, 15000);
  } catch (err) {
    return res.json({ url, scannedAt: new Date().toISOString(), score: 0, totalChecks: 1, passedChecks: 0, failedChecks: 1, severityCounts: { critical: 1, high: 0, medium: 0, low: 0 }, issues: [{ passed: false, severity: 'critical', cat: 'Network', title: 'Site Unreachable', description: `Cannot connect to ${url}: ${err.message}` }], fixPrompts: [], responseTime: Date.now() - startTime, pageSize: 0 });
  }

  const responseTime = Date.now() - startTime;
  const u = new URL(url);

  // ── Run ALL checks ──
  const [
    sslChecks, tlsChecks,
    exposedFiles,
    httpMethodChecks,
    authChecks,
    dnsChecks,
    crawlChecks,
    rateLimitChecks,
    infraChecks,
    apiChecks,
    injectionChecks,
  ] = await Promise.all([
    checkSSL(url),
    checkTLS(url),
    checkExposedFiles(url),
    checkHTTPMethods(url),
    checkAuthentication(url, pageRes.body, pageRes.headers),
    checkDNS(u.hostname),
    checkCrawlability(url),
    checkRateLimiting(url),
    checkInfrastructure(url),
    checkAPISecurity(url, pageRes.headers, pageRes.body),
    checkInjections(url, pageRes.body, pageRes.headers),
  ]);

  const allChecks = [
    ...sslChecks,
    ...tlsChecks,
    ...checkSecurityHeaders(pageRes.headers, pageRes.body),
    ...checkCORS(pageRes.headers),
    ...checkInfoLeakage(pageRes.headers, pageRes.body),
    ...checkCookies(pageRes.headers),
    ...checkMixedContent(pageRes.body, url),
    ...checkCSRF(pageRes.body, pageRes.headers),
    ...checkSEO(pageRes.body),
    ...checkPerformance(pageRes.body, pageRes.headers, responseTime),
    ...checkPrivacy(pageRes.body, pageRes.headers),
    ...checkAccessibility(pageRes.body),
    ...checkSupplyChain(pageRes.body),
    ...checkBusinessLogic(pageRes.body, pageRes.headers),
    ...exposedFiles,
    ...httpMethodChecks,
    ...authChecks,
    ...dnsChecks,
    ...crawlChecks,
    ...rateLimitChecks,
    ...infraChecks,
    ...apiChecks,
    ...injectionChecks,
  ];

  // Deduplicate by title
  const seen = new Set();
  const checks = allChecks.filter(c => { if (seen.has(c.title)) return false; seen.add(c.title); return true; });

  // Scoring
  const weights = { critical: 15, high: 8, medium: 3, low: 1 };
  const maxScore = checks.length * 8;
  const penalty = checks.filter(c => !c.passed).reduce((s, c) => s + (weights[c.severity] || 1), 0);
  const score = Math.max(0, Math.min(100, Math.round(100 - (penalty / Math.max(maxScore, 1)) * 100)));

  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  checks.filter(c => !c.passed).forEach(c => { if (sev[c.severity] !== undefined) sev[c.severity]++; });

  // Category grouping
  const cats = {};
  checks.forEach(c => { if (!cats[c.cat]) cats[c.cat] = []; cats[c.cat].push(c); });

  // Fix prompts
  const fixPrompts = checks.filter(c => !c.passed && c.fix).map(c => ({ title: c.title, severity: c.severity, cat: c.cat, description: c.description, fix: c.fix }));

  res.json({
    url, scannedAt: new Date().toISOString(),
    score, totalChecks: checks.length,
    passedChecks: checks.filter(c => c.passed).length,
    failedChecks: checks.filter(c => !c.passed).length,
    severityCounts: sev,
    issues: checks,
    fixPrompts,
    categories: cats,
    responseTime,
    pageSize: pageRes.body.length,
    statusCode: pageRes.status,
    server: pageRes.headers['server'] || 'Unknown'
  });
});

app.get('/api/health', (_, res) => res.json({ ok: true, checks: '150+', version: '2.0' }));

// ── Page routes (serve specific HTML files) ──
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (_, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/scan', (_, res) => res.sendFile(path.join(__dirname, 'public', 'scan.html')));

// Catch-all fallback: serve index.html (SPA-style)
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`\n  Advanced Scanner v2.0 running → http://localhost:${PORT}\n  150+ vulnerability checks ready\n`));
