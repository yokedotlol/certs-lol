import type { Env, ProbeResult, ScanResult } from './worker';
import { html } from './spa';
import { trackScan, handleUsage } from './usage';
import { enrich } from './enrich';
import { evaluateCompliance } from './compliance';

const CACHE_TTL = 21600; // 6 hours
const RATE_LIMIT = 20;

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https://yoke.lol; frame-ancestors 'none'; base-uri 'self'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
};

function isIP(target: string): boolean {
  // IPv4
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return true;
  // IPv6 (with or without brackets)
  if (target.startsWith('[') && target.endsWith(']')) return true;
  if (target.includes(':') && /^[0-9a-fA-F:]+$/.test(target)) return true;
  return false;
}

function wantsJSON(request: Request): boolean {
  const accept = request.headers.get('Accept') || '';
  const ua = request.headers.get('User-Agent') || '';

  // Explicit JSON request
  if (accept.includes('application/json')) return true;

  // curl, httpie, wget, etc. — unless they explicitly want HTML
  if (accept.includes('text/html')) return false;
  if (/^(curl|HTTPie|Wget|fetch|node|python|Go-http|axios)/i.test(ua)) return true;

  // Wildcard accept from non-browser clients
  if (accept === '*/*' && !/Mozilla|Chrome|Safari|Edge/i.test(ua)) return true;

  return false;
}

function getClientIP(request: Request): string {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
}

async function checkRateLimit(ip: string, env: Env): Promise<{ allowed: boolean; remaining: number; retryAfter?: number }> {
  const id = env.RATE_LIMITER.idFromName(ip);
  const stub = env.RATE_LIMITER.get(id);
  const resp = await stub.fetch(new Request('https://do/check'));
  return resp.json();
}



function addHeaders(response: Response, extra?: Record<string, string>): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    headers.set(k, v);
  }
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      headers.set(k, v);
    }
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function jsonResponse(data: unknown, status = 200, extra?: Record<string, string>): Response {
  return addHeaders(
    new Response(JSON.stringify(data, null, 2) + '\n', {
      status,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    }),
    extra,
  );
}

function htmlResponse(body: string, status = 200): Response {
  return addHeaders(
    new Response(body, {
      status,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=300, s-maxage=600',
        'Vary': 'Accept',
      },
    }),
  );
}

export async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return addHeaders(new Response(null, { status: 204 }), {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept',
      'Access-Control-Max-Age': '86400',
    });
  }

  // Only GET and HEAD
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }

  // Static routes
  if (path === '/' || path === '') {
    if (wantsJSON(request)) {
      return jsonResponse({
        name: 'certs.lol',
        tagline: 'Fast, API-first TLS scanning.',
        usage: 'curl -s https://certs.lol/stripe.com | jq',
        docs: 'https://certs.lol/api/docs',
        version: '1.0.0',
      });
    }
    return htmlResponse(html());
  }

  if (path === '/api/docs') {
    return htmlResponse(docsPage());
  }

  if (path === '/usage') {
    return handleUsage(request, env);
  }

  if (path === '/robots.txt') {
    return addHeaders(new Response('User-agent: *\nAllow: /\nSitemap: https://certs.lol/sitemap.xml\n', {
      headers: { 'Content-Type': 'text/plain' },
    }));
  }

  if (path === '/llms.txt') {
    return addHeaders(new Response(llmsTxt(), {
      headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' },
    }));
  }

  if (path === '/sitemap.xml') {
    return addHeaders(new Response(sitemap(), {
      headers: { 'Content-Type': 'application/xml' },
    }));
  }

  if (path === '/.well-known/security.txt') {
    return addHeaders(new Response(securityTxt(), {
      headers: { 'Content-Type': 'text/plain' },
    }));
  }

  if (path === '/privacy') {
    return htmlResponse(privacyPage());
  }

  if (path === '/terms') {
    return htmlResponse(termsPage());
  }

  if (path === '/about') {
    return htmlResponse(aboutPage());
  }

  // Favicon
  // OG image
  if (path === '/og.png' || path === '/og.svg') {
    return addHeaders(new Response(ogImage(), {
      headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' },
    }));
  }

  if (path === '/favicon.ico' || path === '/favicon.svg') {
    return addHeaders(new Response(faviconSvg(), {
      headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' },
    }));
  }

  // Scan route: /target
  const target = path.slice(1).replace(/\/+$/, '');
  if (!target || target.includes('/')) {
    return jsonResponse({ error: 'Not found' }, 404);
  }

  // Validate target
  const targetIsIP = isIP(target);
  if (!targetIsIP && !/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(target)) {
    return jsonResponse({ error: 'Invalid domain or IP' }, 400);
  }

  const clientIP = getClientIP(request);
  const forceRescan = url.searchParams.has('force');

  // Rate limit check — every request counts (cache hit or miss)
  const rl = await checkRateLimit(clientIP, env);
  if (!rl.allowed) {
    ctx.waitUntil(trackScan(env, { target, cache_hit: false, rate_limited: true }));
    const body = { error: 'Rate limit exceeded', retry_after: rl.retryAfter };
    if (wantsJSON(request)) {
      return jsonResponse(body, 429, {
        'Retry-After': String(rl.retryAfter),
        'X-RateLimit-Limit': String(RATE_LIMIT),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(rl.retryAfter),
      });
    }
    return htmlResponse(html(undefined, 'Rate limit exceeded. Try again in ' + rl.retryAfter + 's.'), 429);
  }

  // Check cache (skip on ?force)
  const cacheKey = `scan:${target.toLowerCase()}`;
  const cached = forceRescan ? null : await env.CACHE.get(cacheKey, 'json') as ScanResult | null;

  if (cached) {
    const result = { ...cached, _meta: { ...cached._meta, cache_hit: true } };

    // Track cache hit (non-blocking)
    ctx.waitUntil(trackScan(env, { target, cache_hit: true }));

    if (wantsJSON(request)) {
      return jsonResponse(result, 200, {
        'X-Cache': 'HIT',
        'X-RateLimit-Limit': String(RATE_LIMIT),
        'X-RateLimit-Remaining': String(rl.remaining),
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300',
      });
    }
    return htmlResponse(html(result, undefined, { remaining: rl.remaining, limit: RATE_LIMIT }));
  }

  // Call probe + enrichment in parallel
  try {
    const probeParam = targetIsIP ? `ip=${encodeURIComponent(target)}` : `domain=${encodeURIComponent(target)}`;
    const probePromise = fetch(`${env.PROBE_URL}/probe-ssl?${probeParam}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${env.FLY_AUTH_SECRET}`,
      },
      signal: AbortSignal.timeout(15000),
    });

    // Run enrichment in parallel (domains only)
    const enrichPromise = targetIsIP ? Promise.resolve(null) : enrich(target, env);

    const [probeResp, enrichment] = await Promise.all([probePromise, enrichPromise]);

    if (!probeResp.ok) {
      const errText = await probeResp.text().catch(() => 'Unknown error');
      ctx.waitUntil(trackScan(env, { target, cache_hit: false, error: true, status: probeResp.status, detail: errText }));
      return jsonResponse({
        error: 'Probe error',
        status: probeResp.status,
        detail: errText,
      }, probeResp.status === 429 ? 429 : 502);
    }

    const probe = await probeResp.json() as ProbeResult;

    if (probe.error) {
      ctx.waitUntil(trackScan(env, { target, cache_hit: false, error: true, status: 502, detail: probe.error }));
      return jsonResponse({ error: 'Scan failed', detail: probe.error }, 502);
    }

    // Compute days remaining
    const daysRemaining = probe.valid_to
      ? Math.max(0, Math.floor((new Date(probe.valid_to).getTime() - Date.now()) / 86400000))
      : 0;

    // Cipher summary
    const cipherSummary = { strong: 0, acceptable: 0, weak: 0, insecure: 0 };
    for (const c of probe.ciphers || []) {
      if (c.strength in cipherSummary) {
        cipherSummary[c.strength as keyof typeof cipherSummary]++;
      }
    }

    // Default enrichment for IPs
    const defaultEnrich = {
      hsts: { enabled: false, max_age: null, include_subdomains: false, preload: false, on_preload_list: false },
      http3: { supported: false, http2: false, alt_svc: null },
      dns_security: null,
    };

    const enrichData = enrichment || defaultEnrich;

    // Build enriched result
    const result: ScanResult = {
      ...probe,
      target,
      is_ip: targetIsIP,
      scanned_at: new Date().toISOString(),
      days_remaining: daysRemaining,
      cipher_summary: cipherSummary,
      hsts: enrichData.hsts,
      http3: enrichData.http3,
      dns_security: targetIsIP ? null : enrichData.dns_security,
      compliance: evaluateCompliance({
        protocols: probe.protocols,
        ciphers: probe.ciphers,
        cipher_summary: cipherSummary,
        key_alg: probe.key_alg,
        key_size: probe.key_size,
        forward_secrecy: probe.forward_secrecy,
        chain_valid: probe.chain_valid,
        days_remaining: daysRemaining,
        ocsp_stapling: probe.ocsp_stapling,
        hsts: enrichData.hsts,
      }),
      _meta: {
        version: '1.0.0',
        cache_hit: false,
        cache_ttl: CACHE_TTL,
        docs: 'https://certs.lol/api/docs',
        ...(targetIsIP ? {} : { full_report: `https://yoke.lol/${target}` }),
      },
    };

    // Cache the result
    await env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL });
    ctx.waitUntil(trackScan(env, { target, cache_hit: false }));

    if (wantsJSON(request)) {
      return jsonResponse(result, 200, {
        'X-Cache': 'MISS',
        'X-RateLimit-Limit': String(RATE_LIMIT),
        'X-RateLimit-Remaining': String(rl.remaining),
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300',
      });
    }
    return htmlResponse(html(result, undefined, { remaining: rl.remaining, limit: RATE_LIMIT }));

  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    ctx.waitUntil(trackScan(env, { target, cache_hit: false, error: true, status: 500, detail: message }));
    if (message.includes('timed out') || message.includes('abort')) {
      return jsonResponse({ error: 'Scan timed out', detail: 'Probe did not respond within 15s' }, 504);
    }
    return jsonResponse({ error: 'Internal error', detail: message }, 500);
  }
}

// --- Static page generators ---

function ogImage(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
<rect width="1200" height="630" fill="#0a0a0f"/>
<text x="100" y="260" font-family="system-ui,sans-serif" font-size="72" font-weight="800" fill="#d8d8e0" letter-spacing="-2">certs.lol</text>
<text x="100" y="330" font-family="system-ui,sans-serif" font-size="28" fill="#9b8afb">Fast, API-first TLS scanning</text>
<text x="100" y="400" font-family="monospace" font-size="22" fill="#38d9a9">$ curl https://certs.lol/stripe.com | jq</text>
<text x="100" y="460" font-family="system-ui,sans-serif" font-size="18" fill="#5c5c6b">No accounts · No tracking · No API keys</text>
</svg>`;
}

function faviconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="80" font-size="80">🔒</text></svg>`;
}

function securityTxt(): string {
  return `Contact: mailto:hello@certs.lol
Expires: 2027-06-12T00:00:00.000Z
Preferred-Languages: en
Canonical: https://certs.lol/.well-known/security.txt
`;
}

function llmsTxt(): string {
  return `# certs.lol

> Fast, API-first TLS scanning.

certs.lol scans any domain or IP for its complete TLS configuration and returns a letter grade with detailed results. Same URL, content-negotiated: curl gets JSON, browsers get HTML.

## API

Scan a domain: GET https://certs.lol/{domain}
Scan an IP: GET https://certs.lol/{ip}
API docs: https://certs.lol/api/docs

No authentication required. Rate limit: 20 scans/hour per IP. Results cached for 6h. Add ?force to bypass cache.

## What it checks

- Protocol support: TLS 1.3, 1.2, 1.1, 1.0
- Certificate: chain validation, expiry, key type/size, SANs, SCTs, OCSP stapling, SHA-256 fingerprint
- Cipher suites: full enumeration with strength grading
- Post-quantum: X25519MLKEM768 hybrid key exchange
- ECH: Encrypted Client Hello
- HSTS: max-age, includeSubDomains, preload list status
- HTTP/2 and HTTP/3 (QUIC)
- DNS security: DNSSEC, CAA, DANE/TLSA
- Compliance: PCI DSS 4.0, NIST SP 800-52r2, HIPAA transport requirements

## Related

- Full domain intelligence: https://yoke.lol
- Source code: https://github.com/yokedotlol/certs-lol
- Probe source: https://github.com/yokedotlol/yoke (fly-proxy/)
`;
}

function sitemap(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://certs.lol/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://certs.lol/api/docs</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://certs.lol/llms.txt</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://certs.lol/about</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://certs.lol/privacy</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>https://certs.lol/terms</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>`;
}

function docsPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Docs — certs.lol</title>
${metaTags('API Documentation', 'certs.lol API reference. Scan any domain or IP for TLS configuration in under 5 seconds.')}
<style>${baseCSS()}</style></head><body>
<div class="page">
<h1>API Documentation</h1>
<p class="muted">certs.lol is API-first. Same URL, content-negotiated.</p>

<h2>Quick Start</h2>
<pre><code>$ curl -s https://certs.lol/stripe.com | jq</code></pre>

<h2>Endpoints</h2>
<h3>GET /{domain}</h3>
<p>Scan a domain's TLS configuration. Returns full scan result with grade, protocols, certificate details, cipher suites, and more.</p>
<pre><code>$ curl -s https://certs.lol/stripe.com | jq '.grade'
"A+"</code></pre>

<h3>GET /{domain}?force</h3>
<p>Bypass cache and force a fresh scan. Still counts against rate limit.</p>
<pre><code>$ curl -s "https://certs.lol/stripe.com?force" | jq '.grade'
"A+"</code></pre>

<h3>GET /{ip}</h3>
<p>Scan a specific IP address. DNS-dependent fields (CAA, DANE, DNSSEC, multi-IP) are omitted.</p>
<pre><code>$ curl -s https://certs.lol/1.1.1.1 | jq '.certificate.subject'
"cloudflare-dns.com"</code></pre>

<h3>GET /</h3>
<p>Service info and usage hint.</p>

<h2>Content Negotiation</h2>
<p>The same URL serves JSON for API clients and HTML for browsers:</p>
<ul>
<li><code>curl</code>, <code>httpie</code>, <code>wget</code> → JSON</li>
<li><code>Accept: application/json</code> → JSON</li>
<li>Browser → HTML</li>
</ul>

<h2>Rate Limiting</h2>
<ul>
<li>20 scans per hour per IP</li>
<li>Results cached for 6h — add <code>?force</code> to bypass</li>
<li>429 response with <code>Retry-After</code> header when exceeded</li>
</ul>

<h2>Response Shape</h2>
<pre><code>{
  "grade": "A+",
  "issuer": "CN=WE1,O=Google Trust Services,C=US",
  "subject": "CN=example.com",
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_to": "2026-06-30T23:59:59Z",
  "key_alg": "ECDSA",
  "key_size": 256,
  "protocols": ["TLS 1.3", "TLS 1.2"],
  "chain_depth": 3,
  "chain_valid": true,
  "chain_certs": [
    {
      "subject": "CN=example.com",
      "issuer": "CN=WE1,O=Google Trust Services,C=US",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_to": "2026-06-30T23:59:59Z",
      "key_alg": "ECDSA", "key_size": 256,
      "serial": "74AA66CF...",
      "is_self_signed": false,
      "signature_alg": "ECDSAWithSHA256"
    },
    { "subject": "CN=WE1,...", "issuer": "CN=GTS Root R4,...", "...": "..." }
  ],
  "sans": ["example.com", "*.example.com"],
  "serial": "74AA66CF6F7314CE0EBD4122DFC80C79",
  "fingerprint": "A5F1682E76B7F050D62B...",
  "probe_ms": 218,
  "error": null,
  "ciphers": [
    { "name": "TLS_AES_128_GCM_SHA256", "id": 4865, "strength": "strong" },
    "..."
  ],
  "ocsp_stapling": true,
  "sct_count": 2,
  "has_scts": true,
  "forward_secrecy": true,
  "key_exchange": "ECDHE (TLS 1.3)",
  "target": "example.com",
  "is_ip": false,
  "scanned_at": "2026-06-13T03:33:08.052Z",
  "days_remaining": 72,
  "cipher_summary": { "strong": 5, "acceptable": 2, "weak": 0, "insecure": 0 },
  "hsts": {
    "enabled": true, "max_age": 31536000,
    "include_subdomains": true, "preload": true,
    "on_preload_list": true
  },
  "http3": {
    "supported": true, "http2": true,
    "alt_svc": "h3=\":443\"; ma=86400"
  },
  "dns_security": {
    "dnssec": true,
    "caa": ["issue digicert.com", "issue letsencrypt.org"],
    "dane_tlsa": null
  },
  "compliance": [
    {
      "framework": "pci-dss-4",
      "display_name": "PCI DSS 4.0",
      "meets_requirements": true,
      "findings": [...]
    },
    {
      "framework": "nist-800-52r2",
      "display_name": "NIST 800-52r2",
      "meets_requirements": true,
      "findings": [...]
    },
    {
      "framework": "hipaa",
      "display_name": "HIPAA",
      "meets_requirements": true,
      "findings": [...]
    }
  ],
  "_meta": {
    "version": "1.0.0",
    "cache_hit": false,
    "cache_ttl": 21600,
    "docs": "https://certs.lol/api/docs",
    "full_report": "https://yoke.lol/example.com"
  }
}</code></pre>

<h2>Compliance Mapping</h2>
<p>Each scan evaluates TLS configuration against transport encryption requirements for PCI DSS 4.0, NIST SP 800-52r2, and HIPAA. These are transport-layer checks only — passing means "meets transport encryption requirements for &lt;framework&gt;", not full compliance with the framework itself.</p>
<p>Each finding has a <code>status</code>: <code>pass</code>, <code>fail</code>, or <code>warn</code>. A framework <code>meets_requirements</code> when all findings are <code>pass</code> or <code>warn</code> (warnings don't cause failure).</p>

<h2>Rate Limit Headers</h2>
<p>Every response includes standard rate limit headers:</p>
<ul>
<li><code>X-RateLimit-Limit</code> — max scans per window (20)</li>
<li><code>X-RateLimit-Remaining</code> — scans left in current window</li>
<li><code>X-RateLimit-Reset</code> — seconds until window resets (429 responses only)</li>
</ul>

<h2>No Auth Required</h2>
<p>No API keys. No accounts. No tracking. Just data.</p>

<div class="footer-link"><a href="/">← back to certs.lol</a></div>
</div></body></html>`;
}

function privacyPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy — certs.lol</title>
${metaTags('Privacy Policy', 'certs.lol privacy policy. We collect nothing.')}
<style>${baseCSS()}</style></head><body>
<div class="page">
<h1>Privacy Policy</h1>
<p class="muted">Last updated: June 2026</p>

<h2>What we collect</h2>
<p>Nothing. certs.lol has no accounts, no cookies, no analytics, no tracking pixels, and no third-party scripts.</p>

<h2>Server logs</h2>
<p>Cloudflare processes requests as our CDN and compute provider. Their standard edge logs (IP, URL, timestamp) are subject to <a href="https://www.cloudflare.com/privacypolicy/">Cloudflare's privacy policy</a>. We do not access, store, or process these logs.</p>

<h2>Rate limiting</h2>
<p>We store a hashed IP counter in Cloudflare KV for rate limiting purposes. These counters expire automatically after 1 hour and contain no personally identifiable information beyond an IP-derived key.</p>

<h2>Scan data</h2>
<p>TLS scan results are cached for 6 hours to improve performance. Cached data contains only publicly observable TLS configuration — no private information.</p>

<h2>Contact</h2>
<p>Questions? <a href="mailto:hello@certs.lol">hello@certs.lol</a></p>

<div class="footer-link"><a href="/">← back to certs.lol</a></div>
</div></body></html>`;
}

function termsPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terms — certs.lol</title>
${metaTags('Terms of Service', 'certs.lol terms of service.')}
<style>${baseCSS()}</style></head><body>
<div class="page">
<h1>Terms of Service</h1>
<p class="muted">Last updated: June 2026</p>

<h2>What this is</h2>
<p>certs.lol is a free TLS scanning tool. It probes publicly-observable TLS configurations and reports what it finds.</p>

<h2>Use it reasonably</h2>
<p>Don't abuse the service. Rate limits are enforced at 20 scans per hour per IP. Automated scanning at scale without coordination is not welcome — talk to us first.</p>

<h2>No warranty</h2>
<p>This tool is provided as-is. Scan results reflect what we observe at scan time and may not represent the complete security posture of any target. Do not use certs.lol as your sole basis for security decisions.</p>

<h2>Scanning third-party servers</h2>
<p>certs.lol performs standard TLS handshakes — the same thing any web browser does. We do not attempt exploits, inject payloads, or probe for vulnerabilities. However, you are responsible for ensuring you have appropriate authorization to scan any target you submit.</p>

<h2>Changes</h2>
<p>We may update these terms. Continued use constitutes acceptance.</p>

<h2>Contact</h2>
<p><a href="mailto:hello@certs.lol">hello@certs.lol</a></p>

<div class="footer-link"><a href="/">← back to certs.lol</a></div>
</div></body></html>`;
}

function aboutPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>About — certs.lol</title>
${metaTags('About', 'Fast, API-first TLS scanning. No accounts, no tracking, no nonsense.')}
<style>${baseCSS()}</style></head><body>
<div class="page">
<h1>About certs.lol</h1>

<p>certs.lol is fast, API-first TLS scanning built for developers who live in the terminal.</p>

<h2>What it does</h2>
<p>Scans any domain or IP for its complete TLS configuration in under 5 seconds: protocol support, cipher suites, certificate chain, post-quantum readiness, ECH, HSTS, HTTP/3, DNSSEC, and more. Returns a letter grade with transparent methodology.</p>

<h2>How it works</h2>
<p><code>curl https://certs.lol/stripe.com | jq</code></p>
<p>Same URL, content-negotiated. curl gets JSON, your browser gets a formatted report. No API keys, no accounts, no tracking.</p>

<h2>Built by</h2>
<p>certs.lol is part of the <a href="https://yoke.lol">.lol</a> family. The TLS probe that powers certs.lol is the same one that feeds <a href="https://yoke.lol">yoke.lol</a>'s security analysis.</p>
<p>Open source: <a href="https://github.com/yokedotlol/certs-lol">github.com/yokedotlol/certs-lol</a></p>

<div class="footer-link"><a href="/">← back to certs.lol</a></div>
</div></body></html>`;
}

function metaTags(title: string, description: string): string {
  return `<meta name="description" content="${description}">
<meta property="og:title" content="${title} — certs.lol">
<meta property="og:description" content="${description}">
<meta property="og:type" content="website">
<meta property="og:url" content="https://certs.lol">
<meta property="og:image" content="https://certs.lol/og.svg">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title} — certs.lol">
<meta name="twitter:description" content="${description}">
<meta name="twitter:image" content="https://certs.lol/og.svg">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="canonical" href="https://certs.lol">`;
}

function baseCSS(): string {
  return `*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#d8d8e0;font-family:'Inter',system-ui,sans-serif;-webkit-font-smoothing:antialiased;line-height:1.6}
.page{max-width:640px;margin:0 auto;padding:3rem 1.5rem}
h1{font-size:1.5rem;font-weight:800;margin-bottom:0.5rem;letter-spacing:-0.03em}
h2{font-size:1rem;font-weight:700;margin-top:2rem;margin-bottom:0.5rem;color:#9b8afb}
h3{font-size:0.875rem;font-weight:600;margin-top:1.5rem;margin-bottom:0.25rem}
p{margin-bottom:1rem;color:#8e8e9a;font-size:0.875rem}
ul{margin:0.5rem 0 1rem 1.5rem;color:#8e8e9a;font-size:0.875rem}
li{margin-bottom:0.25rem}
a{color:#9b8afb;text-decoration:none}a:hover{text-decoration:underline}
pre{background:#111116;border:1px solid #1c1c24;border-radius:6px;padding:12px 16px;overflow-x:auto;margin:0.75rem 0;font-size:13px}
code{font-family:'JetBrains Mono',monospace;color:#38d9a9}
.muted{color:#5c5c6b;font-style:italic}
.footer-link{margin-top:3rem;padding-top:1rem;border-top:1px solid #1c1c24;font-size:12px}`;
}
