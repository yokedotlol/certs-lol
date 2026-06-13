import type { Env, ProbeResult, ScanResult } from './worker';
import { html } from './spa';
import { trackScan, handleUsage } from './usage';
import { enrich } from './enrich';
import { evaluateCompliance } from './compliance';

const CACHE_TTL = 21600; // 6 hours
const RATE_LIMIT = 60;

const INSTALL_SCRIPT = "#!/usr/bin/env bash\n# Install certs CLI \u2014 curl -sSL https://certs.lol/install.sh | bash\nset -euo pipefail\n\nREPO=\"yokedotlol/certs-lol\"\n\necho \"Installing certs...\"\n\n# Detect OS/arch\nOS=$(uname -s | tr '[:upper:]' '[:lower:]')\nARCH=$(uname -m)\ncase \"$ARCH\" in\n  x86_64|amd64) ARCH=\"amd64\" ;;\n  arm64|aarch64) ARCH=\"arm64\" ;;\n  *) echo \"error: unsupported architecture: $ARCH\" >&2; exit 1 ;;\nesac\n\n# Get latest release tag\nLATEST=$(curl -sfL \"https://api.github.com/repos/$REPO/releases/latest\" | grep '\"tag_name\"' | head -1 | sed 's/.*\"tag_name\": *\"//;s/\".*//')\nif [ -z \"$LATEST\" ]; then\n  echo \"error: could not determine latest release\" >&2; exit 1\nfi\n\necho \"  Version: $LATEST ($OS/$ARCH)\"\n\n# Build download URL\nEXT=\"tar.gz\"\n[ \"$OS\" = \"windows\" ] && EXT=\"zip\"\nURL=\"https://github.com/$REPO/releases/download/$LATEST/certs_${OS}_${ARCH}.${EXT}\"\n\n# Pick install dir\nif [ -w /usr/local/bin ]; then\n  INSTALL_DIR=\"/usr/local/bin\"\nelif [ -d \"$HOME/.local/bin\" ]; then\n  INSTALL_DIR=\"$HOME/.local/bin\"\nelse\n  mkdir -p \"$HOME/.local/bin\"\n  INSTALL_DIR=\"$HOME/.local/bin\"\nfi\n\n# Download and extract\nTMP=$(mktemp -d)\ntrap 'rm -rf \"$TMP\"' EXIT\n\necho \"  Downloading from GitHub Releases...\"\ncurl -sfL -o \"$TMP/certs.$EXT\" \"$URL\" || {\n  echo \"error: download failed \u2014 $URL\" >&2; exit 1\n}\n\nif [ \"$EXT\" = \"tar.gz\" ]; then\n  tar -xzf \"$TMP/certs.$EXT\" -C \"$TMP\"\nelse\n  unzip -q \"$TMP/certs.$EXT\" -d \"$TMP\"\nfi\n\n# Install binary\ncp \"$TMP/certs\" \"$INSTALL_DIR/certs\"\nchmod +x \"$INSTALL_DIR/certs\"\n\necho \"  \u2713 Installed to $INSTALL_DIR/certs\"\n\n# Verify\nif \"$INSTALL_DIR/certs\" version &>/dev/null; then\n  echo \"  $($INSTALL_DIR/certs version)\"\nfi\n\n# Check PATH\nif ! echo \"$PATH\" | tr ':' '\\n' | grep -qx \"$INSTALL_DIR\"; then\n  echo \"\"\n  echo \"  Add to your PATH:\"\n  echo \"    export PATH=\\\"$INSTALL_DIR:\\$PATH\\\"\"\nfi\n\necho \"\"\necho \"  Try it: certs example.com\"\n";

function rateLimitMessage(retryMin: number, target: string): string {
  return `<div class="err-title">Rate limit reached</div>
<p>Requests are limited to ${RATE_LIMIT} per hour to prevent abuse and keep hosting costs near zero. Try again in ~${retryMin} minute${retryMin === 1 ? '' : 's'}.</p>
<p>You can also get a full domain report (including TLS) at <a href="https://yoke.lol/${target}">yoke.lol/${target}</a>.</p>
<p>Or <a href="/cli">install the CLI</a> — run locally, unlimited, no rate limits.</p>`;
}

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

  if (path === '/cli') {
    return htmlResponse(cliPage());
  }

  if (path === '/install.sh') {
    return addHeaders(new Response(INSTALL_SCRIPT, {
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600' },
    }));
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

  // Rate limit check — all requests count to prevent abuse
  const rl = await checkRateLimit(clientIP, env);
  if (!rl.allowed) {
    ctx.waitUntil(trackScan(env, { target, cache_hit: false, rate_limited: true }));
    const retryMin = Math.ceil((rl.retryAfter || 60) / 60);
    const body = { error: 'Rate limit exceeded', retry_after: rl.retryAfter || 60 };
    if (wantsJSON(request)) {
      return jsonResponse(body, 429, {
        'Retry-After': String(rl.retryAfter || 60),
        'X-RateLimit-Limit': String(RATE_LIMIT),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(rl.retryAfter || 60),
      });
    }
    return htmlResponse(html(undefined, rateLimitMessage(retryMin, target)), 429);
  }

  // Check cache (skip on ?force)
  const cacheKey = `scan:${target.toLowerCase()}`;
  const cached = forceRescan ? null : await env.CACHE.get(cacheKey, 'json') as ScanResult | null;

  if (cached) {
    const result = { ...cached, _meta: { ...cached._meta, cache_hit: true } };
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
    return htmlResponse(html(result));
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
    return htmlResponse(html(result));

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

No authentication required. Rate limit: 60 requests/hour per IP. Results cached for 6h. Add ?force to bypass cache.

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

- CLI: https://certs.lol/cli — same engine, runs locally
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
  <url><loc>https://certs.lol/cli</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
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
<li>60 requests per hour per IP</li>
<li>Results cached for 6h — add <code>?force</code> to bypass</li>
<li>429 response with <code>Retry-After</code> header when exceeded</li>
</ul>
<p>Rate limits exist to prevent abuse and keep hosting costs near zero. If you need more volume, grab the <a href="https://github.com/yokedotlol/certs-lol">source</a> and run your own instance, or use the full domain report at <a href="https://yoke.lol">yoke.lol</a>.</p>

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
<li><code>X-RateLimit-Limit</code> — max requests per window (60)</li>
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
<p>Rate limits are enforced at 60 requests per hour per IP. Results are cached for 6 hours after a scan. These limits exist to prevent abuse and keep hosting costs near zero — certs.lol runs on a shoestring so it can stay free.</p>
<p>If you hit the limit, wait for the window to reset or check <a href="https://yoke.lol">yoke.lol</a> for a full domain report including TLS. Automated scanning at scale without coordination is not welcome — talk to us first.</p>

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

function cliPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CLI — certs.lol</title>
${metaTags('CLI', 'certs CLI — fast, local TLS scanning. Same engine as certs.lol. No middleman. No rate limits.')}
<style>${baseCSS()}
.badge{display:inline-block;background:#1c1c24;border:1px solid #2a2a35;border-radius:4px;padding:2px 8px;font-size:12px;color:#9b8afb;margin-right:6px}
table{border-collapse:collapse;width:100%;margin:0.75rem 0;font-size:13px}
th{text-align:left;padding:6px 12px;border-bottom:2px solid #1c1c24;color:#9b8afb;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:0.05em}
td{padding:6px 12px;border-bottom:1px solid #111116;color:#8e8e9a;vertical-align:top}
td code{color:#38d9a9;font-size:12px}
td:first-child{color:#d8d8e0;white-space:nowrap}
.check{color:#38d9a9}
.x{color:#5c5c6b}
</style></head><body>
<div class="page">
<h1>certs CLI</h1>
<p>Run locally without us. No middleman. No rate limits. Same engine as certs.lol.</p>
<p><span class="badge">MIT</span><span class="badge">Go</span><span class="badge">&lt;5s scans</span></p>

<h2>Install</h2>
<pre><code># Homebrew
brew install yokedotlol/tap/certs

# Or one-liner
curl -sSL https://certs.lol/install.sh | bash

# Or download from GitHub Releases
curl -sL https://github.com/yokedotlol/certs-lol/releases/latest/download/certs_darwin_arm64.tar.gz | tar xz
sudo mv certs /usr/local/bin/</code></pre>

<h2>Quick Start</h2>
<pre><code># Scan a domain
certs stripe.com

# JSON output (default when piped)
certs stripe.com | jq

# Grade only
certs stripe.com -g

# CI gate — fail if below A
certs api.prod.example.com --assert "min-grade A"

# Compliance check
certs payments.prod --profile pci

# Scan internal hosts (private IPs allowed by default)
certs internal-api.corp.local

# Mail server TLS
certs --mx example.com</code></pre>

<h2>Three Modes</h2>
<table>
<tr><th>Mode</th><th>When</th><th>Use</th></tr>
<tr><td>Pretty</td><td>TTY (default)</td><td>Human-readable, colored tree output</td></tr>
<tr><td>JSON</td><td>Piped / <code>--json</code></td><td>Machine-readable, matches certs.lol API</td></tr>
<tr><td>Assert</td><td><code>--assert</code></td><td>CI/CD gating with pass/fail reports</td></tr>
</table>

<h2>Assertion Rules</h2>
<p>Compose multiple assertions to gate deploys. All must pass — any failure exits non-zero.</p>
<pre><code>certs api.prod \\
  --assert "min-grade A" \\
  --assert "no-tls1.0" \\
  --assert "cert-days 30" \\
  --assert "no-insecure-ciphers"</code></pre>

<h3>Grade</h3>
<table>
<tr><td><code>min-grade &lt;G&gt;</code></td><td>Grade must be ≥ threshold (A+, A, B, C, D, F)</td></tr>
</table>

<h3>Certificate</h3>
<table>
<tr><td><code>cert-days &lt;N&gt;</code></td><td>≥ N days until expiry</td></tr>
<tr><td><code>cert-type &lt;type&gt;</code></td><td>Validation level (DV, OV, EV) — minimum match</td></tr>
<tr><td><code>cert-key-min &lt;bits&gt;</code></td><td>Minimum key size in bits</td></tr>
<tr><td><code>cert-key-type &lt;type&gt;</code></td><td>Key type (RSA, ECDSA, Ed25519)</td></tr>
<tr><td><code>cert-san &lt;pattern&gt;</code></td><td>At least one SAN must match glob</td></tr>
<tr><td><code>cert-issuer &lt;pattern&gt;</code></td><td>Issuer must contain string</td></tr>
<tr><td><code>cert-chain-valid</code></td><td>Chain must be valid</td></tr>
<tr><td><code>cert-has-scts</code></td><td>CT SCTs must be present</td></tr>
</table>

<h3>Protocol</h3>
<table>
<tr><td><code>min-tls &lt;ver&gt;</code></td><td>Minimum supported TLS version</td></tr>
<tr><td><code>max-tls &lt;ver&gt;</code></td><td>Maximum supported TLS version</td></tr>
<tr><td><code>no-tls1.0</code></td><td>TLS 1.0 must not be supported</td></tr>
<tr><td><code>no-tls1.1</code></td><td>TLS 1.1 must not be supported</td></tr>
<tr><td><code>has-tls1.3</code></td><td>TLS 1.3 must be supported</td></tr>
<tr><td><code>has-pq</code></td><td>Post-quantum key exchange required</td></tr>
<tr><td><code>has-ech</code></td><td>Encrypted Client Hello required</td></tr>
</table>

<h3>Ciphers</h3>
<table>
<tr><td><code>no-insecure-ciphers</code></td><td>Zero insecure ciphers (RC4, NULL, EXPORT, anon)</td></tr>
<tr><td><code>no-weak-ciphers</code></td><td>Zero weak ciphers (3DES, CBC-no-FS, RSA-kex)</td></tr>
<tr><td><code>max-weak-ciphers &lt;N&gt;</code></td><td>At most N weak ciphers</td></tr>
<tr><td><code>min-strong-ciphers &lt;N&gt;</code></td><td>At least N strong ciphers</td></tr>
<tr><td><code>has-forward-secrecy</code></td><td>At least one FS cipher present</td></tr>
</table>

<h3>Security &amp; DNS</h3>
<table>
<tr><td><code>has-hsts</code></td><td>HSTS header required</td></tr>
<tr><td><code>hsts-min-age &lt;secs&gt;</code></td><td>HSTS max-age minimum</td></tr>
<tr><td><code>has-hsts-preload</code></td><td>HSTS preload directive required</td></tr>
<tr><td><code>has-dnssec</code></td><td>DNSSEC required</td></tr>
<tr><td><code>has-caa</code></td><td>CAA records required</td></tr>
<tr><td><code>has-ocsp-stapling</code></td><td>OCSP stapling required</td></tr>
</table>

<h3>Compliance</h3>
<table>
<tr><td><code>compliant-pci</code></td><td>PCI DSS 4.0 transport requirements</td></tr>
<tr><td><code>compliant-nist</code></td><td>NIST SP 800-52r2 requirements</td></tr>
<tr><td><code>compliant-hipaa</code></td><td>HIPAA transport requirements</td></tr>
</table>

<h3>Mail</h3>
<table>
<tr><td><code>has-starttls</code></td><td>Server must offer STARTTLS upgrade</td></tr>
</table>

<h2>Profiles</h2>
<p>Named bundles for common use cases:</p>
<pre><code># Production baseline
certs api.prod --profile production

# PCI DSS compliance
certs payments.prod --profile pci

# Maximum strictness
certs cdn.prod --profile strict</code></pre>

<table>
<tr><th>Profile</th><th>Assertions</th></tr>
<tr><td><code>production</code></td><td>min-grade A, no-tls1.0, no-tls1.1, no-insecure-ciphers, cert-days 14, has-hsts</td></tr>
<tr><td><code>staging</code></td><td>min-grade B, no-insecure-ciphers, cert-days 7</td></tr>
<tr><td><code>strict</code></td><td>min-grade A+, no-tls1.0/1.1, no-weak/insecure, has-tls1.3, has-pq, has-forward-secrecy, cert-days 30, has-hsts, has-hsts-preload, has-dnssec, cert-has-scts</td></tr>
<tr><td><code>pci</code></td><td>compliant-pci, no-insecure/weak, has-tls1.3, cert-days 30, has-hsts</td></tr>
<tr><td><code>nist</code></td><td>compliant-nist, has-tls1.3, no-tls1.0/1.1, cert-key-min 256</td></tr>
<tr><td><code>hipaa</code></td><td>compliant-hipaa, cert-days 30, no-insecure-ciphers, has-hsts</td></tr>
<tr><td><code>baseline</code></td><td>min-grade C, no-insecure-ciphers, cert-days 7, cert-chain-valid</td></tr>
</table>

<p>Profiles and <code>--assert</code> compose freely:</p>
<pre><code>certs cdn.prod --profile production --assert "has-pq"</code></pre>

<h2>Config File</h2>
<p>Check a <code>.certs.yaml</code> into your repo for team-wide defaults:</p>
<pre><code># .certs.yaml
profile: production
assertions:
  - cert-type OV
  - cert-issuer DigiCert
  - has-pq
  - hsts-min-age 63072000
targets:
  - api.example.com
  - cdn.example.com
  - payments.example.com</code></pre>
<pre><code># Uses .certs.yaml from current directory
certs

# Or specify config
certs --config path/to/.certs.yaml</code></pre>
<p>Lookup order: <code>--config</code> flag → <code>.certs.yaml</code> in cwd → <code>~/.config/certs/config.yaml</code></p>

<h2>Bulk Scanning</h2>
<pre><code># Scan from file (auto-concurrent above 3 targets)
certs --file domains.txt --out results/

# With assertions
certs --file production-domains.txt --profile production --out results/

# Control concurrency
certs --file domains.txt --workers 20 --quiet</code></pre>
<p>Writes per-target JSON files and a <code>_summary.json</code> with aggregate results.</p>

<h2>STARTTLS &amp; Mail</h2>
<pre><code># Auto-detect from port
certs mail.example.com --port 25       # SMTP STARTTLS
certs mail.example.com --port 587      # SMTP STARTTLS
certs mail.example.com --port 993      # IMAP implicit TLS

# Explicit protocol
certs mail.example.com --port 2525 --starttls smtp

# MX lookup — resolve and scan all mail servers
certs --mx example.com --assert "has-tls1.3"</code></pre>

<h2>CI Examples</h2>

<h3>GitHub Actions</h3>
<pre><code>name: TLS Check
on: [push]
jobs:
  tls:
    runs-on: ubuntu-latest
    steps:
      - name: Install certs
        run: |
          curl -sL https://github.com/yokedotlol/certs-lol/releases/latest/download/certs_linux_amd64.tar.gz | tar xz
          sudo mv certs /usr/local/bin/
      - name: Check TLS
        run: certs api.example.com --profile production</code></pre>

<h3>GitLab CI</h3>
<pre><code>tls-gate:
  script:
    - curl -sL https://github.com/yokedotlol/certs-lol/releases/latest/download/certs_linux_amd64.tar.gz | tar xz
    - ./certs api.example.com --profile production
  only:
    - main</code></pre>

<h2>Exit Codes</h2>
<table>
<tr><td><code>0</code></td><td>Scan succeeded, all assertions passed</td></tr>
<tr><td><code>1</code></td><td>Scan succeeded, assertion(s) failed</td></tr>
<tr><td><code>2</code></td><td>Usage error (bad flags, invalid assertion)</td></tr>
<tr><td><code>3</code></td><td>Scan/connection error</td></tr>
</table>

<h2>Flags</h2>
<table>
<tr><th>Flag</th><th>Short</th><th>Default</th><th>Description</th></tr>
<tr><td><code>--json</code></td><td><code>-j</code></td><td>auto</td><td>Force JSON output</td></tr>
<tr><td><code>--table</code></td><td><code>-t</code></td><td>auto</td><td>Force pretty output</td></tr>
<tr><td><code>--grade</code></td><td><code>-g</code></td><td>—</td><td>Print only the letter grade</td></tr>
<tr><td><code>--assert</code></td><td><code>-a</code></td><td>—</td><td>Assertion rule (repeatable)</td></tr>
<tr><td><code>--profile</code></td><td><code>-P</code></td><td>—</td><td>Named assertion profile</td></tr>
<tr><td><code>--config</code></td><td><code>-c</code></td><td>.certs.yaml</td><td>Config file path</td></tr>
<tr><td><code>--port</code></td><td><code>-p</code></td><td>443</td><td>Target port</td></tr>
<tr><td><code>--timeout</code></td><td>—</td><td>15s</td><td>Connection timeout</td></tr>
<tr><td><code>--starttls</code></td><td>—</td><td>—</td><td>Force STARTTLS protocol</td></tr>
<tr><td><code>--probe-only</code></td><td>—</td><td>false</td><td>Skip enrichment</td></tr>
<tr><td><code>--no-private</code></td><td>—</td><td>false</td><td>Block private/reserved IPs</td></tr>
<tr><td><code>--mx</code></td><td>—</td><td>—</td><td>Resolve MX and scan mail servers</td></tr>
<tr><td><code>--file</code></td><td><code>-f</code></td><td>—</td><td>Read targets from file</td></tr>
<tr><td><code>--out</code></td><td><code>-o</code></td><td>—</td><td>Write results to directory</td></tr>
<tr><td><code>--workers</code></td><td><code>-w</code></td><td>10</td><td>Concurrent workers (bulk)</td></tr>
<tr><td><code>--quiet</code></td><td><code>-q</code></td><td>false</td><td>Suppress progress</td></tr>
</table>

<h2>Source</h2>
<p><a href="https://github.com/yokedotlol/certs-lol">github.com/yokedotlol/certs-lol</a> — MIT licensed.</p>

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
