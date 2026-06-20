import type { Env, ProbeResult, ScanResult } from './worker';
import { html } from './spa';
import { trackScan, handleUsage } from './usage';
import { renderStatusPage } from './status';
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
  'X-XSS-Protection': '0',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https://yoke.lol; frame-ancestors 'none'; base-uri 'self'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
};

function cspWithNonce(nonce: string): string {
  return "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https://yoke.lol; frame-ancestors 'none'; base-uri 'self'";
}

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
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Vary': 'Accept, Accept-Encoding' },
    }),
    extra,
  );
}

function htmlResponse(body: string, status = 200, nonce?: string): Response {
  return addHeaders(
    new Response(body, {
      status,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=3600, s-maxage=3600, stale-while-revalidate=300',
        'Vary': 'Accept, Accept-Encoding',
      },
    }),
    nonce ? { 'Content-Security-Policy': cspWithNonce(nonce) } : undefined,
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

  // MTA-STS policy file (served from mta-sts.certs.lol)
  if (url.hostname === 'mta-sts.certs.lol' && path === '/.well-known/mta-sts.txt') {
    return new Response(
      'version: STSv1\nmode: enforce\nmx: route1.mx.cloudflare.net\nmx: route2.mx.cloudflare.net\nmx: route3.mx.cloudflare.net\nmax_age: 604800\n',
      { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' } },
    );
  }
  if (url.hostname === 'mta-sts.certs.lol') {
    return new Response('Not found', { status: 404 });
  }

  // Health endpoint — not rate limited
  if (path === '/health') {
    return jsonResponse({ status: 'ok', service: 'certs.lol' });
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
        family: {
          tls: 'https://certs.lol',
          dns: 'https://ns.lol',
          http: 'https://xhttp.lol',
          email: 'https://vrfy.lol',
          domains: 'https://yoke.lol',
        },
      });
    }
    const nonce = crypto.randomUUID();
    return htmlResponse(html(undefined, undefined, undefined, nonce), 200, nonce);
  }

  if (path === '/api/docs') {
    return htmlResponse(docsPage());
  }

  if (path === '/usage') {
    return handleUsage(request, env);
  }

  if (path === '/status') {
    return renderStatusPage(env);
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

  // OG image (raster PNG for social platform crawlers)
  if (path === '/og.png' || path === '/og.svg') {
    return addHeaders(new Response(ogImagePng(), {
      headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=604800' },
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

  // Validate target — reject file extensions from bot/crawler noise before hitting the probe
  const FILE_EXT = /\.(png|jpe?g|gif|svg|webp|ico|css|js|map|json|xml|txt|html?|woff2?|ttf|eot|php|aspx?|pdf|zip|gz|bak|log|env)$/i;
  if (FILE_EXT.test(target)) {
    return jsonResponse({ error: 'Invalid domain or IP' }, 400);
  }

  const targetIsIP = isIP(target);
  if (!targetIsIP && !/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(target)) {
    return jsonResponse({ error: 'Invalid domain or IP' }, 400);
  }

  const clientIP = getClientIP(request);
  const forceRescan = url.searchParams.has('force');

  // Check cache first — cache hits don't consume rate-limit credit
  const cacheKey = `scan:${target.toLowerCase()}`;
  const cached = forceRescan ? null : await env.CACHE.get(cacheKey, 'json') as ScanResult | null;

  if (cached) {
    const result = { ...cached, _meta: { ...cached._meta, cache_hit: true } };
    ctx.waitUntil(trackScan(env, { target, cache_hit: true }));

    if (wantsJSON(request)) {
      return jsonResponse(result, 200, {
        'X-Cache': 'HIT',
        'X-RateLimit-Limit': String(RATE_LIMIT),
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300',
      });
    }
    const cachedNonce = crypto.randomUUID();
    return htmlResponse(html(result, undefined, { remaining: RATE_LIMIT, limit: RATE_LIMIT }, cachedNonce), 200, cachedNonce);
  }

  // Rate limit check — only fresh scans count
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
    const rlNonce = crypto.randomUUID();
    return htmlResponse(html(undefined, rateLimitMessage(retryMin, target), { remaining: 0, limit: RATE_LIMIT }, rlNonce), 429, rlNonce);
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
        ...(targetIsIP ? {} : { dns_report: `https://ns.lol/${target}`, http_report: `https://xhttp.lol/${target}`, full_report: `https://yoke.lol/${target}` }),
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
    const scanNonce = crypto.randomUUID();
    return htmlResponse(html(result, undefined, { remaining: rl.remaining, limit: RATE_LIMIT }, scanNonce), 200, scanNonce);

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

// Base64-encoded 1200x630 PNG — terminal-style share card
const OG_PNG_B64 = "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1W2W1G1pWr47CILvv/bfxsYHLlubmBh54+gTOdlFBfmVkUh0YPDCD5q/+Rff/txlNxwODl8aHukqKarLzirIyIgEQXDizItt55vnU/xi1/HTba/k51Xk5pQEQdDZffL5V/74wKH/L5mann8D4omhc5cOV5WvzM0pzgiFgyA4d+nw0ZPPBkHQ09tyset4NDM7EsnKzIwNjXQdP/3CX3z7c/2D553NAHeRrKxYEASJRNxQAHAbhfLyyowCANxiBQVFQRAMDQ0YCgBuowxDAAAAIBACAAAgEAIAACAQAgAAIBACAAAgEAIAACAQAgAAIBACAAAgEAIAACAQAgAAIBACAAAgEL4DoVDIkQMAALgXA+GuXY8sW7bCwQMAALjnAiEAAAACIQAAADcpco/3f/Pm7fX1S666at++Pd3dndXVtdu3P5hevnKb8vLKpqY1BQVF09NTvb3dp06dGBjon0+9JSWl9fVL6+rqI5HMZ599cmxsdJ4NjkajS5Ysr6urz83NGx8fO3eu7dSpE9PT005lAABAILwxzc37m5v3p5cff/yT5861z3y8rpqaum3bdh49emj//pczMjJWrFi9Y8f7n3nmifmEunXrNrW1tcTj401Na2+owQ0Njclk6vXXXxkbGy0uLtm69YHCwuL9+192KgMAAALhrbN8eVN3d+epU8fTHw8dah4ZGZ5PwYmJiZdeei4Igpt4NM6JE0dnlnt6ultazjQ1rcnKykokEo4IAABwQ9xDePNisVg8Hp/9zdmzp255K1K3uL7cLY2Nf/PF7FX1TgAAABAI710DA31VVdWFhUW3pfZwOFxRUdXQsKKjo/WWTQ9Ga0vr/+CfDnxn//jxdicAAADc7e7WS0ZjsVhBQWF6OZVKzfGq+unp6dHRkYVow+HDB3fseHD37kf7+np6e3suXDjX3997a7r/4Q//dFZWLAiCjo625ubXbk2loUh40Zd+aeyN093feNYvBwAABMLbprFxVWPjqvTy8PBgfn7htbYcGOjfs2dBAsz4+NiePd8rLS2rqKguL69obGzq6Gg7cODVW9D9p59+IhwOl5VVbNq0devW+1977ZVbUGnFZz4aLshp/edfCVIpvxwAABAIb5tTp453dLSll687Q7hwzUilUj093T093UEQ1Ncv3bx528WL5y9c6LgFIzA9Pd3ZefHIkYP33Xd/WVl5ug0L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";

function ogImagePng(): Uint8Array {
  const raw = atob(OG_PNG_B64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function faviconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="80" font-size="80">🔒</text></svg>`;
}

function securityTxt(): string {
  return `Contact: https://github.com/yokedotlol/certs-lol/issues
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
<li><strong>60 requests per hour</strong> per IP — rolling window</li>
<li>Results cached for 6h — add <code>?force</code> to bypass, but force-scans still count</li>
<li>Cached results also count against the limit (abuse prevention)</li>
<li>429 response with <code>Retry-After</code> header when exceeded</li>
</ul>
<p><strong>Why 60/hr?</strong> TLS scans are resource-intensive — each request triggers a real probe that makes live TLS connections to the target from a <a href="https://fly.io">Fly.io</a> edge node. This is significantly heavier than DNS lookups, which is why certs.lol's limit is lower than other .lol tools (e.g. <a href="https://ns.lol">ns.lol</a> allows 120/hr).</p>
<p>For unlimited local scanning, <a href="/cli">install the CLI</a> — same engine, no rate limits, no middleman.</p>
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
    "dns_report": "https://ns.lol/example.com",
    "http_report": "https://xhttp.lol/example.com",
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

${staticFooter()}
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

${staticFooter()}
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

${staticFooter()}
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
<p>certs.lol is part of the <a href="https://yoke.lol">.lol</a> family — free developer tools for DNS, TLS, HTTP, email, and domain intelligence.</p>
<ul>
<li><a href="https://certs.lol">certs.lol</a> — TLS/SSL scanner (you are here)</li>
<li><a href="https://ns.lol">ns.lol</a> — DNS toolkit</li>
<li><a href="https://xhttp.lol">xhttp.lol</a> — HTTP response debugger</li>
<li><a href="https://vrfy.lol">vrfy.lol</a> — Email validation</li>
<li><a href="https://yoke.lol">yoke.lol</a> — Full domain intelligence</li>
</ul>
<p>Open source: <a href="https://github.com/yokedotlol/certs-lol">github.com/yokedotlol/certs-lol</a></p>

<h2>Contact</h2>
<p><a href="mailto:hello@certs.lol">hello@certs.lol</a></p>

${staticFooter()}
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
<p style="margin-top:0.75rem;padding:8px 12px;background:#111116;border-left:3px solid #38d9a9;border-radius:4px;font-size:12px;color:#8e8e9a">🔒 <strong style="color:#38d9a9">Privacy:</strong> This CLI never contacts certs.lol servers. All scans connect directly from your machine to the target domain. <a href="https://github.com/yokedotlol/certs-lol" style="color:#9b8afb">You can always self-host if you need privacy.</a></p>

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

${staticFooter()}
</div></body></html>`;
}

function metaTags(title: string, description: string): string {
  return `<meta name="description" content="${description}">
<meta property="og:title" content="${title} — certs.lol">
<meta property="og:description" content="${description}">
<meta property="og:type" content="website">
<meta property="og:url" content="https://certs.lol">
<meta property="og:image" content="https://certs.lol/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title} — certs.lol">
<meta name="twitter:description" content="${description}">
<meta name="twitter:image" content="https://certs.lol/og.png">
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
.footer{padding:2rem 0 3rem;margin-top:2rem;font-size:10px;color:#3a3a4a;font-family:'JetBrains Mono',monospace;text-align:center;display:flex;flex-direction:column;align-items:center;gap:10px}
.footer a{color:#55556a;text-decoration:none;transition:color .2s}
.footer a:hover{color:#7a7a8e;text-decoration:none}
.footer-links{display:flex;justify-content:center;gap:16px;flex-wrap:wrap}
.footer-tagline{font-size:10px;color:#3a3a4a;margin-bottom:2px}
.footer-tagline a{color:#55556a;text-decoration:none;transition:color .2s}
.footer-tagline a:hover{color:#9b8afb}
.footer-family{display:flex;justify-content:center;gap:16px}
.footer-family a{color:#3a3a4a;text-decoration:none;transition:color .2s}
.footer-family a:hover{color:#9b8afb}
.yoke-badge{display:inline-block}
.yoke-badge img{opacity:0.6;transition:opacity .2s;vertical-align:middle}
.yoke-badge:hover img{opacity:1}`;
}

function staticFooter(): string {
  return `<footer class="footer">
<div class="footer-links">
  <a href="https://github.com/yokedotlol/certs-lol">GitHub</a>
  <a href="/api/docs">API</a>
  <a href="/cli">CLI</a>
  <a href="/about">About</a>
  <a href="/privacy">Privacy</a>
  <a href="/terms">Terms</a>
</div>
<div class="footer-tagline">Part of the <a href="https://yoke.lol/tools">.lol tools</a></div>
<div class="footer-family">
  <a href="https://yoke.lol">yoke</a>
  <a href="https://ns.lol">ns</a>
  <a href="https://xhttp.lol">xhttp</a>
  <a href="https://vrfy.lol">vrfy</a>
</div>
<a href="https://yoke.lol/certs.lol" class="yoke-badge"><img src="https://yoke.lol/badge/certs.lol.svg" alt="Yoke score for certs.lol" height="20"></a>
</footer>`;
}
